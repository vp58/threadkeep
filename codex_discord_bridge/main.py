from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import signal
import socket
import stat
import tempfile
import time
import uuid
from pathlib import Path

from .appserver import CodexAppServer
from .config import Config
from .discord_io import (
    bootstrap_root_cursor,
    dedicated_token,
    receive_forever,
    reconcile_delivery,
    send_result,
    verify_owner_private_audience,
)
from .discord_permissions import verify_discord_permissions
from .store import JobStore
from conversations.vault_policy import VaultPolicySeal


log = logging.getLogger("codex_discord_bridge")


def clear_ready_marker(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("Codex readiness marker path is not a regular file")
    path.unlink()


def write_ready_marker(
    path: Path,
    instance_id: str,
    started_at: int,
    *,
    workers_configured: int = 1,
    workers_ready: int = 1,
) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if path.exists() or path.is_symlink():
        clear_ready_marker(path)
    payload = {
        "version": 1,
        "ready": True,
        "pid": os.getpid(),
        "instance_id": instance_id,
        "started_at": started_at,
        "workers_configured": workers_configured,
        "workers_ready": workers_ready,
    }
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, prefix=".ready.", delete=False
    ) as handle:
        temporary = Path(handle.name)
        json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    try:
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


async def maintain_ready_marker(
    path: Path,
    gateway_ready: asyncio.Event,
    worker_ready: asyncio.Event | tuple[asyncio.Event, ...],
    instance_id: str,
    started_at: int,
    poll_interval: float = 0.25,
) -> None:
    worker_events = (
        (worker_ready,)
        if isinstance(worker_ready, asyncio.Event)
        else tuple(worker_ready)
    )
    if not worker_events:
        raise ValueError("at least one Codex worker readiness event is required")
    published = False
    try:
        while True:
            ready_workers = sum(event.is_set() for event in worker_events)
            ready = gateway_ready.is_set() and ready_workers == len(worker_events)
            if ready and (not published or not path.exists()):
                write_ready_marker(
                    path,
                    instance_id,
                    started_at,
                    workers_configured=len(worker_events),
                    workers_ready=ready_workers,
                )
                published = True
            elif not ready and published:
                clear_ready_marker(path)
                published = False
            await asyncio.sleep(poll_interval)
    finally:
        clear_ready_marker(path)


def acquire_runtime_lock(path):
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise RuntimeError("Codex runtime state directory is unavailable") from exc
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise RuntimeError(
            "Codex runtime state directory must be a private, owned real directory"
        )
    existed = False
    try:
        current = path.lstat()
        existed = True
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or current.st_uid != os.getuid()
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise RuntimeError("Codex runtime lock path is unsafe")
    except FileNotFoundError:
        pass
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    if not existed:
        os.fchmod(descriptor, 0o600)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise RuntimeError("Codex runtime lock file changed while opening")
    handle = os.fdopen(descriptor, "a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise RuntimeError("another Codex Discord bridge process already owns the runtime") from exc
    return handle


def destination_for(config: Config, store: JobStore, event_id: str) -> str | None:
    source_channel_id = store.job_channel_for(event_id)
    if source_channel_id and source_channel_id != config.channel_id:
        return source_channel_id
    return store.discord_thread_for(event_id) or store.thread_for(f"discord:{event_id}")


async def renew_lease(
    store: JobStore, event_id: str, owner: str, generation: int, interval: int = 60
) -> None:
    while True:
        await asyncio.sleep(interval)
        if not store.renew(event_id, owner, generation, lease_seconds=300):
            raise RuntimeError("worker lost its job lease")


async def reconcile_startup_state(
    config: Config,
    store: JobStore,
    token: str,
    *,
    instance_id: str,
) -> None:
    """Fence the previous process and reconcile ambiguous delivery once.

    This runs to completion before any pool slot may claim queued work. A
    per-slot call would incorrectly classify healthy sibling leases as
    abandoned and would race Discord delivery reconciliation.
    """

    owner = f"{socket.gethostname()}:{os.getpid()}:startup:{instance_id}"
    while abandoned := store.reclaim_abandoned(owner):
        log.error(
            "abandoned_job_marked_uncertain event_id=%s generation=%s",
            abandoned[0],
            abandoned[2],
        )
    while expired := store.reclaim_expired(owner):
        log.error(
            "expired_job_marked_uncertain event_id=%s generation=%s",
            expired[0],
            expired[2],
        )

    for manifest_id in store.incomplete_manifest_ids():
        try:
            await reconcile_delivery(
                token, store, manifest_id, bot_user_id=config.bot_user_id
            )
            log.info("delivery_manifest_reconciled event_id=%s", manifest_id)
        except Exception as exc:
            log.error(
                "delivery_manifest_reconcile_failed event_id=%s type=%s",
                manifest_id,
                type(exc).__name__,
            )

    for uncertain_id, uncertain_generation in store.uncertain_jobs():
        destination_id = destination_for(config, store, uncertain_id)
        manifest = store.delivery_manifest(uncertain_id)
        if manifest:
            try:
                message_id = await reconcile_delivery(
                    token, store, uncertain_id, bot_user_id=config.bot_user_id
                )
                if store.complete_uncertain(
                    uncertain_id, uncertain_generation, message_id
                ):
                    log.info(
                        "uncertain_job_reconciled event_id=%s result_message_id=%s",
                        uncertain_id,
                        message_id,
                    )
                    continue
            except Exception as exc:
                log.error(
                    "uncertain_job_reconcile_failed event_id=%s type=%s",
                    uncertain_id,
                    type(exc).__name__,
                )
        if destination_id:
            try:
                await send_result(
                    token,
                    config,
                    f"{uncertain_id}:error",
                    "The worker stopped processing this request and marked it uncertain. "
                    "Prior local or external effects may have occurred, so it will not run again "
                    "automatically. Review the result before deciding what to do next.",
                    destination_id,
                    store,
                )
            except Exception:
                log.exception("uncertain_job_notice_failed event_id=%s", uncertain_id)


async def worker(
    config: Config,
    store: JobStore,
    token: str,
    instructions_sha256: str | None = None,
    account_binding: str | None = None,
    shared_skills_manifest_sha256: str | None = None,
    shared_hooks_manifest_sha256: str | None = None,
    vault_policy_seal: VaultPolicySeal | None = None,
    ready_event: asyncio.Event | None = None,
    slot_id: int = 1,
) -> None:
    if slot_id < 1:
        raise ValueError("Codex worker slot IDs start at one")
    owner = (
        f"{socket.gethostname()}:{os.getpid()}:slot-{slot_id}:{uuid.uuid4().hex}"
    )
    work_dir = config.state_dir / "workers" / f"slot-{slot_id}"
    app: CodexAppServer | None = None

    try:
        while True:
            if app is not None and app.reader_task is not None and app.reader_task.done():
                log.error("appserver_reader_stopped_while_idle")
                if ready_event is not None:
                    ready_event.clear()
                await app.close()
                app = None
            if app is None:
                app = CodexAppServer(
                    config.codex_bin,
                    work_dir,
                    workspace_dir=config.working_directory,
                    sandbox_mode=config.sandbox_mode,
                    channel_trust=config.channel_trust,
                    full_computer_access_accepted=config.full_computer_access_accepted,
                    codex_home=config.codex_home,
                    instructions_file=config.instructions_file,
                    instructions_sha256=instructions_sha256,
                    account_binding=account_binding,
                    shared_skills_root=config.shared_skills_root,
                    shared_skills_manifest_sha256=shared_skills_manifest_sha256,
                    shared_hooks_manifest_sha256=shared_hooks_manifest_sha256,
                    vault_policy_seal=vault_policy_seal,
                    vault_root=config.vault_root,
                    policy_runtime_root=config.state_dir,
                )
                await app.start()
                if ready_event is not None:
                    ready_event.set()
                log.info("appserver_ready slot=%s", slot_id)
            app._bound_vault_policy()
            app._bound_shared_hooks()
            await app.require_bound_chatgpt_principal()
            job = store.claim(owner)
            if not job:
                await asyncio.sleep(0.5)
                continue
            event_id, content, generation = job
            destination_id = destination_for(config, store, event_id)
            lease_task = asyncio.create_task(
                renew_lease(store, event_id, owner, generation), name=f"lease-{event_id}"
            )
            try:
                codex_scope = (
                    f"codex:{store.policy_binding}:"
                    f"{destination_id or config.channel_id}"
                )
                thread_id = store.thread_for(codex_scope)
                if not thread_id:
                    thread_id = await app.create_thread()
                    store.save_thread(codex_scope, thread_id)
                turn_task = asyncio.create_task(
                    app.turn(thread_id, content, event_id), name=f"turn-{event_id}"
                )
                done, _ = await asyncio.wait(
                    {turn_task, lease_task}, return_when=asyncio.FIRST_COMPLETED
                )
                if lease_task in done:
                    turn_task.cancel()
                    await asyncio.gather(turn_task, return_exceptions=True)
                    raise lease_task.exception() or RuntimeError("lease task stopped")
                answer = await turn_task
                message_id = await send_result(
                    token, config, event_id, answer, destination_id, store
                )
                if not store.finish(event_id, owner, generation, "completed", message_id):
                    raise RuntimeError("worker lost its fencing generation")
                log.info(
                    "job_completed event_id=%s result_message_id=%s slot=%s",
                    event_id,
                    message_id,
                    slot_id,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception("job_failed event_id=%s type=%s", event_id, type(exc).__name__)
                marked_uncertain = store.finish(event_id, owner, generation, "uncertain")
                recovered = False
                if marked_uncertain and store.delivery_manifest(event_id):
                    try:
                        message_id = await reconcile_delivery(
                            token, store, event_id, bot_user_id=config.bot_user_id
                        )
                        recovered = store.complete_uncertain(event_id, generation, message_id)
                        if recovered:
                            log.info(
                                "job_delivery_reconciled event_id=%s result_message_id=%s",
                                event_id,
                                message_id,
                            )
                    except Exception as reconcile_exc:
                        log.error(
                            "job_delivery_reconcile_failed event_id=%s type=%s",
                            event_id,
                            type(reconcile_exc).__name__,
                        )
                if marked_uncertain and not recovered and destination_id:
                    try:
                        await send_result(
                            token,
                            config,
                            f"{event_id}:error",
                            "The worker stopped processing this request and marked it uncertain. "
                            "Prior local or external effects may have occurred, so it will not run "
                            "again automatically. Review the result before deciding what to do next.",
                            destination_id,
                            store,
                        )
                    except Exception:
                        log.exception("discord_error_notice_failed event_id=%s", event_id)
                if app:
                    if ready_event is not None:
                        ready_event.clear()
                    await app.close()
                    app = None
            finally:
                lease_task.cancel()
                await asyncio.gather(lease_task, return_exceptions=True)
    finally:
        if ready_event is not None:
            ready_event.clear()
        if app:
            await app.close()


async def probe_account_binding(
    config: Config,
    instructions_sha256: str | None,
    shared_skills_manifest_sha256: str,
    shared_hooks_manifest_sha256: str,
    vault_policy_seal: VaultPolicySeal,
) -> str:
    """Read only the official nonsecret App Server account facts."""

    app = CodexAppServer(
        config.codex_bin,
        config.state_dir / "account-probe",
        workspace_dir=config.working_directory,
        sandbox_mode=config.sandbox_mode,
        channel_trust=config.channel_trust,
        full_computer_access_accepted=config.full_computer_access_accepted,
        codex_home=config.codex_home,
        instructions_file=config.instructions_file,
        instructions_sha256=instructions_sha256,
        account_binding=None,
        shared_skills_root=config.shared_skills_root,
        shared_skills_manifest_sha256=shared_skills_manifest_sha256,
        shared_hooks_manifest_sha256=shared_hooks_manifest_sha256,
        vault_policy_seal=vault_policy_seal,
        vault_root=config.vault_root,
        policy_runtime_root=config.state_dir,
    )
    try:
        await app.start()
        if app.account_binding is None:
            raise RuntimeError("App Server did not return a ChatGPT account binding")
        return app.account_binding
    finally:
        await app.close()


async def supervise_service_tasks(
    service_tasks: tuple[asyncio.Task, ...],
    stop_task: asyncio.Task,
) -> None:
    """Fail the bridge closed if any Gateway, worker, or readiness task stops."""

    if not service_tasks:
        raise ValueError("at least one bridge service task is required")
    try:
        done, _ = await asyncio.wait(
            {*service_tasks, stop_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stop_task not in done:
            completed_service = next(task for task in done if task is not stop_task)
            await completed_service
            raise RuntimeError(f"{completed_service.get_name()} stopped unexpectedly")
    finally:
        for task in (*service_tasks, stop_task):
            task.cancel()
        await asyncio.gather(
            *service_tasks,
            stop_task,
            return_exceptions=True,
        )


async def run() -> None:
    config = Config.from_discoparty()
    runtime_lock = acquire_runtime_lock(config.state_dir / "bridge.lock")
    ready_path: Path | None = None
    try:
        token = dedicated_token(config)
        await verify_discord_permissions(token, config)
        await verify_owner_private_audience(token, config)
        instructions_sha256 = config.instructions_digest()
        shared_skills_manifest_sha256 = config.shared_skills_digest()
        shared_hooks_manifest_sha256 = config.shared_hooks_digest()
        vault_policy_seal = config.seal_vault_policy()
        account_binding = await probe_account_binding(
            config,
            instructions_sha256,
            shared_skills_manifest_sha256,
            shared_hooks_manifest_sha256,
            vault_policy_seal,
        )
        policy_binding = config.policy_fingerprint(
            instructions_sha256,
            account_binding,
            shared_skills_manifest_sha256,
            vault_policy_seal,
            shared_hooks_manifest_sha256,
        )
        store = JobStore(
            config.state_dir / "jobs.sqlite3",
            max_database_bytes=config.max_database_bytes,
            retention_days=config.retention_days,
            policy_binding=policy_binding,
        )
        stale_queued, stale_running = store.quarantine_stale_jobs()
        if stale_queued or stale_running:
            log.error(
                "stale_policy_jobs_quarantined queued=%s running=%s",
                stale_queued,
                stale_running,
            )
        ready_path = config.state_dir / "ready.json"
        clear_ready_marker(ready_path)
        instance_id = uuid.uuid4().hex
        started_at = int(time.time())
        await bootstrap_root_cursor(token, config, store)
        await reconcile_startup_state(
            config,
            store,
            token,
            instance_id=instance_id,
        )
        log.info(
            "bridge_starting channel_id=%s bot_id=%s workers=%s channel_trust=%s",
            config.channel_id,
            config.bot_user_id,
            config.max_concurrent_workers,
            config.channel_trust,
        )
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass
        gateway_ready = asyncio.Event()
        worker_ready_events = tuple(
            asyncio.Event() for _ in range(config.max_concurrent_workers)
        )
        gateway_task = asyncio.create_task(
            receive_forever(token, config, store, gateway_ready),
            name="discord-gateway",
        )
        worker_tasks = tuple(
            asyncio.create_task(
                worker(
                    config,
                    store,
                    token,
                    instructions_sha256,
                    account_binding,
                    shared_skills_manifest_sha256,
                    shared_hooks_manifest_sha256,
                    vault_policy_seal,
                    worker_ready_events[slot_id - 1],
                    slot_id,
                ),
                name=f"codex-worker-{slot_id}",
            )
            for slot_id in range(1, config.max_concurrent_workers + 1)
        )
        readiness_task = asyncio.create_task(
            maintain_ready_marker(
                ready_path,
                gateway_ready,
                worker_ready_events,
                instance_id,
                started_at,
            ),
            name="readiness-marker",
        )
        stop_task = asyncio.create_task(stop.wait(), name="shutdown-signal")
        service_tasks = (gateway_task, *worker_tasks, readiness_task)
        await supervise_service_tasks(service_tasks, stop_task)
    finally:
        if ready_path is not None:
            clear_ready_marker(ready_path)
        fcntl.flock(runtime_lock.fileno(), fcntl.LOCK_UN)
        runtime_lock.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    asyncio.run(run())


if __name__ == "__main__":
    main()
