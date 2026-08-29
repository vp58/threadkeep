#!/usr/bin/env python3
"""Persistent Discord gateway WebSocket client.

Connects to the Discord gateway, identifies with the configured bot token, runs
the heartbeat loop, and dispatches every INTERACTION_CREATE event to the
interaction router (router.py).

This client never exits on its own. It reconnects on disconnect using the
documented gateway resume/identify protocol and exponential backoff.

Run via launchd, systemd, or directly:

    python3 client.py
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import fcntl
import json
import logging
import logging.handlers
import math
import os
import random
import re
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator

from websockets.asyncio.client import connect as _WebSocketConnect

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "conversations"))
from config import CONFIG  # noqa: E402
from codex_discord_bridge.process_supervisor import supervisor_command  # noqa: E402
from discord_http import direct_urlopen  # noqa: E402
from discord_secret import load_discord_token, sanitized_child_environment  # noqa: E402
import interaction_store  # noqa: E402

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"
LOG_PATH = LOG_DIR / "client.log"
STATE_PATH = HERE / "state" / "client_state.json"
IDENTIFY_LEDGER_PATH = HERE / "state" / "identify_budget.json"
INTERACTION_STORE_PATH = HERE / "state" / "interactions.sqlite3"
GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"

ROUTER_TIMEOUT_SECONDS = 20.0
ROUTER_TERMINATE_GRACE_SECONDS = 5.0
INTERACTION_RETRY_POLL_SECONDS = 0.5
SNOWFLAKE_RE = re.compile(r"^[1-9][0-9]{16,19}$")
APPROVAL_CUSTOM_ID_RE = re.compile(r"^(approve|reject):([a-f0-9]{12,64})$")
DISCORD_API = "https://discord.com/api/v10"

IDENTIFY_LEDGER_VERSION = 1
IDENTIFY_HOURLY_LIMIT = 20
IDENTIFY_DAILY_LIMIT = 400
IDENTIFY_HOURLY_WINDOW_SECONDS = 60 * 60
IDENTIFY_DAILY_WINDOW_SECONDS = 24 * 60 * 60

# Component interactions do not require message, DM, or privileged content
# intents. GUILDS is retained only to bind READY membership to the one
# configured guild and fail closed if this dedicated bot is installed elsewhere.
INTENTS = 1

OP_DISPATCH = 0
OP_HEARTBEAT = 1
OP_IDENTIFY = 2
OP_RESUME = 6
OP_RECONNECT = 7
OP_INVALID_SESSION = 9
OP_HELLO = 10
OP_HEARTBEAT_ACK = 11


def _require_direct_discord_transport() -> None:
    proxies = urllib.request.getproxies()
    configured = sorted(
        str(name)
        for name, value in proxies.items()
        if str(name).lower() in {"http", "https", "all"} and value
    )
    if configured:
        raise RuntimeError(
            "Discord transport refuses ambient proxy configuration: "
            + ", ".join(configured)
        )


class _NoRedirectWebSocketConnect(_WebSocketConnect):
    """Refuse Gateway redirects before a bot token can cross origins."""

    def process_redirect(self, exc: Exception) -> Exception | str:
        return exc


_GATEWAY_CONNECT = _NoRedirectWebSocketConnect


class IdentifyBudgetLedgerError(ValueError):
    """The persisted IDENTIFY ledger cannot be trusted."""


class UnauthorizedInteractionError(RuntimeError):
    """A relevant approval interaction came from someone other than the owner."""


def _empty_identify_ledger() -> dict[str, Any]:
    return {
        "version": IDENTIFY_LEDGER_VERSION,
        "identify_timestamps": [],
        "blocked_until": 0.0,
    }


def _atomic_write_private_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically replace *path* with a mode-0600 JSON file."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _load_identify_ledger(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_identify_ledger()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IdentifyBudgetLedgerError("ledger is unreadable") from exc

    if not isinstance(payload, dict):
        raise IdentifyBudgetLedgerError("ledger root is not an object")
    version = payload.get("version")
    if isinstance(version, bool) or version != IDENTIFY_LEDGER_VERSION:
        raise IdentifyBudgetLedgerError("unsupported ledger version")
    timestamps = payload.get("identify_timestamps")
    if not isinstance(timestamps, list):
        raise IdentifyBudgetLedgerError("identify_timestamps is not a list")
    normalized_timestamps: list[float] = []
    for value in timestamps:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise IdentifyBudgetLedgerError("ledger contains an invalid timestamp")
        normalized_timestamps.append(float(value))

    blocked_until = payload.get("blocked_until", 0.0)
    if (
        isinstance(blocked_until, bool)
        or not isinstance(blocked_until, (int, float))
        or not math.isfinite(blocked_until)
        or blocked_until < 0
    ):
        raise IdentifyBudgetLedgerError("blocked_until is invalid")
    return {
        "version": IDENTIFY_LEDGER_VERSION,
        "identify_timestamps": sorted(normalized_timestamps),
        "blocked_until": float(blocked_until),
    }


@contextmanager
def _identify_ledger_lock(path: Path) -> Iterator[None]:
    """Serialize ledger read-modify-write cycles across local processes."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    lock_path = path.with_name(path.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def reserve_identify_slot(
    now: float, logger: logging.Logger
) -> tuple[bool, float, str]:
    """Reserve one persisted IDENTIFY slot or return a safe retry delay."""
    try:
        with _identify_ledger_lock(IDENTIFY_LEDGER_PATH):
            try:
                ledger = _load_identify_ledger(IDENTIFY_LEDGER_PATH)
            except IdentifyBudgetLedgerError as exc:
                # Unknown prior usage must not be treated as zero. After a full
                # daily window, every possibly-recorded IDENTIFY has aged out.
                delay = float(IDENTIFY_DAILY_WINDOW_SECONDS)
                recovery = _empty_identify_ledger()
                recovery["blocked_until"] = now + delay
                try:
                    _atomic_write_private_json(IDENTIFY_LEDGER_PATH, recovery)
                except OSError as write_exc:
                    logger.error(
                        "IDENTIFY ledger corrupt and fail-closed recovery write failed: %s",
                        type(write_exc).__name__,
                    )
                    return False, delay, "ledger unavailable"
                logger.error(
                    "IDENTIFY ledger corrupt; failing closed for %.0fs: %s",
                    delay,
                    exc,
                )
                return False, delay, "corrupt ledger"

            blocked_until = ledger["blocked_until"]
            if blocked_until > now:
                return False, blocked_until - now, "fail-closed recovery"

            timestamps = [
                value
                for value in ledger["identify_timestamps"]
                if value > now - IDENTIFY_DAILY_WINDOW_SECONDS
            ]
            hourly = [
                value
                for value in timestamps
                if value > now - IDENTIFY_HOURLY_WINDOW_SECONDS
            ]

            ready_times: list[tuple[float, str]] = []
            if len(hourly) >= IDENTIFY_HOURLY_LIMIT:
                ready_times.append(
                    (
                        hourly[-IDENTIFY_HOURLY_LIMIT]
                        + IDENTIFY_HOURLY_WINDOW_SECONDS,
                        "hourly budget",
                    )
                )
            if len(timestamps) >= IDENTIFY_DAILY_LIMIT:
                ready_times.append(
                    (
                        timestamps[-IDENTIFY_DAILY_LIMIT]
                        + IDENTIFY_DAILY_WINDOW_SECONDS,
                        "daily budget",
                    )
                )
            if ready_times:
                ready_at, reason = max(ready_times, key=lambda item: item[0])
                if len(timestamps) != len(ledger["identify_timestamps"]):
                    ledger["identify_timestamps"] = timestamps
                    ledger["blocked_until"] = 0.0
                    _atomic_write_private_json(IDENTIFY_LEDGER_PATH, ledger)
                return False, max(ready_at - now, 1.0), reason

            timestamps.append(now)
            _atomic_write_private_json(
                IDENTIFY_LEDGER_PATH,
                {
                    "version": IDENTIFY_LEDGER_VERSION,
                    "identify_timestamps": timestamps,
                    "blocked_until": 0.0,
                },
            )
            return True, 0.0, "reserved"
    except OSError as exc:
        # Failure to read, lock, or durably write the budget is a denial, never
        # permission to IDENTIFY without accounting for it.
        logger.error(
            "IDENTIFY ledger unavailable; failing closed for %.0fs: %s",
            IDENTIFY_DAILY_WINDOW_SECONDS,
            type(exc).__name__,
        )
        return False, float(IDENTIFY_DAILY_WINDOW_SECONDS), "ledger unavailable"


async def wait_for_identify_budget(logger: logging.Logger) -> None:
    """Wait in this process until a fresh IDENTIFY has a durable reservation."""
    while True:
        reserved, delay, reason = reserve_identify_slot(time.time(), logger)
        if reserved:
            logger.info("IDENTIFY budget slot reserved")
            return
        logger.warning("IDENTIFY %s exhausted; waiting %.1fs", reason, delay)
        await asyncio.sleep(delay)


def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("threadkeep-gateway")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=2_000_000, backupCount=5
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    stderr = logging.StreamHandler()
    stderr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(stderr)
    return logger


def load_token() -> str:
    return load_discord_token()


def save_state(state: dict[str, Any]) -> None:
    persisted: dict[str, Any] = {}
    for key in (
        "session_id",
        "resume_gateway_url",
        "application_id",
        "bot_user_id",
    ):
        value = state.get(key)
        if value is not None:
            if (
                not isinstance(value, str)
                or (
                    key in {"application_id", "bot_user_id"}
                    and not SNOWFLAKE_RE.fullmatch(value)
                )
                or (key not in {"application_id", "bot_user_id"} and not value)
            ):
                raise ValueError(f"invalid gateway state field: {key}")
            persisted[key] = value
    guild_ids = state.get("guild_ids")
    if guild_ids is not None:
        if (
            not isinstance(guild_ids, list)
            or any(not isinstance(value, str) or not SNOWFLAKE_RE.fullmatch(value) for value in guild_ids)
            or len(set(guild_ids)) != len(guild_ids)
        ):
            raise ValueError("invalid gateway state field: guild_ids")
        persisted["guild_ids"] = sorted(guild_ids)
    sequence = state.get("last_seq")
    if sequence is not None:
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError("invalid committed gateway sequence")
        persisted["last_seq"] = sequence
    _atomic_write_private_json(STATE_PATH, persisted)


def load_state() -> dict[str, Any]:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            return {}
    return {}


def _require_snowflake(value: Any, label: str) -> str:
    normalized = str(value or "")
    if not SNOWFLAKE_RE.fullmatch(normalized):
        raise RuntimeError(f"interaction has invalid {label}")
    return normalized


def _message_has_custom_id(message: dict[str, Any], custom_id: str) -> bool:
    components = message.get("components")
    if not isinstance(components, list):
        return False
    for row in components:
        if not isinstance(row, dict):
            continue
        children = row.get("components")
        if not isinstance(children, list):
            continue
        for component in children:
            if isinstance(component, dict) and component.get("custom_id") == custom_id:
                return True
    return False


def classify_interaction(interaction: Any) -> str:
    """Classify without validating unrelated Discord/plugin interactions."""

    if not isinstance(interaction, dict):
        return "unrelated"
    data = interaction.get("data")
    if not isinstance(data, dict):
        return "unrelated"
    custom_id = data.get("custom_id")
    if not isinstance(custom_id, str):
        return "unrelated"
    if APPROVAL_CUSTOM_ID_RE.fullmatch(custom_id):
        return "approval"
    if custom_id.startswith("approve:") or custom_id.startswith("reject:"):
        return "invalid_approval"
    return "unrelated"


def _interaction_actor_id(interaction: dict[str, Any]) -> str:
    member = interaction.get("member")
    member_user = member.get("user") if isinstance(member, dict) else None
    user = member_user if isinstance(member_user, dict) else interaction.get("user")
    if not isinstance(user, dict):
        return ""
    return str(user.get("id") or "")


def _post_interaction_callback(
    interaction: dict[str, Any], payload: dict[str, Any]
) -> tuple[int, str]:
    _require_direct_discord_transport()
    interaction_id = _require_snowflake(interaction.get("id"), "interaction ID")
    interaction_token = interaction.get("token")
    if (
        not isinstance(interaction_token, str)
        or not interaction_token
        or len(interaction_token) > 512
        or "\x00" in interaction_token
    ):
        raise RuntimeError("interaction callback token is invalid")
    encoded_token = urllib.parse.quote(interaction_token, safe="")
    request = urllib.request.Request(
        f"{DISCORD_API}/interactions/{interaction_id}/{encoded_token}/callback",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ThreadkeepGatewayClient/0.1",
        },
        method="POST",
    )
    try:
        with direct_urlopen(request, timeout=2.0) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        finally:
            exc.close()
        return exc.code, body
    except (TimeoutError, urllib.error.URLError, OSError):
        # The callback token is embedded in the request URL. Never allow a
        # transport exception carrying request details to reach persistent logs.
        raise RuntimeError("Discord interaction callback transport failed") from None


def _callback_is_terminal(status: int, body: str) -> bool:
    if 200 <= status < 300:
        return True
    try:
        error_code = json.loads(body).get("code")
    except (AttributeError, json.JSONDecodeError):
        error_code = None
    # 40060 means another delivery already ACKed this interaction. 10062 means
    # the initial deadline expired; the authenticated message PATCH remains the
    # only completion path and is safe to retry.
    return error_code in {40060, 10062}


async def acknowledge_approval_interaction(interaction: dict[str, Any]) -> None:
    status, body = await asyncio.to_thread(
        _post_interaction_callback, interaction, {"type": 6}
    )
    if not _callback_is_terminal(status, body):
        raise RuntimeError(f"Discord interaction ACK failed with HTTP {status}")


async def reject_unauthorized_interaction(
    interaction: dict[str, Any], logger: logging.Logger
) -> None:
    try:
        status, _body = await asyncio.to_thread(
            _post_interaction_callback,
            interaction,
            {
                "type": 4,
                "data": {"content": "Not authorized.", "flags": 1 << 6},
            },
        )
        if not _callback_is_terminal(status, _body):
            logger.warning("unauthorized interaction rejection HTTP %s", status)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "could not reject unauthorized interaction: %s", type(exc).__name__
        )


def validate_interaction_ingress(
    interaction: dict[str, Any], state: dict[str, Any]
) -> tuple[str, str, str]:
    """Bind one component interaction to the authenticated READY principal."""

    if interaction.get("type") != 3:
        raise RuntimeError("gateway interaction is not a message component")
    _require_snowflake(interaction.get("id"), "interaction ID")
    application_id = _require_snowflake(
        interaction.get("application_id"), "application ID"
    )
    expected_application_id = _require_snowflake(
        state.get("application_id"), "READY application binding"
    )
    if application_id != expected_application_id:
        raise RuntimeError("interaction application does not match the READY principal")

    guild_id = _require_snowflake(interaction.get("guild_id"), "guild ID")
    if guild_id != _require_snowflake(CONFIG.discord.guild_id, "configured guild ID"):
        raise RuntimeError("interaction guild does not match configured guild")
    known_guilds = state.get("guild_ids")
    if not isinstance(known_guilds, list) or guild_id not in known_guilds:
        raise RuntimeError("interaction guild is not bound to the active READY session")

    _require_snowflake(interaction.get("channel_id"), "channel ID")
    message = interaction.get("message")
    if not isinstance(message, dict):
        raise RuntimeError("interaction is missing its source message")
    _require_snowflake(message.get("id"), "message ID")
    expected_bot_user_id = _require_snowflake(
        state.get("bot_user_id"), "READY bot binding"
    )
    author_id = _require_snowflake(
        (message.get("author") or {}).get("id"), "message author ID"
    )
    if author_id != expected_bot_user_id:
        raise RuntimeError("interaction source message was not authored by this bot")
    interaction_data = interaction.get("data") or {}
    if not isinstance(interaction_data, dict):
        raise RuntimeError("interaction component data is invalid")
    custom_id = str(interaction_data.get("custom_id") or "")
    if (
        interaction_data.get("component_type") != 2
        or not custom_id
        or not _message_has_custom_id(message, custom_id)
    ):
        raise RuntimeError("clicked component is not present on the source message")
    owner_user_id = _require_snowflake(
        CONFIG.discord.owner_user_id, "configured owner user ID"
    )
    actor_user_id = _require_snowflake(
        _interaction_actor_id(interaction), "interaction actor user ID"
    )
    if actor_user_id != owner_user_id:
        raise UnauthorizedInteractionError(
            "approval interaction actor does not match configured owner"
        )
    return expected_application_id, expected_bot_user_id, guild_id


async def _terminate_router_group(proc: Any, logger: logging.Logger) -> None:
    """Terminate and reap the complete supervised router process group."""

    if proc.returncode is not None:
        await proc.wait()
        return
    process_group = proc.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        await proc.wait()
        return
    logger.warning("terminating router process group pgid=%s", process_group)
    try:
        await asyncio.wait_for(
            asyncio.shield(proc.wait()), timeout=ROUTER_TERMINATE_GRACE_SECONDS
        )
        return
    except asyncio.TimeoutError:
        pass
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await proc.wait()


async def _cleanup_router_group(proc: Any, logger: logging.Logger) -> None:
    cleanup = asyncio.create_task(_terminate_router_group(proc, logger))
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            # The caller propagates its original cancellation after cleanup.
            # Repeated cancellation must never cancel the cleanup task itself.
            continue
    await cleanup


async def dispatch_interaction(
    interaction: dict[str, Any],
    logger: logging.Logger,
    *,
    expected_application_id: str,
    expected_bot_user_id: str,
    expected_guild_id: str,
) -> None:
    """Run router.py under a stable process-group supervisor."""
    if "token" in interaction:
        raise RuntimeError("durable interaction retained its callback token")
    payload = json.dumps(
        {
            "interaction": interaction,
            "expected_application_id": expected_application_id,
            "expected_bot_user_id": expected_bot_user_id,
            "expected_guild_id": expected_guild_id,
            "interaction_preacknowledged": True,
        }
    )
    proc: Any | None = None
    spawn_task: asyncio.Task[Any] | None = None
    try:
        command = supervisor_command(
            [
                sys.executable,
                str(HERE / "router.py"),
                "--from-stdin",
            ]
        )
        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
                env=sanitized_child_environment(keep={"THREADKEEP_CONFIG"}),
            )
        )
        proc = await asyncio.shield(spawn_task)
        _stdout, _stderr = await asyncio.wait_for(
            proc.communicate(input=payload.encode("utf-8")),
            timeout=ROUTER_TIMEOUT_SECONDS,
        )
        if proc.returncode not in {0, 1}:
            # Child output may contain target details or control-file paths.
            # The exit status is sufficient for the retry decision.
            logger.warning("router exit=%s", proc.returncode)
            raise RuntimeError(f"interaction router failed with exit {proc.returncode}")
        elif proc.returncode == 1:
            logger.info("router handled interaction with a user-visible rejection")
    except asyncio.TimeoutError as exc:
        if proc is not None:
            await _cleanup_router_group(proc, logger)
        logger.error("router timed out after %.1fs", ROUTER_TIMEOUT_SECONDS)
        raise RuntimeError("interaction router timed out") from exc
    except asyncio.CancelledError:
        if proc is None and spawn_task is not None:
            while not spawn_task.done():
                try:
                    await asyncio.shield(spawn_task)
                except asyncio.CancelledError:
                    continue
            proc = spawn_task.result()
        if proc is not None:
            await _cleanup_router_group(proc, logger)
        raise
    except BaseException as exc:  # noqa: BLE001
        if proc is not None and proc.returncode is None:
            await _cleanup_router_group(proc, logger)
        logger.exception("router invocation failed: %s", exc)
        raise


async def drain_interaction_once(logger: logging.Logger) -> bool:
    """Attempt one durable inbox row; rc>=2 is released for retry."""

    promoted = interaction_store.activate_stale_received(INTERACTION_STORE_PATH)
    if promoted:
        logger.warning(
            "activated %s interaction(s) through the authenticated PATCH fallback",
            promoted,
        )
    job = interaction_store.claim_next(INTERACTION_STORE_PATH)
    if job is None:
        return False
    try:
        await dispatch_interaction(
            job.interaction,
            logger,
            expected_application_id=job.expected_application_id,
            expected_bot_user_id=job.expected_bot_user_id,
            expected_guild_id=job.expected_guild_id,
        )
    except asyncio.CancelledError:
        interaction_store.release_for_retry(
            INTERACTION_STORE_PATH,
            job.interaction_id,
            "interaction drainer cancelled",
            attempts=job.attempts,
        )
        raise
    except BaseException as exc:  # noqa: BLE001
        delay = interaction_store.release_for_retry(
            INTERACTION_STORE_PATH,
            job.interaction_id,
            f"{type(exc).__name__}: {exc}",
            attempts=job.attempts,
        )
        if delay is None:
            logger.critical(
                "interaction dead-lettered after %s failed attempts; manual review required",
                job.attempts,
            )
        else:
            logger.error(
                "interaction attempt=%s failed; retrying in %.1fs: %s",
                job.attempts,
                delay,
                exc,
            )
        return True
    interaction_store.mark_done(INTERACTION_STORE_PATH, job.interaction_id)
    logger.info("interaction durably completed")
    return True


async def interaction_drain_loop(
    wakeup: asyncio.Event, logger: logging.Logger
) -> None:
    recovered = interaction_store.recover_processing(INTERACTION_STORE_PATH)
    if recovered:
        logger.warning("recovered %s interrupted interaction claim(s)", recovered)
    wakeup.set()
    while True:
        processed = await drain_interaction_once(logger)
        if processed:
            continue
        wakeup.clear()
        try:
            await asyncio.wait_for(
                wakeup.wait(), timeout=INTERACTION_RETRY_POLL_SECONDS
            )
        except asyncio.TimeoutError:
            pass


async def _abort_gateway(ws: Any) -> None:
    """Break a half-open Gateway connection so the outer loop reconnects."""

    transport = getattr(ws, "transport", None)
    if transport is not None:
        transport.abort()
        return
    await ws.close(code=4000, reason="heartbeat failure")


async def heartbeat_loop(
    ws: Any,
    interval_ms: int,
    received: dict[str, Any],
    heartbeat_ack: asyncio.Event,
    logger: logging.Logger,
) -> None:
    """Send heartbeat at the interval Discord requested."""
    await asyncio.sleep((interval_ms / 1000.0) * random.random())
    while True:
        if not heartbeat_ack.is_set():
            logger.warning("Discord heartbeat was not acknowledged; reconnecting")
            await _abort_gateway(ws)
            raise RuntimeError("Discord heartbeat ACK timeout")
        heartbeat_ack.clear()
        try:
            await ws.send(
                json.dumps({"op": OP_HEARTBEAT, "d": received.get("last_seq")})
            )
            logger.debug("heartbeat sent seq=%s", received.get("last_seq"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("heartbeat send failed: %s", type(exc).__name__)
            await _abort_gateway(ws)
            raise RuntimeError("Discord heartbeat send failed") from None
        await asyncio.sleep(interval_ms / 1000.0)


async def gateway_session(
    token: str,
    state: dict[str, Any],
    logger: logging.Logger,
    interaction_wakeup: asyncio.Event | None = None,
) -> None:
    """One gateway session. Returns on disconnect so caller can reconnect."""
    should_resume = bool(
        state.get("session_id")
        and state.get("resume_gateway_url")
        and state.get("application_id") == CONFIG.discord.application_id
        and state.get("bot_user_id") == CONFIG.discord.bot_user_id
        and isinstance(state.get("guild_ids"), list)
        and CONFIG.discord.guild_id in state.get("guild_ids", [])
    )

    _require_direct_discord_transport()
    async with _GATEWAY_CONNECT(
        GATEWAY_URL, max_size=4_000_000, proxy=None
    ) as ws:
        logger.info("connected to gateway")
        hello_raw = await ws.recv()
        hello = json.loads(hello_raw)
        if hello.get("op") != OP_HELLO:
            logger.error("expected HELLO, got %s", hello)
            return
        heartbeat_interval = hello["d"]["heartbeat_interval"]
        logger.info("hello: heartbeat_interval=%sms", heartbeat_interval)

        if should_resume:
            payload = {
                "op": OP_RESUME,
                "d": {
                    "token": token,
                    "session_id": state["session_id"],
                    "seq": state.get("last_seq"),
                },
            }
            logger.info("attempting Gateway RESUME seq=%s", state.get("last_seq"))
        else:
            for key in (
                "session_id",
                "resume_gateway_url",
                "last_seq",
                "application_id",
                "bot_user_id",
                "guild_ids",
            ):
                state.pop(key, None)
            # Reserve only after a valid HELLO, immediately before IDENTIFY.
            # Failed TCP/TLS/HELLO attempts must not burn the durable budget.
            await wait_for_identify_budget(logger)
            payload = {
                "op": OP_IDENTIFY,
                "d": {
                    "token": token,
                    "intents": INTENTS,
                    "properties": {
                        "os": sys.platform,
                        "browser": "ThreadkeepGatewayClient",
                        "device": "ThreadkeepGatewayClient",
                    },
                },
            }
            logger.info("identifying with gateway intents=%s", INTENTS)
        await ws.send(json.dumps(payload))

        # Discord heartbeats acknowledge receipt, while RESUME starts after the
        # last interaction durably entered the inbox. Keep the received and
        # committed sequence numbers separate.
        received = {"last_seq": state.get("last_seq")}
        heartbeat_ack = asyncio.Event()
        heartbeat_ack.set()
        hb_task = asyncio.create_task(
            heartbeat_loop(
                ws,
                heartbeat_interval,
                received,
                heartbeat_ack,
                logger,
            )
        )

        try:
            async for raw in ws:
                msg = json.loads(raw)
                op = msg.get("op")
                sequence = msg.get("s")
                if sequence is not None:
                    if (
                        isinstance(sequence, bool)
                        or not isinstance(sequence, int)
                        or sequence < 0
                    ):
                        raise RuntimeError("gateway returned an invalid sequence")
                    received["last_seq"] = sequence
                if op == OP_DISPATCH:
                    if sequence is None:
                        raise RuntimeError("gateway dispatch omitted its sequence")
                    event = msg.get("t")
                    data = msg.get("d") or {}
                    interaction_activated = False
                    if event == "READY":
                        state["session_id"] = data.get("session_id")
                        state["resume_gateway_url"] = data.get("resume_gateway_url")
                        state["application_id"] = _require_snowflake(
                            (data.get("application") or {}).get("id"),
                            "READY application ID",
                        )
                        if state["application_id"] != _require_snowflake(
                            CONFIG.discord.application_id,
                            "configured application ID",
                        ):
                            raise RuntimeError(
                                "READY application does not match configured application"
                            )
                        state["bot_user_id"] = _require_snowflake(
                            (data.get("user") or {}).get("id"),
                            "READY bot user ID",
                        )
                        if state["bot_user_id"] != _require_snowflake(
                            CONFIG.discord.bot_user_id,
                            "configured bot user ID",
                        ):
                            raise RuntimeError(
                                "READY bot user does not match configured bot"
                            )
                        guilds = data.get("guilds")
                        if not isinstance(guilds, list):
                            raise RuntimeError("READY guild list is invalid")
                        if any(not isinstance(guild, dict) for guild in guilds):
                            raise RuntimeError("READY guild list contains an invalid entry")
                        state["guild_ids"] = sorted(
                            {
                                _require_snowflake(guild.get("id"), "READY guild ID")
                                for guild in guilds
                            }
                        )
                        configured_guild_id = _require_snowflake(
                            CONFIG.discord.guild_id, "configured guild ID"
                        )
                        if state["guild_ids"] != [configured_guild_id]:
                            raise RuntimeError(
                                "READY guild membership is not exactly the configured guild"
                            )
                        logger.info("READY principal and session binding verified")
                    elif event == "RESUMED":
                        logger.info("RESUMED ok")
                    elif event == "GUILD_CREATE":
                        guild_id = _require_snowflake(data.get("id"), "guild ID")
                        if guild_id != _require_snowflake(
                            CONFIG.discord.guild_id, "configured guild ID"
                        ):
                            raise RuntimeError(
                                "dedicated bot joined an unconfigured guild"
                            )
                        state["guild_ids"] = sorted(
                            set(state.get("guild_ids") or []) | {guild_id}
                        )
                    elif event == "GUILD_DELETE":
                        guild_id = _require_snowflake(data.get("id"), "guild ID")
                        if guild_id != _require_snowflake(
                            CONFIG.discord.guild_id, "configured guild ID"
                        ):
                            raise RuntimeError(
                                "dedicated bot reported an unconfigured guild"
                            )
                        state["guild_ids"] = sorted(
                            set(state.get("guild_ids") or []) - {guild_id}
                        )
                    elif event == "INTERACTION_CREATE":
                        classification = classify_interaction(data)
                        if classification == "unrelated":
                            logger.debug(
                                "checkpointing unrelated Discord interaction"
                            )
                        elif classification == "invalid_approval":
                            logger.warning(
                                "checkpointing malformed approval custom_id"
                            )
                        else:
                            try:
                                (
                                    expected_application_id,
                                    expected_bot_user_id,
                                    expected_guild_id,
                                ) = validate_interaction_ingress(data, state)
                            except UnauthorizedInteractionError:
                                logger.warning(
                                    "checkpointing approval click from non-owner"
                                )
                                await reject_unauthorized_interaction(data, logger)
                            except RuntimeError as exc:
                                # An exact Threadkeep approval ID with invalid
                                # principal/message fields is terminally denied.
                                # It must not poison the Gateway RESUME cursor.
                                logger.warning(
                                    "checkpointing invalid approval interaction: %s",
                                    exc,
                                )
                            else:
                                interaction_store.enqueue(
                                    INTERACTION_STORE_PATH,
                                    data,
                                    expected_application_id=expected_application_id,
                                    expected_bot_user_id=expected_bot_user_id,
                                    expected_guild_id=expected_guild_id,
                                )
                                await acknowledge_approval_interaction(data)
                                interaction_store.mark_ready(
                                    INTERACTION_STORE_PATH,
                                    str(data["id"]),
                                )
                                interaction_activated = True
                    else:
                        logger.debug("dispatch event=%s", event)
                    # Commit only after the dispatch side effect succeeds. The
                    # atomic write prevents a crash from checkpointing a
                    # partially handled approval interaction.
                    state["last_seq"] = sequence
                    save_state(state)
                    if interaction_activated and interaction_wakeup is not None:
                        interaction_wakeup.set()
                elif op == OP_HEARTBEAT:
                    heartbeat_ack.clear()
                    await ws.send(
                        json.dumps(
                            {"op": OP_HEARTBEAT, "d": received.get("last_seq")}
                        )
                    )
                elif op == OP_HEARTBEAT_ACK:
                    heartbeat_ack.set()
                    logger.debug("heartbeat ack")
                elif op == OP_RECONNECT:
                    logger.info("gateway requested reconnect")
                    return
                elif op == OP_INVALID_SESSION:
                    resumable = bool(msg.get("d"))
                    logger.warning("invalid session, resumable=%s", resumable)
                    if not resumable:
                        state.pop("session_id", None)
                        state.pop("resume_gateway_url", None)
                        state.pop("last_seq", None)
                        save_state(state)
                    await asyncio.sleep(1 + random.random() * 4)
                    return
                else:
                    logger.debug("opcode %s ignored", op)
        finally:
            hb_task.cancel()
            try:
                await hb_task
            except asyncio.CancelledError:
                pass


async def run_forever() -> None:
    logger = setup_logging()
    token = load_token()
    state = load_state()
    interaction_wakeup = asyncio.Event()
    drain_task = asyncio.create_task(
        interaction_drain_loop(interaction_wakeup, logger),
        name="threadkeep-interaction-drainer",
    )
    backoff = 1.0
    session_task: asyncio.Task[None] | None = None
    try:
        while True:
            session_task = asyncio.create_task(
                gateway_session(
                    token, state, logger, interaction_wakeup=interaction_wakeup
                ),
                name="threadkeep-discord-gateway-session",
            )
            done, _ = await asyncio.wait(
                {session_task, drain_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if drain_task in done:
                session_task.cancel()
                try:
                    await session_task
                except asyncio.CancelledError:
                    pass
                await drain_task
                raise RuntimeError("interaction drainer stopped unexpectedly")
            try:
                await session_task
                backoff = 1.0
                logger.info("session ended cleanly, reconnecting")
            except Exception as exc:  # noqa: BLE001
                logger.exception("session error: %s", exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
            await asyncio.sleep(1)
    finally:
        if session_task is not None and not session_task.done():
            session_task.cancel()
            try:
                await session_task
            except asyncio.CancelledError:
                pass
        drain_task.cancel()
        try:
            await drain_task
        except asyncio.CancelledError:
            pass


def main() -> int:
    def _shutdown(_sig: int, _frame: Any) -> None:
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        asyncio.run(run_forever())
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
