#!/usr/bin/env python3
"""Unsupported standalone Discord approval marker watcher.

This daemon is retained only as a hardened reference integration. The public
installer deliberately removes its LaunchAgent and the production Claude flow
does not start it: request_approval.py polls the immutable decision marker
directly. Do not run this watcher alongside that polling flow because the two
consumers race for the same marker.

Polls `approvals/<sha>.json` markers written by request_approval_responder.py
when the owner clicks Approve or Reject. For each approved marker that has a
matching `pending/<sha>.json` send-context file, this daemon invokes a
user-supplied outbound script and edits the Discord prompt message to reflect
the outcome.

Why a daemon: Discord interactions must ACK within 3 seconds, but the outbound
gate scripts in many setups do triple QA, intent checks, and integrity rounds
which routinely exceed 30s. The router cannot block on those. So the router
writes a marker and returns immediately. This daemon picks up the marker and
runs the slow path out of band.

By default this daemon is a no-op for the public install. To use it, set
environment variables:

    THREADKEEP_SLACK_GATE  -- path to a Slack post script that accepts the same
                            flags as documented in docs/PROTOCOL.md
    THREADKEEP_EMAIL_GATE  -- path to an email send script with the same contract

Without these, the daemon will log unknown-operation and archive the marker.

Gates preserved: this daemon does NOT bypass any check. It passes through
every flag the caller provided (gate-json, approval-json,
discord-approval-message-id). The outbound gate scripts remain the sole point
of enforcement.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import logging
import logging.handlers
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "conversations"))
from config import CONFIG  # noqa: E402
from discord_http import direct_urlopen  # noqa: E402
from discord_secret import (  # noqa: E402
    load_discord_token as resolve_discord_token,
    sanitized_child_environment,
)
from codex_discord_bridge.process_supervisor import supervisor_command  # noqa: E402

HERE = Path(__file__).resolve().parent
APPROVALS_DIR = HERE / "approvals"
PENDING_DIR = HERE / "pending"
COMPLETED_DIR = HERE / "completed"
FAILED_DIR = HERE / "failed"
PROCESSED_MARKERS_DIR = HERE / "processed-markers"
INFLIGHT_DIR = HERE / "inflight"
LOG_DIR = HERE / "logs"
LOG_PATH = LOG_DIR / "marker-watcher.log"

SLACK_GATE = os.environ.get("THREADKEEP_SLACK_GATE", "")
EMAIL_GATE = os.environ.get("THREADKEEP_EMAIL_GATE", "")

ORPHAN_GRACE_SEC = 30
DEFAULT_POLL_INTERVAL_SEC = 2
MAX_CONTROL_FILE_BYTES = 1_000_000
MAX_DRAFT_BYTES = 200_000
PENDING_VERSION = 2
MARKER_VERSION = 2
BINDING_VERSION = 1
EXECUTION_MANIFEST_VERSION = 1
SHA_PREFIX_RE = re.compile(r"[a-f0-9]{12,64}\Z")
FULL_SHA_RE = re.compile(r"[a-f0-9]{64}\Z")
SNOWFLAKE_RE = re.compile(r"[1-9][0-9]{16,19}\Z")
PENDING_KEYS = frozenset({"version", "status", "operation", "draft", "binding"})
BINDING_KEYS = frozenset(
    {
        "version",
        "sha_prefix",
        "full_sha",
        "approver_user_id",
        "expected_application_id",
        "expected_guild_id",
        "expected_bot_user_id",
        "discord_prompt_channel_id",
        "discord_prompt_message_id",
        "request_action",
        "request_target",
        "created_at",
        "expires_at",
        "binding_sha256",
    }
)
MARKER_KEYS = frozenset(
    {
        "version",
        "status",
        "action",
        "sha_prefix",
        "full_sha",
        "interaction_id",
        "user_id",
        "application_id",
        "guild_id",
        "bot_user_id",
        "channel_id",
        "message_id",
        "request_action",
        "request_target",
        "binding_sha256",
        "ts",
    }
)
OPERATION_GATES = {
    "slack_post": "slack",
    "gmail_send": "email",
}


@dataclass(frozen=True)
class ValidatedApproval:
    operation: str
    draft: str
    binding: dict[str, Any]
    marker: dict[str, Any]


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


def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("threadkeep-marker-watcher")
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
    stdout = logging.StreamHandler(sys.stdout)
    stdout.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(stdout)
    return logger


def _require_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError(f"approval control directory is unsafe: {path}")


def ensure_dirs() -> None:
    for d in (
        APPROVALS_DIR,
        PENDING_DIR,
        COMPLETED_DIR,
        FAILED_DIR,
        PROCESSED_MARKERS_DIR,
        INFLIGHT_DIR,
    ):
        _require_private_directory(d)


def load_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_CONTROL_FILE_BYTES
        ):
            raise RuntimeError("approval state file is not a private owned regular file")
        raw = bytearray()
        while chunk := os.read(
            descriptor,
            min(65_536, MAX_CONTROL_FILE_BYTES + 1 - len(raw)),
        ):
            raw.extend(chunk)
            if len(raw) > MAX_CONTROL_FILE_BYTES:
                raise RuntimeError("approval state file exceeds the size limit")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or after.st_nlink != 1
        ):
            raise RuntimeError("approval state file changed while reading")
    finally:
        os.close(descriptor)
    payload = json.loads(bytes(raw).decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("approval state file root is not an object")
    return payload


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _require_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _canonical_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def atomic_create_sealed_json(path: Path, payload: dict[str, Any]) -> None:
    """Create one private read-only snapshot without replacing an existing one."""
    _require_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(_canonical_json(payload) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o400)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            raise RuntimeError("sealed execution manifest already exists") from None
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


@contextmanager
def scan_lock():
    """Prevent two watcher processes from executing the same approval."""
    lock_path = APPROVALS_DIR.parent / ".marker-watcher.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("marker watcher lock file is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def load_discord_token() -> str:
    return resolve_discord_token()


def edit_discord_message(channel_id: str, message_id: str, content: str,
                         token: str, logger: logging.Logger) -> None:
    """Patch the prompt message content. Best-effort, never raises."""
    if not channel_id or not message_id:
        return
    _require_direct_discord_transport()
    body = json.dumps({"content": content}).encode("utf-8")
    req = urllib.request.Request(
        f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}",
        data=body,
        headers={
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": "ThreadkeepMarkerWatcher/0.1",
        },
        method="PATCH",
    )
    try:
        with direct_urlopen(req, timeout=10) as resp:
            logger.info("discord patch status=%s", resp.status)
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")[:200]
        finally:
            exc.close()
        logger.warning("discord patch HTTP %s: %s", exc.code, body)
    except Exception as exc:  # noqa: BLE001
        logger.warning("discord patch error: %s", exc)


def fetch_message_content(channel_id: str, message_id: str, token: str,
                          logger: logging.Logger) -> str:
    if not channel_id or not message_id:
        return ""
    _require_direct_discord_transport()
    req = urllib.request.Request(
        f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}",
        headers={
            "Authorization": f"Bot {token}",
            "User-Agent": "ThreadkeepMarkerWatcher/0.1",
        },
    )
    try:
        with direct_urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return str(data.get("content", ""))
    except urllib.error.HTTPError as exc:
        exc.close()
        logger.warning("discord fetch HTTP error")
        return ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("discord fetch error: %s", exc)
        return ""


def build_outbound_cmd(
    approval: ValidatedApproval, execution_manifest_path: Path
) -> list[str] | None:
    """Build the command for the user-supplied outbound script.

    The script receives only the private read-only execution snapshot. It never
    receives the mutable producer-owned pending path.
    """
    if OPERATION_GATES.get(approval.operation) == "slack" and SLACK_GATE:
        gate = SLACK_GATE
    elif OPERATION_GATES.get(approval.operation) == "email" and EMAIL_GATE:
        gate = EMAIL_GATE
    else:
        return None

    binding = approval.binding
    approver_ref = (
        f"{binding['discord_prompt_channel_id']}:"
        f"{binding['discord_prompt_message_id']}"
    )

    cmd = [
        sys.executable,
        gate,
        "--pending-json",
        str(execution_manifest_path),
        "--discord-approval-message-id",
        approver_ref,
        "--discord-approver-user-id",
        str(binding["approver_user_id"]),
    ]
    return cmd


def _require_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"invalid {label}")
    if (
        not value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"invalid {label}")
    return value


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"invalid {label}") from None
    if parsed.tzinfo is None:
        raise ValueError(f"invalid {label}")
    return parsed.astimezone(timezone.utc)


def _validate_binding(
    sha_prefix: str,
    binding: Any,
    *,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(binding, dict) or set(binding) != BINDING_KEYS:
        raise ValueError("pending approval binding has an unexpected schema")
    if type(binding.get("version")) is not int or binding["version"] != BINDING_VERSION:
        raise ValueError("pending approval binding version is invalid")
    digest = binding.get("binding_sha256")
    unsigned = dict(binding)
    unsigned.pop("binding_sha256", None)
    if (
        not isinstance(digest, str)
        or not FULL_SHA_RE.fullmatch(digest)
        or _canonical_digest(unsigned) != digest
    ):
        raise ValueError("pending approval binding digest does not match")

    prefix = binding.get("sha_prefix")
    full_sha = binding.get("full_sha")
    if (
        not isinstance(prefix, str)
        or not SHA_PREFIX_RE.fullmatch(prefix)
        or prefix != sha_prefix
    ):
        raise ValueError("pending approval SHA prefix mismatch")
    if (
        not isinstance(full_sha, str)
        or not FULL_SHA_RE.fullmatch(full_sha)
        or not full_sha.startswith(prefix)
    ):
        raise ValueError("pending approval full SHA mismatch")

    identifiers = (
        "approver_user_id",
        "expected_application_id",
        "expected_guild_id",
        "expected_bot_user_id",
        "discord_prompt_channel_id",
        "discord_prompt_message_id",
    )
    for key in identifiers:
        value = binding.get(key)
        if not isinstance(value, str) or not SNOWFLAKE_RE.fullmatch(value):
            raise ValueError(f"pending approval {key} is invalid")

    expected_configuration = {
        "approver_user_id": CONFIG.discord.owner_user_id,
        "expected_application_id": CONFIG.discord.application_id,
        "expected_guild_id": CONFIG.discord.guild_id,
        "expected_bot_user_id": CONFIG.discord.bot_user_id,
    }
    for key, expected in expected_configuration.items():
        if binding.get(key) != expected:
            raise ValueError(f"pending approval {key} does not match current configuration")

    _require_text(binding.get("request_action"), "request action", 200)
    _require_text(binding.get("request_target"), "request target", 2000)
    created_at = _parse_timestamp(binding.get("created_at"), "binding created_at")
    expiry = binding.get("expires_at")
    if type(expiry) is not int or expiry < int(now.timestamp()):
        raise ValueError("pending approval binding is expired")
    if created_at.timestamp() > expiry:
        raise ValueError("pending approval binding timestamps are invalid")
    return dict(binding)


def _validate_approval(
    sha_prefix: str,
    marker: dict[str, Any],
    pending: dict[str, Any],
    *,
    now: datetime | None = None,
) -> ValidatedApproval:
    current = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    if not SHA_PREFIX_RE.fullmatch(sha_prefix):
        raise ValueError("invalid approval SHA prefix")
    if set(pending) != PENDING_KEYS:
        raise ValueError("pending approval has an unexpected schema")
    if type(pending.get("version")) is not int or pending["version"] != PENDING_VERSION:
        raise ValueError("pending approval version is invalid")
    if pending.get("status") != "pending":
        raise ValueError("pending approval status is invalid")
    operation = pending.get("operation")
    if not isinstance(operation, str) or operation not in OPERATION_GATES:
        raise ValueError("pending approval operation is not allowed")
    draft = pending.get("draft")
    if (
        not isinstance(draft, str)
        or not draft.strip()
        or len(draft.encode("utf-8")) > MAX_DRAFT_BYTES
    ):
        raise ValueError("pending approval draft is invalid")
    binding = _validate_binding(
        sha_prefix,
        pending.get("binding"),
        now=current,
    )
    if binding["request_action"] != operation:
        raise ValueError("pending operation does not match frozen request action")
    if hashlib.sha256(draft.encode("utf-8")).hexdigest() != binding["full_sha"]:
        raise ValueError("pending draft does not match approved full SHA")

    if set(marker) != MARKER_KEYS:
        raise ValueError("approval marker has an unexpected schema")
    if type(marker.get("version")) is not int or marker["version"] != MARKER_VERSION:
        raise ValueError("approval marker version is invalid")
    marker_pair = (marker.get("action"), marker.get("status"))
    if marker_pair not in {("approve", "approved"), ("reject", "rejected")}:
        raise ValueError("approval marker action and status do not match")
    interaction_id = marker.get("interaction_id")
    if not isinstance(interaction_id, str) or not SNOWFLAKE_RE.fullmatch(interaction_id):
        raise ValueError("approval marker interaction_id is invalid")
    marker_time = _parse_timestamp(marker.get("ts"), "approval marker timestamp")
    created_time = _parse_timestamp(binding["created_at"], "binding created_at")
    if marker_time < created_time or marker_time.timestamp() > binding["expires_at"]:
        raise ValueError("approval marker timestamp is outside the binding lifetime")

    expected_marker = {
        "sha_prefix": binding["sha_prefix"],
        "full_sha": binding["full_sha"],
        "user_id": binding["approver_user_id"],
        "application_id": binding["expected_application_id"],
        "guild_id": binding["expected_guild_id"],
        "bot_user_id": binding["expected_bot_user_id"],
        "channel_id": binding["discord_prompt_channel_id"],
        "message_id": binding["discord_prompt_message_id"],
        "request_action": binding["request_action"],
        "request_target": binding["request_target"],
        "binding_sha256": binding["binding_sha256"],
    }
    for key, expected in expected_marker.items():
        if marker.get(key) != expected:
            raise ValueError(f"approval marker {key} does not match frozen binding")
    return ValidatedApproval(
        operation=operation,
        draft=draft,
        binding=binding,
        marker=dict(marker),
    )


def validate_approval_binding(
    sha_prefix: str,
    marker: dict[str, Any],
    pending: dict[str, Any],
    *,
    now: datetime | None = None,
) -> str | None:
    """Return a fail-closed reason when marker and pending intent diverge."""
    try:
        _validate_approval(sha_prefix, marker, pending, now=now)
    except (TypeError, ValueError) as exc:
        return str(exc)
    return None


def build_execution_manifest(approval: ValidatedApproval) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "version": EXECUTION_MANIFEST_VERSION,
        "status": "approved",
        "operation": approval.operation,
        "draft": approval.draft,
        "binding": approval.binding,
        "decision": {
            "action": approval.marker["action"],
            "status": approval.marker["status"],
            "interaction_id": approval.marker["interaction_id"],
            "ts": approval.marker["ts"],
        },
    }
    manifest["execution_manifest_sha256"] = _canonical_digest(manifest)
    return manifest


def now_hhmm_utc() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M UTC")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def unlink_durable(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def execute_send(
    sha_prefix: str,
    approval: ValidatedApproval,
    execution_manifest_path: Path,
    logger: logging.Logger,
    timeout_sec: int = 180,
) -> dict[str, Any]:
    """Invoke the configured outbound script. Returns result record."""
    cmd = build_outbound_cmd(approval, execution_manifest_path)
    if cmd is None:
        return {
            "ok": False,
            "error": f"no outbound gate configured for operation {approval.operation}",
        }

    logger.info("executing sha=%s op=%s", sha_prefix, approval.operation)
    try:
        proc = run_outbound_command(cmd, timeout_sec)
    except subprocess.TimeoutExpired as exc:
        logger.error("send timed out after %ss for sha=%s: %s", timeout_sec, sha_prefix, exc)
        return {"ok": False, "error": f"timeout after {timeout_sec}s"}
    logger.info("rc=%s", proc.returncode)
    if proc.returncode != 0:
        return {
            "ok": False,
            "rc": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    return {
        "ok": True,
        "rc": 0,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def run_outbound_command(
    cmd: list[str], timeout_sec: int
) -> subprocess.CompletedProcess[str]:
    """Run one optional gate with a scrubbed environment and group cleanup."""

    proc = subprocess.Popen(
        supervisor_command(cmd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=sanitized_child_environment(),
        cwd=REPO_ROOT,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def handle_approved_marker(sha_prefix: str, marker_path: Path, pending_path: Path,
                           logger: logging.Logger, discord_token: str,
                           timeout_sec: int = 180) -> None:
    marker = load_json(marker_path)
    pending = load_json(pending_path)
    completed_path = COMPLETED_DIR / f"{sha_prefix}.json"
    failed_path = FAILED_DIR / f"{sha_prefix}.json"
    inflight_path = INFLIGHT_DIR / f"{sha_prefix}.json"
    execution_manifest_path = INFLIGHT_DIR / f"{sha_prefix}.execution.json"

    # A final record is the durable replay fence. If cleanup was interrupted
    # after it was written, archive the remaining inputs without executing the
    # external gate again.
    for final_path in (completed_path, failed_path):
        if final_path.exists():
            load_json(final_path)
            logger.warning(
                "approval already has durable outcome sha=%s; completing cleanup",
                sha_prefix,
            )
            try:
                marker_path.rename(PROCESSED_MARKERS_DIR / marker_path.name)
            except FileNotFoundError:
                pass
            unlink_durable(pending_path)
            unlink_durable(inflight_path)
            unlink_durable(execution_manifest_path)
            return

    try:
        approval = _validate_approval(sha_prefix, marker, pending)
    except (TypeError, ValueError) as exc:
        logger.error("approval binding rejected sha=%s reason=%s", sha_prefix, exc)
        try:
            marker_path.rename(PROCESSED_MARKERS_DIR / marker_path.name)
        except Exception as archive_error:  # noqa: BLE001
            logger.error(
                "failed to quarantine invalid marker sha=%s: %s",
                sha_prefix,
                archive_error,
            )
        return

    trusted_channel = str(approval.binding["discord_prompt_channel_id"])
    trusted_message = str(approval.binding["discord_prompt_message_id"])
    if inflight_path.exists():
        # The prior process durably claimed this approval but did not write a
        # final result. The external send may have happened. Never replay it.
        load_json(inflight_path)
        result = {
            "ok": False,
            "uncertain": True,
            "error": "outbound result is uncertain after an interrupted durable claim",
        }
    else:
        execution_manifest = build_execution_manifest(approval)
        atomic_write_json(
            inflight_path,
            {
                "version": 1,
                "state": "executing",
                "sha_prefix": sha_prefix,
                "claimed_at": now_iso(),
                "binding_sha256": approval.binding["binding_sha256"],
                "execution_manifest_sha256": execution_manifest[
                    "execution_manifest_sha256"
                ],
            },
        )
        atomic_create_sealed_json(execution_manifest_path, execution_manifest)
        result = execute_send(
            sha_prefix,
            approval,
            execution_manifest_path,
            logger,
            timeout_sec=timeout_sec,
        )

    stamp = now_hhmm_utc()

    if trusted_channel and trusted_message:
        current = fetch_message_content(
            trusted_channel,
            trusted_message,
            discord_token,
            logger,
        )
        base = current.strip() or f"[APPROVED {stamp}] (content unavailable)"
    else:
        base = ""

    if result.get("ok"):
        suffix = f"\n[SENT {stamp}]"
        new_content = base + suffix
        edit_discord_message(
            trusted_channel,
            trusted_message,
            new_content,
            discord_token,
            logger,
        )
        atomic_write_json(completed_path, {
            "sha_prefix": sha_prefix,
            "operation": approval.operation,
            "completed_at": now_iso(),
            "marker": marker,
            "pending": pending,
            "result": result,
        })
        logger.info("completed sha=%s -> %s", sha_prefix, completed_path)
    else:
        reason = result.get("error") or result.get("stderr") or result.get("stdout") or "unknown"
        suffix = f"\n[SEND FAILED {stamp}: {str(reason)[:200]}]"
        new_content = base + suffix
        if trusted_channel and trusted_message:
            edit_discord_message(
                trusted_channel,
                trusted_message,
                new_content,
                discord_token,
                logger,
            )
        atomic_write_json(failed_path, {
            "sha_prefix": sha_prefix,
            "operation": pending.get("operation", ""),
            "failed_at": now_iso(),
            "marker": marker,
            "pending": pending,
            "result": result,
        })
        logger.error("failed sha=%s -> %s", sha_prefix, failed_path)

    try:
        marker_path.rename(PROCESSED_MARKERS_DIR / marker_path.name)
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to archive marker %s: %s", marker_path, exc)
        try:
            marker_path.unlink()
        except Exception:
            pass
    unlink_durable(pending_path)
    unlink_durable(inflight_path)
    unlink_durable(execution_manifest_path)


def handle_rejected_marker(
    sha_prefix: str,
    marker_path: Path,
    pending_path: Path,
    logger: logging.Logger,
) -> None:
    marker = load_json(marker_path)
    pending = load_json(pending_path)
    try:
        approval = _validate_approval(sha_prefix, marker, pending)
    except (TypeError, ValueError) as exc:
        # A forged rejection must not destroy a legitimate pending operation.
        logger.error(
            "rejection binding rejected sha=%s reason=%s; preserving pending",
            sha_prefix,
            exc,
        )
    else:
        if approval.marker["status"] != "rejected":
            raise RuntimeError("rejection handler received a non-rejected marker")
        logger.info("rejected sha=%s; clearing exact bound pending operation", sha_prefix)
        unlink_durable(pending_path)
    try:
        marker_path.rename(PROCESSED_MARKERS_DIR / marker_path.name)
    except Exception:
        try:
            marker_path.unlink()
        except Exception:
            pass


def _scan_once_unlocked(
    logger: logging.Logger, discord_token: str, timeout_sec: int = 180
) -> int:
    """Single sweep over approvals/. Returns count of markers processed."""
    processed = 0
    for marker_path in sorted(APPROVALS_DIR.glob("*.json")):
        sha_prefix = marker_path.stem
        try:
            marker = load_json(marker_path)
        except Exception as exc:  # noqa: BLE001
            logger.error("bad marker %s: %s; archiving", marker_path, exc)
            try:
                marker_path.rename(PROCESSED_MARKERS_DIR / marker_path.name)
            except Exception:
                pass
            continue
        status = str(marker.get("status", "")).lower()
        pending_path = PENDING_DIR / f"{sha_prefix}.json"

        if status not in {"approved", "rejected"}:
            logger.warning("marker %s has unknown status=%s; archiving", marker_path, status)
            try:
                marker_path.rename(PROCESSED_MARKERS_DIR / marker_path.name)
            except Exception:
                pass
            processed += 1
            continue

        if not pending_path.exists():
            try:
                marker_age = time.time() - marker_path.stat().st_mtime
            except Exception:
                marker_age = 0
            if marker_age < ORPHAN_GRACE_SEC:
                logger.info("approved sha=%s no pending yet (age=%.1fs); waiting",
                            sha_prefix, marker_age)
                continue
            logger.info("approved sha=%s orphan after %.0fs grace; archiving",
                        sha_prefix, marker_age)
            try:
                marker_path.rename(PROCESSED_MARKERS_DIR / marker_path.name)
            except Exception:
                pass
            processed += 1
            continue

        if status == "rejected":
            handle_rejected_marker(sha_prefix, marker_path, pending_path, logger)
        else:
            handle_approved_marker(
                sha_prefix,
                marker_path,
                pending_path,
                logger,
                discord_token,
                timeout_sec=timeout_sec,
            )
        processed += 1
    return processed


def scan_once(logger: logging.Logger, discord_token: str, timeout_sec: int = 180) -> int:
    """Serialize one durable marker sweep across local watcher processes."""
    with scan_lock():
        return _scan_once_unlocked(logger, discord_token, timeout_sec)


def run_forever(poll_interval_sec: int, logger: logging.Logger,
                discord_token: str, timeout_sec: int = 180) -> int:
    logger.info("marker-watcher started; polling %s every %ss",
                APPROVALS_DIR, poll_interval_sec)
    while True:
        try:
            scan_once(logger, discord_token, timeout_sec=timeout_sec)
        except Exception as exc:  # noqa: BLE001
            logger.exception("scan error: %s", exc)
        time.sleep(max(1, poll_interval_sec))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true",
                        help="Run a single scan and exit (test mode)")
    parser.add_argument("--poll-interval-sec", type=int, default=DEFAULT_POLL_INTERVAL_SEC)
    parser.add_argument("--send-timeout-sec", type=int, default=180,
                        help="How long to wait for the outbound gate script to complete.")
    args = parser.parse_args()

    logger = setup_logging()
    ensure_dirs()
    try:
        token = load_discord_token()
    except Exception as exc:  # noqa: BLE001
        logger.exception("token load failed: %s", exc)
        return 2

    if args.once:
        processed = scan_once(logger, token, timeout_sec=args.send_timeout_sec)
        logger.info("scan complete; processed=%s", processed)
        return 0

    return run_forever(args.poll_interval_sec, logger, token, timeout_sec=args.send_timeout_sec)


if __name__ == "__main__":
    sys.exit(main())
