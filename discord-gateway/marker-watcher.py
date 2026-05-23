#!/usr/bin/env python3
"""Discord approval marker watcher daemon (optional component).

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
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "conversations"))
from config import CONFIG  # noqa: E402

HERE = Path(__file__).resolve().parent
APPROVALS_DIR = HERE / "approvals"
PENDING_DIR = HERE / "pending"
COMPLETED_DIR = HERE / "completed"
FAILED_DIR = HERE / "failed"
PROCESSED_MARKERS_DIR = HERE / "processed-markers"
LOG_DIR = HERE / "logs"
LOG_PATH = LOG_DIR / "marker-watcher.log"

SLACK_GATE = os.environ.get("THREADKEEP_SLACK_GATE", "")
EMAIL_GATE = os.environ.get("THREADKEEP_EMAIL_GATE", "")

ORPHAN_GRACE_SEC = 30
DEFAULT_POLL_INTERVAL_SEC = 2


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


def ensure_dirs() -> None:
    for d in (APPROVALS_DIR, PENDING_DIR, COMPLETED_DIR, FAILED_DIR, PROCESSED_MARKERS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(path)


def load_discord_token() -> str:
    token = os.environ.get(CONFIG.discord.token_env_var, "")
    if token:
        return token
    if CONFIG.discord.token_file and CONFIG.discord.token_file.exists():
        return CONFIG.discord.token_file.read_text().strip()
    raise RuntimeError(
        f"No Discord bot token found. Set {CONFIG.discord.token_env_var} "
        "or configure discord.token_file in config.toml."
    )


def edit_discord_message(channel_id: str, message_id: str, content: str,
                         token: str, logger: logging.Logger) -> None:
    """Patch the prompt message content. Best-effort, never raises."""
    if not channel_id or not message_id:
        return
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
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("discord patch status=%s", resp.status)
    except urllib.error.HTTPError as exc:
        logger.warning("discord patch HTTP %s: %s", exc.code,
                       exc.read().decode("utf-8", errors="replace")[:200])
    except Exception as exc:  # noqa: BLE001
        logger.warning("discord patch error: %s", exc)


def fetch_message_content(channel_id: str, message_id: str, token: str,
                          logger: logging.Logger) -> str:
    if not channel_id or not message_id:
        return ""
    req = urllib.request.Request(
        f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}",
        headers={
            "Authorization": f"Bot {token}",
            "User-Agent": "ThreadkeepMarkerWatcher/0.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return str(data.get("content", ""))
    except Exception as exc:  # noqa: BLE001
        logger.warning("discord fetch error: %s", exc)
        return ""


def build_outbound_cmd(pending: dict[str, Any], marker: dict[str, Any]) -> list[str] | None:
    """Build the command for the user-supplied outbound script.

    The script receives all pending fields via --pending-json. The user's script
    is responsible for interpreting the operation, calling the actual API, and
    returning JSON on stdout.
    """
    op = pending.get("operation", "")
    if op.startswith("slack_") and SLACK_GATE:
        gate = SLACK_GATE
    elif op == "gmail_send" and EMAIL_GATE:
        gate = EMAIL_GATE
    else:
        return None

    ch_id = marker.get("channel_id") or pending.get("discord_prompt_channel_id", "")
    msg_id = marker.get("message_id") or pending.get("discord_prompt_message_id", "")
    approver_ref = f"{ch_id}:{msg_id}" if (ch_id and msg_id) else ""

    cmd = [
        sys.executable,
        gate,
        "--pending-json", json.dumps(pending),
    ]
    if approver_ref:
        cmd.extend(["--discord-approval-message-id", approver_ref])
        cmd.extend(["--discord-approver-user-id", pending.get("approver_user_id", "")])
    return cmd


def now_hhmm_utc() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M UTC")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def execute_send(sha_prefix: str, marker: dict[str, Any], pending: dict[str, Any],
                 logger: logging.Logger, timeout_sec: int = 180) -> dict[str, Any]:
    """Invoke the configured outbound script. Returns result record."""
    cmd = build_outbound_cmd(pending, marker)
    if cmd is None:
        return {
            "ok": False,
            "error": f"no outbound gate configured for operation {pending.get('operation', '')}",
        }

    logger.info("executing sha=%s op=%s", sha_prefix, pending.get("operation", ""))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
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


def handle_approved_marker(sha_prefix: str, marker_path: Path, pending_path: Path,
                           logger: logging.Logger, discord_token: str,
                           timeout_sec: int = 180) -> None:
    marker = load_json(marker_path)
    pending = load_json(pending_path)

    if pending.get("sha_prefix", "") != sha_prefix:
        logger.error("sha mismatch marker=%s pending=%s; treating as failure",
                     sha_prefix, pending.get("sha_prefix", ""))

    result = execute_send(sha_prefix, marker, pending, logger, timeout_sec=timeout_sec)

    ch_id = pending.get("discord_prompt_channel_id", "") or marker.get("channel_id", "")
    msg_id = pending.get("discord_prompt_message_id", "") or marker.get("message_id", "")
    stamp = now_hhmm_utc()

    current = fetch_message_content(ch_id, msg_id, discord_token, logger)
    base = current.strip() or f"[APPROVED {stamp}] (content unavailable)"

    if result.get("ok"):
        suffix = f"\n[SENT {stamp}]"
        new_content = base + suffix
        edit_discord_message(ch_id, msg_id, new_content, discord_token, logger)
        completed_path = COMPLETED_DIR / f"{sha_prefix}.json"
        atomic_write_json(completed_path, {
            "sha_prefix": sha_prefix,
            "operation": pending.get("operation", ""),
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
        edit_discord_message(ch_id, msg_id, new_content, discord_token, logger)
        failed_path = FAILED_DIR / f"{sha_prefix}.json"
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
    try:
        pending_path.unlink()
    except Exception:
        pass


def handle_rejected_marker(sha_prefix: str, marker_path: Path, pending_path: Path | None,
                           logger: logging.Logger) -> None:
    logger.info("rejected sha=%s; clearing pending", sha_prefix)
    if pending_path and pending_path.exists():
        try:
            pending_path.unlink()
        except Exception:
            pass
    try:
        marker_path.rename(PROCESSED_MARKERS_DIR / marker_path.name)
    except Exception:
        try:
            marker_path.unlink()
        except Exception:
            pass


def scan_once(logger: logging.Logger, discord_token: str, timeout_sec: int = 180) -> int:
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

        if status == "rejected":
            handle_rejected_marker(sha_prefix, marker_path, pending_path, logger)
            processed += 1
            continue

        if status != "approved":
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

        handle_approved_marker(sha_prefix, marker_path, pending_path,
                               logger, discord_token, timeout_sec=timeout_sec)
        processed += 1
    return processed


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
