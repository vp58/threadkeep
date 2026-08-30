#!/usr/bin/env python3
"""Deterministic intake for the cx-chat orchestrator.

The instant a message lands in the listen channel or an owned thread, intake
does two things and NOTHING else, with NO LLM involved:

    1. add the eye reaction  (the human knows we have it)
    2. INSERT the row into the durable queue keyed on message_id

The eye reaction then means "the system has this, durably," not "the LLM finally
reached it." Ack latency becomes constant and independent of LLM state. A crash
after this point loses nothing: the row is on disk and the drainer replays it.

intake is safe to call redundantly: enqueue is idempotent on message_id and the
eye reaction is idempotent on Discord's side, so even if BOTH the legacy path and
intake run during a transition window, nothing double-acks or double-records.

The Discord helper scripts (react.py) are resolved from the repo's approval/
directory by default; override with THREADKEEP_DISCORD_SCRIPTS (used by tests to
inject fakes).
"""
from __future__ import annotations

import os
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import mq  # noqa: E402
sys.path.insert(0, str(_HERE.parent))
import safe_files  # noqa: E402
from public_output import contains_sensitive_data  # noqa: E402

_REPO_ROOT = _HERE.parents[1]
DISCORD_SCRIPTS = Path(
    os.environ.get("THREADKEEP_DISCORD_SCRIPTS", str(_REPO_ROOT / "approval"))
).expanduser()
REACT = DISCORD_SCRIPTS / "react.py"


def _react(channel_id: str, message_id: str, emoji: str) -> bool:
    """Best-effort reaction. True requires exit 0 and one exact ``ok``.

    Idempotent on Discord's side (re-adding an existing reaction is a no-op).
    """
    try:
        result = subprocess.run(
            [sys.executable, str(REACT), "--channel-id", channel_id,
             "--message-id", message_id, "--emoji", emoji],
            capture_output=True, text=True, timeout=20, check=False,
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        exact_ack = (stdout, stderr) in {("ok", ""), ("", "ok")}
        return result.returncode == 0 and exact_ack
    except Exception:
        return False


def react_eyes(channel_id: str, message_id: str) -> bool:
    return _react(channel_id, message_id, "eyes")


def react_sensitive_rejection(channel_id: str, message_id: str) -> bool:
    return _react(channel_id, message_id, "🚫")


def handle_inbound(
    *,
    message_id: str,
    chat_id: str,
    body: str,
    user: Optional[str] = None,
    ts: Optional[str] = None,
    kind: Optional[str] = None,
    react: bool = True,
    conn: Optional[Any] = None,
) -> dict[str, Any]:
    """Deterministic intake of one inbound message. No LLM.

    Order matters for the invariant: we DURABLY RECORD first, then react. If we
    crash between, the row exists and the drainer will (re-)ack on replay. If we
    reacted first and crashed before the insert, the human would see an eye for a
    message we have no record of.

    Returns a small status dict. Idempotent on message_id.
    """
    if contains_sensitive_data(body):
        acked = react_sensitive_rejection(chat_id, message_id) if react else False
        return {
            "message_id": message_id,
            "chat_id": chat_id,
            "new": False,
            "acked": acked,
            "rejected": "sensitive-data",
            "at": time.time(),
        }

    own_conn = conn is None
    if own_conn:
        conn = mq.connect()
    try:
        inserted = mq.enqueue(
            conn, message_id=message_id, chat_id=chat_id, body=body,
            user=user, ts=ts, kind=kind,
        )
        acked = False
        if react:
            acked = react_eyes(chat_id, message_id)
            if acked:
                mq.mark_acked(conn, message_id)
        return {
            "message_id": message_id,
            "chat_id": chat_id,
            "new": inserted,
            "acked": acked,
            "at": time.time(),
        }
    finally:
        if own_conn:
            conn.close()


def _main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="intake")
    parser.add_argument(
        "--exchange-id",
        required=True,
        help="Private intake exchange ID allocated by conversations/safe_files.py",
    )
    args = parser.parse_args(argv)
    raw = safe_files.read("intake", args.exchange_id, consume=True)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit("intake exchange is not valid JSON") from exc
    if not isinstance(payload, dict) or set(payload) - {
        "message_id",
        "chat_id",
        "body",
        "user",
        "user_id",
        "ts",
        "kind",
    }:
        raise SystemExit("intake exchange has an invalid object shape")
    message_id = payload.get("message_id")
    chat_id = payload.get("chat_id")
    body = payload.get("body")
    user = payload.get("user")
    user_id = payload.get("user_id")
    ts = payload.get("ts")
    kind = payload.get("kind")
    if not isinstance(message_id, str) or not message_id.isdecimal():
        raise SystemExit("intake message_id must be numeric")
    if not isinstance(chat_id, str) or not chat_id.isdecimal():
        raise SystemExit("intake chat_id must be numeric")
    if not isinstance(body, str) or not body.strip() or len(body) > 100_000:
        raise SystemExit("intake body is empty or too large")
    if user is not None and (not isinstance(user, str) or len(user) > 256):
        raise SystemExit("intake user is invalid")
    from config import CONFIG

    if not isinstance(user_id, str) or user_id != CONFIG.discord.owner_user_id:
        raise SystemExit("intake author is not the configured owner")
    if ts is not None and (not isinstance(ts, str) or len(ts) > 128):
        raise SystemExit("intake timestamp is invalid")
    if kind is not None and kind not in {"top-level", "reply"}:
        raise SystemExit("intake kind is invalid")
    result = handle_inbound(
        message_id=message_id,
        chat_id=chat_id,
        body=body,
        user=user,
        ts=ts,
        kind=kind,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
