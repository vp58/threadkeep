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
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import mq  # noqa: E402

_REPO_ROOT = _HERE.parents[1]
DISCORD_SCRIPTS = Path(
    os.environ.get("THREADKEEP_DISCORD_SCRIPTS", str(_REPO_ROOT / "approval"))
).expanduser()
REACT = DISCORD_SCRIPTS / "react.py"


def react_eyes(channel_id: str, message_id: str) -> bool:
    """Best-effort eye reaction. Returns True if the call did not raise.

    Idempotent on Discord's side (re-adding an existing reaction is a no-op).
    """
    try:
        subprocess.run(
            ["python3", str(REACT), "--channel-id", channel_id,
             "--message-id", message_id, "--emoji", "eyes"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        return True
    except Exception:
        return False


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
