#!/usr/bin/env python3
"""Drainer support for the cx-chat orchestrator.

The LLM listener is demoted to a pure queue DRAINER. Per claimed row its only
reasoning job is: generate a 4-7 word title for a NEW top-level (classification
is a deterministic registry lookup, not reasoning). Everything else, claim,
dispatch, ordering, replay, is deterministic code here.

This module provides the deterministic half so the listener prompt shrinks to
"call drain_one, if it hands you a row needing a title, supply one, call
dispatch_claimed". It does NOT spawn the worker subagent itself (that is the
listener's Agent-tool call, which only the listener context can make).

drain flow per row:
    claim_next()                 -> atomic, per-thread-ordered
    classify_row()               -> 'reply' if thread owned, else 'top-level'
    (listener supplies title if top-level and none stored)
    dispatch.py (idempotent)     -> binds thread + session, appends transcript
    mark_dispatched()
    (listener spawns worker, then mark_spawned / mark_done)

The listen-channel id is read from THREADKEEP_LISTEN_CHANNEL_ID (a top-level post
there becomes a new thread; anything else is a reply into an owned thread or is
unowned). The default posting username is read from THREADKEEP_DEFAULT_USER
(falls back to "owner").
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import mq  # noqa: E402

SCRIPTS = _HERE.parent
DISPATCH = SCRIPTS / "dispatch.py"
CONVO_CLI = SCRIPTS / "cli.py"

LISTEN_CHANNEL = os.environ.get("THREADKEEP_LISTEN_CHANNEL_ID", "")
DEFAULT_USER = os.environ.get("THREADKEEP_DEFAULT_USER", "owner")


def classify_row(row: Any) -> str:
    """Deterministic classification: top-level vs reply. A registry lookup, not
    reasoning. If the chat_id is the listen channel itself, it is a top-level
    post; otherwise if the thread is owned (registered) it is a reply."""
    chat_id = str(row["chat_id"])
    if LISTEN_CHANNEL and chat_id == LISTEN_CHANNEL:
        return "top-level"
    # Owned thread?
    res = subprocess.run(
        ["python3", str(CONVO_CLI), "thread-lookup", chat_id],
        capture_output=True, text=True, check=False, timeout=20,
    )
    if res.returncode == 0 and res.stdout.strip():
        return "reply"
    # Unknown thread: not ours. Caller should skip / dead-letter.
    return "unowned"


def dispatch_claimed(
    conn: Any,
    row: Any,
    *,
    title: Optional[str] = None,
) -> dict[str, Any]:
    """Run the (idempotent) dispatch.py for a claimed row and mark it dispatched.

    For a top-level row a title is required (use the stored one, else the passed
    one). Returns the parsed dispatch JSON. On dispatch failure, re-arms the row
    (release_claim) and raises so the caller can retry/alert.
    """
    kind = classify_row(row)
    if kind == "unowned":
        mq.mark_errored(conn, row["message_id"], "unowned thread, not dispatched")
        raise RuntimeError(f"unowned thread {row['chat_id']}")

    if kind == "top-level":
        the_title = row["title"] or title
        if not the_title:
            raise ValueError("top-level row needs a title before dispatch")
        cmd = [
            "python3", str(DISPATCH), "top-level",
            "--channel-id", str(row["chat_id"]),
            "--message-id", str(row["message_id"]),
            "--user", str(row["user"] or DEFAULT_USER),
            "--title", the_title,
            "--message", str(row["body"]),
        ]
    else:  # reply
        cmd = [
            "python3", str(DISPATCH), "reply",
            "--thread-id", str(row["chat_id"]),
            "--message-id", str(row["message_id"]),
            "--user", str(row["user"] or DEFAULT_USER),
            "--message", str(row["body"]),
        ]

    res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)
    if res.returncode != 0:
        mq.release_claim(conn, row["message_id"])
        raise RuntimeError(f"dispatch.py failed rc={res.returncode}: {res.stderr.strip()}")

    data = json.loads(res.stdout.strip().splitlines()[-1])
    mq.mark_dispatched(
        conn, row["message_id"],
        session_id=data["session_id"], thread_id=data["thread_id"],
    )
    return data


def drain_one(conn: Any) -> Optional[dict[str, Any]]:
    """Claim and return the next ready row for the listener to title+spawn.

    Returns a dict with the row fields and its classification, or None if the
    queue has nothing claimable. The listener then supplies a title (if
    top-level and needed) and calls dispatch_claimed + spawns the worker.
    """
    row = mq.claim_next(conn)
    if row is None:
        return None
    kind = classify_row(row)
    return {
        "message_id": row["message_id"],
        "chat_id": row["chat_id"],
        "user": row["user"],
        "body": row["body"],
        "kind": kind,
        "stored_title": row["title"],
        "needs_title": kind == "top-level" and not row["title"],
    }


def mark_spawned(conn: Any, message_id: str) -> None:
    """Record that the worker subagent was launched for this row."""
    mq.mark_spawned(conn, message_id)


def mark_done(conn: Any, message_id: str) -> None:
    """Record that the worker finished this row (terminal)."""
    mq.mark_done(conn, message_id)


def mark_errored(conn: Any, message_id: str, error: str) -> None:
    """Dead-letter this row with an error (terminal)."""
    mq.mark_errored(conn, message_id, error)


def startup_replay(conn: Any) -> dict[str, Any]:
    """On drainer/listener startup: re-arm stale claims and report what is left
    to replay so a crash mid-burst loses nothing.

    Returns {"rearmed": [ids], "pending": [{message_id,state,chat_id}...]}.
    """
    rearmed = mq.recover_stale(conn)
    pend = mq.pending(conn)
    return {
        "rearmed": rearmed,
        "pending": [
            {"message_id": r["message_id"], "state": r["state"],
             "chat_id": r["chat_id"]}
            for r in pend
        ],
    }


# --- thin CLI so the listener / cron can drive it without importing Python ---

def _main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="drainer")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("drain-one")
    sub.add_parser("replay")
    sub.add_parser("metrics")
    dd = sub.add_parser("dispatch-claimed")
    dd.add_argument("--message-id", required=True)
    dd.add_argument("--title", default=None)
    for verb in ("spawned", "done"):
        s = sub.add_parser(f"mark-{verb}")
        s.add_argument("--message-id", required=True)
    me = sub.add_parser("mark-errored")
    me.add_argument("--message-id", required=True)
    me.add_argument("--error", required=True)
    args = p.parse_args(argv)

    conn = mq.connect()
    try:
        if args.cmd == "drain-one":
            print(json.dumps(drain_one(conn)))
        elif args.cmd == "replay":
            print(json.dumps(startup_replay(conn)))
        elif args.cmd == "metrics":
            print(json.dumps(mq.metrics(conn)))
        elif args.cmd == "dispatch-claimed":
            row = mq.get(conn, args.message_id)
            if row is None:
                print(json.dumps({"error": "no such message"}), file=sys.stderr)
                return 2
            print(json.dumps(dispatch_claimed(conn, row, title=args.title)))
        elif args.cmd == "mark-spawned":
            mq.mark_spawned(conn, args.message_id)
            print(json.dumps({"ok": True}))
        elif args.cmd == "mark-done":
            mq.mark_done(conn, args.message_id)
            print(json.dumps({"ok": True}))
        elif args.cmd == "mark-errored":
            mq.mark_errored(conn, args.message_id, args.error)
            print(json.dumps({"ok": True}))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
