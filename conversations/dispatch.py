#!/usr/bin/env python3
"""Synchronous state setup for a Discord listen-channel message.

Two modes:
  1. Top-level message: create a thread, create a conversation, append user turn
  2. Thread reply: look up the existing conversation, append user turn

Either way, this script handles only the deterministic state changes. It does
NOT spawn any Claude or Codex session. The caller (the listener agent) is
expected to follow up with an Agent (Task) subagent that performs the actual
work using the session_id and thread_id returned in this script's JSON output.

Output JSON (both modes):
    {
        "mode": "top-level" | "reply",
        "session_id": "<uuid>",
        "thread_id": "<discord_thread_id>",
        "channel_id": "<parent_channel_id>",
        "title": "<conversation title>",
        "convo_path": "<absolute path to active/<uuid>.md>",
        "is_new": true | false
    }
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import lib  # noqa: E402

DISCORD_DIR = _HERE.parent / "discord-gateway"
APPROVAL_DIR = _HERE.parent / "approval"
SEND_MESSAGE = APPROVAL_DIR / "send_message.py"
CREATE_THREAD = APPROVAL_DIR / "create_thread.py"
REACT = APPROVAL_DIR / "react.py"
CONVO_CLI = _HERE / "cli.py"


def _run(cmd: list[str], check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)


def create_thread_in_chat(channel_id: str, message_id: str, name: str) -> str:
    res = _run(["python3", str(CREATE_THREAD),
                "--channel-id", channel_id,
                "--message-id", message_id,
                "--name", name[:100]])
    data = json.loads(res.stdout.strip().splitlines()[-1])
    return data["id"]


def react_eyes(channel_id: str, message_id: str) -> None:
    """Best-effort eyes reaction. Doesn't fail the dispatch if Discord rejects."""
    try:
        _run(["python3", str(REACT),
              "--channel-id", channel_id,
              "--message-id", message_id,
              "--emoji", "eyes"], check=False)
    except Exception:
        pass


def append_turn(session_id: str, speaker: str, text: str) -> None:
    _run(["python3", str(CONVO_CLI), "append-turn", session_id,
          "--speaker", speaker, "--text", text])


def thread_lookup(thread_id: str) -> str | None:
    res = _run(["python3", str(CONVO_CLI), "thread-lookup", thread_id], check=False)
    if res.returncode != 0:
        return None
    return res.stdout.strip() or None


def create_convo(title: str, thread_id: str, session_id: str) -> None:
    _run(["python3", str(CONVO_CLI), "new",
          "--title", title,
          "--thread-id", thread_id,
          "--session-id", session_id])


def cmd_top_level(args: argparse.Namespace) -> int:
    session_id = str(uuid.uuid4())

    thread_id = create_thread_in_chat(args.channel_id, args.message_id, args.title)
    create_convo(args.title, thread_id, session_id)
    append_turn(session_id, "user", args.message)
    react_eyes(args.channel_id, args.message_id)

    convo_path = lib.conversation_path(session_id, status="active")
    print(json.dumps({
        "mode": "top-level",
        "session_id": session_id,
        "thread_id": thread_id,
        "channel_id": args.channel_id,
        "title": args.title,
        "convo_path": str(convo_path),
        "is_new": True,
    }))
    return 0


def cmd_reply(args: argparse.Namespace) -> int:
    session_id = thread_lookup(args.thread_id)
    if not session_id:
        print(json.dumps({"error": f"no conversation registered for thread {args.thread_id}"}),
              file=sys.stderr)
        return 2

    append_turn(session_id, "user", args.message)
    react_eyes(args.thread_id, args.message_id)

    fm, _, path = lib.load_conversation(session_id)
    print(json.dumps({
        "mode": "reply",
        "session_id": session_id,
        "thread_id": args.thread_id,
        "channel_id": fm.get("discord_channel_id"),
        "title": fm.get("title", "(untitled)"),
        "convo_path": str(path),
        "is_new": False,
    }))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="dispatch")
    sub = p.add_subparsers(dest="cmd", required=True)

    tl = sub.add_parser("top-level", help="Top-level message in the listen channel")
    tl.add_argument("--channel-id", required=True, help="Listen channel id (parent)")
    tl.add_argument("--message-id", required=True, help="The user's message id (thread anchor)")
    tl.add_argument("--user", default="owner", help="Posting username")
    tl.add_argument("--title", required=True, help="Short title for the new thread/conversation")
    tl.add_argument("--message", required=True, help="User's full message body")
    tl.set_defaults(func=cmd_top_level)

    rp = sub.add_parser("reply", help="Reply in an existing thread")
    rp.add_argument("--thread-id", required=True)
    rp.add_argument("--message-id", required=True, help="The user's reply message id")
    rp.add_argument("--user", default="owner")
    rp.add_argument("--message", required=True)
    rp.set_defaults(func=cmd_reply)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
