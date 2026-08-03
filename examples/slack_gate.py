#!/usr/bin/env python3
"""Minimal outbound adapter for Threadkeep marker watcher.

This example intentionally does not call Slack. It validates the pending approval
payload shape and prints the command that a real adapter would execute.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_pending(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("pending JSON must be an object")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pending-json", required=True)
    parser.add_argument("--discord-approval-message-id", required=True)
    args = parser.parse_args()

    pending = load_pending(Path(args.pending_json))
    channel = pending.get("channel")
    text = pending.get("text")
    thread_ts = pending.get("thread_ts")

    if not channel or not text:
        print(json.dumps({"ok": False, "error": "pending payload needs channel and text"}))
        return 1

    result = {
        "ok": True,
        "dry_run": True,
        "would_send": {
            "channel": channel,
            "thread_ts": thread_ts,
            "text": text,
            "approval": args.discord_approval_message_id,
        },
    }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
