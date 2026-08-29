#!/usr/bin/env python3
"""Legacy dry-run parser for an obsolete marker-watcher payload.

This file is retained only as reference material. The production installer does
not install the watcher, this parser is not a security gate, and it never calls
Slack. The current review reference is not a one-time send capability.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path


def load_pending(path: Path) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > 1_000_000
        ):
            raise ValueError("pending JSON file is not private and owned")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            payload = json.load(handle)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise ValueError("pending JSON must be an object")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pending-json", required=True)
    parser.add_argument("--discord-approval-message-id", required=True)
    parser.add_argument("--discord-approver-user-id", required=True)
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
            "approver_user_id": args.discord_approver_user_id,
        },
    }
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
