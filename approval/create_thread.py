#!/usr/bin/env python3
"""Create a Discord thread off a parent message.

Usage:
    create_thread.py --channel-id <channel> --message-id <msg> --name "<thread name>" [--auto-archive 1440]

Returns JSON: {"id": "...", "name": "...", "parent_id": "...", "type": 11}

Discord docs: POST /channels/{channel.id}/messages/{message.id}/threads
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from send_message import load_token  # noqa: E402


def create_thread(channel_id: str, message_id: str, name: str, auto_archive_minutes: int, token: str) -> dict:
    url = f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}/threads"
    payload = json.dumps({
        "name": name[:100],
        "auto_archive_duration": auto_archive_minutes,
    })
    cmd = [
        "curl", "-s", "--retry", "3", "--retry-delay", "5",
        "--retry-connrefused", "--connect-timeout", "10",
        "-X", "POST",
        "-H", f"Authorization: Bot {token}",
        "-H", "Content-Type: application/json",
        "-d", payload,
        url,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"curl failed: {result.stderr}")
    try:
        resp = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"Non-JSON response: {result.stdout[:300]}")
    if "id" not in resp:
        raise RuntimeError(f"Discord API error: {result.stdout[:300]}")
    return resp


def main() -> int:
    p = argparse.ArgumentParser(description="Create a Discord thread off a parent message")
    p.add_argument("--channel-id", required=True, help="Parent channel id")
    p.add_argument("--message-id", required=True, help="Parent message id")
    p.add_argument("--name", required=True, help="Thread name (max 100 chars)")
    p.add_argument("--auto-archive", type=int, default=1440,
                   help="Minutes of inactivity before Discord auto-archives (60, 1440, 4320, 10080)")
    args = p.parse_args()

    token = load_token()
    result = create_thread(args.channel_id, args.message_id, args.name, args.auto_archive, token)
    print(json.dumps({
        "id": result["id"],
        "name": result["name"],
        "parent_id": result.get("parent_id"),
        "type": result.get("type"),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
