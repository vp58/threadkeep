#!/usr/bin/env python3
"""Add a reaction to a Discord message.

Usage:
    react.py --channel-id <channel> --message-id <msg> --emoji <emoji>

Emoji format: alias (eyes, check, x, ...) or a unicode literal.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from send_message import load_token  # noqa: E402

ALIASES = {
    "eyes": "\N{EYES}",
    "check": "\N{WHITE HEAVY CHECK MARK}",
    "white_check_mark": "\N{WHITE HEAVY CHECK MARK}",
    "x": "\N{CROSS MARK}",
    "fire": "\N{FIRE}",
    "thumbsup": "\N{THUMBS UP SIGN}",
    "thumbsdown": "\N{THUMBS DOWN SIGN}",
    "thinking": "\N{THINKING FACE}",
    "rocket": "\N{ROCKET}",
    "warning": "\N{WARNING SIGN}",
    "heart": "\N{HEAVY BLACK HEART}",
    "hourglass": "\N{HOURGLASS WITH FLOWING SAND}",
    "wave": "\N{WAVING HAND SIGN}",
}


def react(channel_id: str, message_id: str, emoji: str, token: str) -> bool:
    encoded = urllib.parse.quote(emoji, safe="")
    url = f"https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}/reactions/{encoded}/@me"
    cmd = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--retry", "3", "--retry-delay", "3",
        "-X", "PUT",
        "-H", f"Authorization: Bot {token}",
        "-H", "Content-Length: 0",
        url,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    status = result.stdout.strip()
    return status in ("204", "200")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--channel-id", required=True)
    p.add_argument("--message-id", required=True)
    p.add_argument("--emoji", required=True, help="Alias (eyes, check, x) or unicode literal")
    args = p.parse_args()

    emoji = ALIASES.get(args.emoji.lower().strip(":"), args.emoji)
    token = load_token()
    ok = react(args.channel_id, args.message_id, emoji, token)
    print("ok" if ok else "failed", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
