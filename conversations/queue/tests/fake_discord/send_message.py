#!/usr/bin/env python3
"""Fake send_message.py for tests. Records sends (used by monitor alert test)."""
import argparse, json, os
from pathlib import Path

LOG = Path(os.environ["DISCOPARTY_TEST_CALLLOG"])


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--channel-id", required=True)
    p.add_argument("--message", required=True)
    a = p.parse_args()
    with LOG.open("a") as f:
        f.write(json.dumps({"call": "send", "channel_id": a.channel_id,
                            "message": a.message}) + "\n")
    print("sent")


if __name__ == "__main__":
    main()
