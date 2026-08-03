#!/usr/bin/env python3
"""Fake react.py for tests. Records each eye reaction so tests can assert
ack-once (exactly one eye per message_id)."""
import argparse, json, os
from pathlib import Path

LOG = Path(os.environ["THREADKEEP_TEST_CALLLOG"])


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--channel-id", required=True)
    p.add_argument("--message-id", required=True)
    p.add_argument("--emoji", required=True)
    a = p.parse_args()
    # Optional fault injection: set THREADKEEP_TEST_REACT_FAIL=1 to simulate a
    # Discord reaction failure.
    if os.environ.get("THREADKEEP_TEST_REACT_FAIL") == "1":
        raise SystemExit(1)
    with LOG.open("a") as f:
        f.write(json.dumps({"call": "react", "channel_id": a.channel_id,
                            "message_id": a.message_id, "emoji": a.emoji}) + "\n")
    print("ok")


if __name__ == "__main__":
    main()
