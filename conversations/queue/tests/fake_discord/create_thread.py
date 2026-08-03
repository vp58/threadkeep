#!/usr/bin/env python3
"""Fake create_thread.py for tests. Deterministic thread id from message id,
records the call, prints the same JSON shape the real one does ({"id": ...})."""
import argparse, json, os
from pathlib import Path

LOG = Path(os.environ["THREADKEEP_TEST_CALLLOG"])


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--channel-id", required=True)
    p.add_argument("--message-id", required=True)
    p.add_argument("--name", required=True)
    a = p.parse_args()
    thread_id = f"thr_{a.message_id}"
    with LOG.open("a") as f:
        f.write(json.dumps({"call": "create_thread", "channel_id": a.channel_id,
                            "message_id": a.message_id, "thread_id": thread_id}) + "\n")
    print(json.dumps({"id": thread_id}))


if __name__ == "__main__":
    main()
