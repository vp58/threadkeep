#!/usr/bin/env python3
"""Durable fake for starter-message thread create and reconciliation."""
import json
import os
import sys
import time
from pathlib import Path

LOG = Path(os.environ["THREADKEEP_TEST_CALLLOG"])
STATE = LOG.with_name("fake-threads.json")


def load_state():
    if not STATE.exists():
        return {}
    return json.loads(STATE.read_text())


def save_state(value):
    temporary = STATE.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True))
    os.replace(temporary, STATE)


def main():
    payload = json.loads(sys.stdin.read())
    if set(payload) != {
        "operation",
        "channel_id",
        "message_id",
        "name",
        "auto_archive",
    }:
        raise SystemExit("invalid shape")
    message_id = payload["message_id"]
    state = load_state()
    thread = state.get(message_id)
    call = {
        "call": "create_thread",
        "operation": payload["operation"],
        "channel_id": payload["channel_id"],
        "message_id": message_id,
        "argv": sys.argv,
    }
    with LOG.open("a") as stream:
        stream.write(json.dumps(call, sort_keys=True) + "\n")
    if thread is None:
        if payload["operation"] == "reconcile":
            print(json.dumps({
                "outcome": "absent",
                "channel_id": payload["channel_id"],
                "thread_id": message_id,
            }, sort_keys=True))
            return
        if payload["operation"] not in {"create", "recover"}:
            raise SystemExit("unsupported thread operation")
        if (
            payload["operation"] == "create"
            and os.environ.get("THREADKEEP_TEST_THREAD_FAIL_BEFORE_CREATE") == "1"
        ):
            raise SystemExit(70)
        if (
            payload["operation"] == "recover"
            and os.environ.get("THREADKEEP_TEST_THREAD_FAIL_BEFORE_RECOVERY") == "1"
        ):
            raise SystemExit(72)
        thread = {
            "id": message_id,
            "name": payload["name"],
            "parent_id": payload["channel_id"],
            "type": 11,
            "owner_id": "fake-bot",
        }
        state[message_id] = thread
        save_state(state)
        delay = float(os.environ.get("THREADKEEP_TEST_THREAD_CREATE_DELAY", "0"))
        if delay:
            time.sleep(delay)
        if os.environ.get("THREADKEEP_TEST_THREAD_CRASH_AFTER_CREATE") == "1":
            raise SystemExit(71)
    elif (
        thread["name"] != payload["name"]
        or thread["parent_id"] != payload["channel_id"]
    ):
        raise SystemExit("frozen thread mismatch")
    print(json.dumps(thread, sort_keys=True))


if __name__ == "__main__":
    main()
