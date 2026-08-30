#!/usr/bin/env python3
"""Crash-replay-safe dispatch for one already-claimed queue message.

The only accepted input is a small JSON object on stdin containing a queue
message ID and, for a new top-level post, an optional generated title. The
owner's message body and display name are read from the private queue database
and never cross a process argv boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE / "queue"))

import idempotency  # noqa: E402
import lib  # noqa: E402
import mq  # noqa: E402
from config import CONFIG  # noqa: E402
from public_output import public_safe_output, withheld_notice  # noqa: E402

APPROVAL_DIR = Path(
    os.environ.get("THREADKEEP_DISCORD_SCRIPTS", str(_HERE.parent / "approval"))
).expanduser()
CREATE_THREAD = APPROVAL_DIR / "create_thread.py"


def _run_json_helper(path: Path, payload: dict[str, Any], timeout: int = 60) -> dict[str, Any]:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    result = subprocess.run(
        [sys.executable, str(path)],
        input=encoded,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else ""
        raise RuntimeError(
            f"Discord helper failed with rc={result.returncode}"
            + (f": {detail[:500]}" if detail else "")
        )
    try:
        value = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise RuntimeError("Discord helper returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Discord helper result is not an object")
    return value


def _read_stdin() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise RuntimeError("dispatch request is too large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("dispatch stdin must be one UTF-8 JSON object") from exc
    if not isinstance(payload, dict) or set(payload) - {"message_id", "title"}:
        raise RuntimeError("dispatch request has an invalid object shape")
    message_id = payload.get("message_id")
    title = payload.get("title")
    if not isinstance(message_id, str) or not message_id or len(message_id) > 128:
        raise RuntimeError("dispatch message_id is invalid")
    if title is not None and (
        not isinstance(title, str)
        or not title.strip()
        or len(title) > 100
        or "\n" in title
        or "\r" in title
    ):
        raise RuntimeError("dispatch title is invalid")
    return {"message_id": message_id, "title": title.strip() if title else None}


def _safe_title(value: str) -> str:
    title = public_safe_output(value.strip(), agent_name="Claude")
    if title == withheld_notice("Claude"):
        title = "Threadkeep conversation"
    title = " ".join(title.split())[:100].strip()
    if not title:
        raise RuntimeError("dispatch title became empty after public-output filtering")
    return title


def _ensure_conversation(operation: dict[str, Any]) -> None:
    fm, _created = lib.ensure_conversation(
        title=str(operation["title"]),
        thread_id=str(operation["thread_id"]),
        channel_id=str(operation["channel_id"]),
        session_id=str(operation["session_id"]),
    )
    exact = (
        str(fm.get("claude_session_id") or "") == str(operation["session_id"])
        and str(fm.get("discord_thread_id") or "") == str(operation["thread_id"])
        and str(fm.get("discord_channel_id") or "") == str(operation["channel_id"])
        and str(fm.get("title") or "") == str(operation["title"])
    )
    if not exact:
        raise RuntimeError("conversation file conflicts with frozen dispatch binding")


def _result(operation: dict[str, Any], *, is_new: bool) -> dict[str, Any]:
    return {
        "mode": operation["mode"],
        "session_id": operation["session_id"],
        "thread_id": operation["thread_id"],
        "channel_id": operation["channel_id"],
        "title": operation["title"],
        "convo_path": str(
            lib.conversation_path(str(operation["session_id"]), status="active")
        ),
        "is_new": is_new,
    }


def dispatch_claimed(message_id: str, supplied_title: str | None) -> dict[str, Any]:
    queue = mq.connect()
    try:
        row = mq.get(queue, message_id)
        if row is None:
            raise RuntimeError("dispatch requires an existing queue row")
        if row["state"] != "claimed":
            raise RuntimeError("dispatch requires a currently claimed queue row")
        mode = (
            "top-level"
            if str(row["chat_id"]) == CONFIG.discord.chat_channel_id
            else "reply"
        )
        if mode == "top-level":
            frozen_title = mq.freeze_title(queue, message_id, supplied_title)
            title = _safe_title(frozen_title)
            source_thread_id = None
            channel_id = str(row["chat_id"])
            session_id = None
        else:
            if supplied_title is not None:
                raise RuntimeError("reply dispatch cannot accept a title")
            source_thread_id = str(row["chat_id"])
            session_id = lib.thread_to_session(source_thread_id)
            if not session_id:
                raise RuntimeError("reply thread is not owned by Threadkeep")
            fm, _body, _path = lib.load_conversation(session_id)
            if str(fm.get("discord_thread_id") or "") != source_thread_id:
                raise RuntimeError("conversation registry and transcript thread binding disagree")
            channel_id = str(fm.get("discord_channel_id") or "")
            if not channel_id:
                raise RuntimeError("conversation has no frozen parent channel")
            title = str(fm.get("title") or "").strip()
            if not title:
                raise RuntimeError("conversation has no title")
        body = str(row["body"])
        body_sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
        request_sha = idempotency.request_digest(
            {
                "message_id": str(row["message_id"]),
                "chat_id": str(row["chat_id"]),
                "body": body,
                "user": row["user"],
                "ts": row["ts"],
                "kind": row["kind"],
                "mode": mode,
                "title": title if mode == "top-level" else None,
            }
        )
    finally:
        queue.close()

    with idempotency.operation_lock():
        operation = idempotency.prepare(
            message_id=message_id,
            mode=mode,
            request_sha256=request_sha,
            body_sha256=body_sha,
            channel_id=channel_id,
            source_thread_id=source_thread_id,
            title=title,
            session_id=session_id,
        )
        try:
            if operation["state"] == "completed":
                return idempotency.result(operation)

            if mode == "top-level":
                if operation["state"] == "prepared":
                    operation = idempotency.mark_thread_attempted(message_id)
                    helper_operation = "create"
                elif operation["state"] == "thread_create_attempted":
                    helper_operation = "reconcile"
                elif operation["state"] == "thread_absence_confirmed":
                    helper_operation = "recover"
                else:
                    helper_operation = ""
                if helper_operation:
                    thread = _run_json_helper(
                        CREATE_THREAD,
                        {
                            "operation": helper_operation,
                            "channel_id": channel_id,
                            "message_id": message_id,
                            "name": operation["title"],
                            "auto_archive": 1440,
                        },
                    )
                    if thread == {
                        "outcome": "absent",
                        "channel_id": channel_id,
                        "thread_id": message_id,
                    }:
                        if helper_operation != "reconcile":
                            raise RuntimeError(
                                "Discord helper returned absence outside reconciliation"
                            )
                        operation = idempotency.mark_thread_absence_confirmed(
                            message_id
                        )
                        thread = _run_json_helper(
                            CREATE_THREAD,
                            {
                                "operation": "recover",
                                "channel_id": channel_id,
                                "message_id": message_id,
                                "name": operation["title"],
                                "auto_archive": 1440,
                            },
                        )
                    thread_id = str(thread.get("id") or "")
                    if thread_id != message_id:
                        raise RuntimeError(
                            "Discord starter-message thread ID did not equal its source message ID"
                        )
                    operation = idempotency.confirm_thread(message_id, thread_id)
                if operation["state"] == "thread_confirmed":
                    _ensure_conversation(operation)
                    operation = idempotency.mark_conversation_ready(message_id)
                elif operation["state"] in {"conversation_ready", "turn_appended"}:
                    _ensure_conversation(operation)

            if operation["state"] in {"prepared", "conversation_ready"}:
                lib.append_turn_once(
                    str(operation["session_id"]),
                    "user",
                    body,
                    completion_token=str(operation["turn_token"]),
                    text_sha256=body_sha,
                    marker_kind="input",
                )
                operation = idempotency.mark_turn_appended(message_id)

            if operation["state"] == "turn_appended":
                result = _result(operation, is_new=mode == "top-level")
                operation = idempotency.complete(message_id, result)
            return idempotency.result(operation)
        except Exception as exc:
            idempotency.record_error(message_id, f"{type(exc).__name__}: {exc}")
            raise


def main() -> int:
    payload = _read_stdin()
    result = dispatch_claimed(payload["message_id"], payload["title"])
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"dispatch failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
