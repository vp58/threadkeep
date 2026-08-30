#!/usr/bin/env python3
"""Drainer support for the cx-chat orchestrator.

The LLM listener is demoted to a pure queue DRAINER. Per claimed row its only
reasoning job is: generate a 4-7 word title for a NEW top-level (classification
is a deterministic registry lookup, not reasoning). Everything else, claim,
dispatch, ordering, replay, is deterministic code here.

This module provides the deterministic half so the listener prompt shrinks to
"call drain_one, if it hands you a row needing a title, supply one, call
dispatch_claimed". It does NOT spawn the worker subagent itself (that is the
listener's Agent-tool call, which only the listener context can make).

drain flow per row:
    claim_next()                 -> atomic, per-thread-ordered
    classify_row()               -> 'reply' if thread owned, else 'top-level'
    (listener supplies title if top-level and none stored)
    dispatch.py (idempotent)     -> binds thread + session, appends transcript
    mark_dispatched()
    (listener spawns worker, then mark_spawned / mark_done)

The listen-channel id is read from THREADKEEP_LISTEN_CHANNEL_ID (a top-level post
there becomes a new thread; anything else is a reply into an owned thread or is
unowned). The default posting username is read from THREADKEEP_DEFAULT_USER
(falls back to "owner").
"""
from __future__ import annotations

import json
import hashlib
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import mq  # noqa: E402
sys.path.insert(0, str(_HERE.parent))
import safe_files  # noqa: E402
from config import CONFIG  # noqa: E402
from discord_destination import validate_destination, validate_principal  # noqa: E402
from discord_http import DiscordHTTPError, json_request, request as discord_request  # noqa: E402
from discord_secret import load_discord_token  # noqa: E402
import lib  # noqa: E402
from public_output import public_safe_output  # noqa: E402

SCRIPTS = _HERE.parent
DISPATCH = SCRIPTS / "dispatch.py"
CONVO_CLI = SCRIPTS / "cli.py"

LISTEN_CHANNEL = CONFIG.discord.chat_channel_id
NONCE_RETRY_WINDOW_SECONDS = 60
DELIVERY_HISTORY_MAX_PAGES = 50


def classify_row(row: Any) -> str:
    """Deterministic classification: top-level vs reply. A registry lookup, not
    reasoning. If the chat_id is the listen channel itself, it is a top-level
    post; otherwise if the thread is owned (registered) it is a reply."""
    chat_id = str(row["chat_id"])
    if LISTEN_CHANNEL and chat_id == LISTEN_CHANNEL:
        return "top-level"
    # Owned thread?
    res = subprocess.run(
        [sys.executable, str(CONVO_CLI), "thread-lookup", chat_id],
        capture_output=True, text=True, check=False, timeout=20,
    )
    if res.returncode == 0 and res.stdout.strip():
        return "reply"
    # Unknown thread: not ours. Caller should skip / dead-letter.
    return "unowned"


def dispatch_claimed(
    conn: Any,
    row: Any,
    *,
    title: Optional[str] = None,
) -> dict[str, Any]:
    """Run the (idempotent) dispatch.py for a claimed row and mark it dispatched.

    For a top-level row a title is required (use the stored one, else the passed
    one). Returns the parsed dispatch JSON. On dispatch failure, re-arms the row
    (release_claim) and raises so the caller can retry/alert.
    """
    kind = classify_row(row)
    if kind == "unowned":
        mq.mark_errored(conn, row["message_id"], "unowned thread, not dispatched")
        raise RuntimeError(f"unowned thread {row['chat_id']}")

    if kind == "top-level":
        the_title = row["title"] or title
        if not the_title:
            raise ValueError("top-level row needs a title before dispatch")
        payload = {"message_id": str(row["message_id"]), "title": the_title}
    else:  # reply
        payload = {"message_id": str(row["message_id"])}

    res = subprocess.run(
        [sys.executable, str(DISPATCH)],
        input=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if res.returncode != 0:
        mq.release_claim(conn, row["message_id"])
        raise RuntimeError(f"dispatch.py failed rc={res.returncode}: {res.stderr.strip()}")

    data = json.loads(res.stdout.strip().splitlines()[-1])
    mq.mark_dispatched(
        conn, row["message_id"],
        session_id=data["session_id"], thread_id=data["thread_id"],
    )
    return data


def drain_one(conn: Any) -> Optional[dict[str, Any]]:
    """Claim and return the next ready row for the listener to title+spawn.

    Returns a dict with the row fields and its classification, or None if the
    queue has nothing claimable. The listener then supplies a title (if
    top-level and needed) and calls dispatch_claimed + spawns the worker.
    """
    row = mq.claim_next(conn)
    if row is None:
        return None
    kind = classify_row(row)
    return {
        "message_id": row["message_id"],
        "chat_id": row["chat_id"],
        "user": row["user"],
        "body": row["body"],
        "kind": kind,
        "stored_title": row["title"],
        "needs_title": kind == "top-level" and not row["title"],
    }


def mark_spawned(conn: Any, message_id: str) -> None:
    """Durably authorize one worker before crossing the Agent launch boundary."""
    mq.mark_spawned(conn, message_id)


def mark_done(conn: Any, message_id: str) -> None:
    """Record that the worker finished this row (terminal)."""
    mq.mark_done(conn, message_id)


def mark_errored(conn: Any, message_id: str, error: str) -> None:
    """Dead-letter this row with an error (terminal)."""
    mq.mark_errored(conn, message_id, error)


class DeliveryAmbiguousError(RuntimeError):
    """An old or contradictory Discord POST can no longer be retried safely."""


def _exact_discord_message(
    message: Any,
    *,
    thread_id: str,
    content: str,
    nonce: str,
) -> str:
    if not isinstance(message, dict):
        raise DeliveryAmbiguousError("Discord response message is malformed")
    message_id = str(message.get("id") or "")
    author = message.get("author")
    if (
        not re.fullmatch(r"[1-9][0-9]{16,19}", message_id)
        or str(message.get("channel_id") or "") != thread_id
        or str(message.get("nonce") or "") != nonce
        or message.get("content") != content
        or not isinstance(author, dict)
        or str(author.get("id") or "") != CONFIG.discord.bot_user_id
    ):
        raise DeliveryAmbiguousError(
            "Discord response does not match its exact channel, author, nonce, and content"
        )
    return message_id


def _history_page(token: str, path: str) -> list[dict[str, Any]]:
    _status, raw = discord_request("GET", path, token, timeout=30, max_attempts=4)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeliveryAmbiguousError(
            "Discord history reconciliation returned invalid JSON"
        ) from exc
    if not isinstance(value, list) or len(value) > 100:
        raise DeliveryAmbiguousError(
            "Discord history reconciliation returned a malformed page"
        )
    if not all(isinstance(item, dict) for item in value):
        raise DeliveryAmbiguousError(
            "Discord history reconciliation returned a malformed message"
        )
    return value


def _find_response_in_history(
    token: str,
    *,
    thread_id: str,
    content: str,
    nonce: str,
) -> str | None:
    before: str | None = None
    seen: set[str] = set()
    match: str | None = None
    for _page in range(DELIVERY_HISTORY_MAX_PAGES):
        suffix = f"&before={before}" if before else ""
        rows = _history_page(
            token, f"/channels/{thread_id}/messages?limit=100{suffix}"
        )
        if not rows:
            return match
        page_ids: list[str] = []
        for row in rows:
            row_id = str(row.get("id") or "")
            if not re.fullmatch(r"[1-9][0-9]{16,19}", row_id) or row_id in seen:
                raise DeliveryAmbiguousError(
                    "Discord history reconciliation returned invalid pagination"
                )
            seen.add(row_id)
            page_ids.append(row_id)
            if str(row.get("nonce") or "") != nonce:
                continue
            author = row.get("author")
            if not isinstance(author, dict) or str(author.get("id") or "") != CONFIG.discord.bot_user_id:
                continue
            candidate = _exact_discord_message(
                row, thread_id=thread_id, content=content, nonce=nonce
            )
            if match is not None:
                raise DeliveryAmbiguousError(
                    "Discord contains duplicate bot responses for one delivery nonce"
                )
            match = candidate
        oldest = str(min(int(value) for value in page_ids))
        if before is not None and int(oldest) >= int(before):
            raise DeliveryAmbiguousError(
                "Discord history reconciliation did not move backwards"
            )
        if len(rows) < 100:
            return match
        before = oldest
    raise DeliveryAmbiguousError(
        "Discord history reconciliation exceeded its bounded page limit"
    )


def _deliver_prepared_response(
    conn: Any,
    *,
    message_id: str,
    thread_id: str,
    content: str,
    response_sha256: str,
    nonce: str,
    token: str,
) -> str:
    row = mq.get(conn, message_id)
    if row is None:
        raise RuntimeError("worker completion row disappeared")
    if row["response_ambiguous_at"] is not None:
        raise DeliveryAmbiguousError(
            "Discord response delivery is quarantined for operator review"
        )
    confirmed = str(row["response_message_id"] or "")
    if confirmed:
        return confirmed

    first_attempt, attempted_at = mq.begin_response_attempt(conn, message_id)
    age = time.time() - attempted_at
    if not first_attempt and (age < 0 or age > NONCE_RETRY_WINDOW_SECONDS):
        try:
            found = _find_response_in_history(
                token, thread_id=thread_id, content=content, nonce=nonce
            )
        except DeliveryAmbiguousError:
            mq.mark_response_ambiguous(conn, message_id)
            raise
        if found is None:
            mq.mark_response_ambiguous(conn, message_id)
            raise DeliveryAmbiguousError(
                "aged Discord POST had no provable history match; delivery quarantined"
            )
        mq.confirm_response_delivery(
            conn,
            message_id,
            response_sha256=response_sha256,
            response_nonce=nonce,
            response_message_id=found,
        )
        return found

    try:
        sent = json_request(
            "POST",
            f"/channels/{thread_id}/messages",
            token,
            {
                "content": content,
                "allowed_mentions": {"parse": []},
                "nonce": nonce,
                "enforce_nonce": True,
            },
            timeout=45,
            max_attempts=1,
        )
    except DiscordHTTPError as exc:
        if first_attempt and 400 <= exc.status < 500:
            mq.clear_response_attempt(conn, message_id, attempted_at)
        raise
    try:
        sent_id = _exact_discord_message(
            sent, thread_id=thread_id, content=content, nonce=nonce
        )
    except DeliveryAmbiguousError:
        mq.mark_response_ambiguous(conn, message_id)
        raise
    readback = json_request(
        "GET",
        f"/channels/{thread_id}/messages/{sent_id}",
        token,
        timeout=30,
        max_attempts=4,
    )
    try:
        _exact_discord_message(
            readback, thread_id=thread_id, content=content, nonce=nonce
        )
    except DeliveryAmbiguousError:
        mq.mark_response_ambiguous(conn, message_id)
        raise
    mq.confirm_response_delivery(
        conn,
        message_id,
        response_sha256=response_sha256,
        response_nonce=nonce,
        response_message_id=sent_id,
    )
    return sent_id


def _complete_response(
    conn: Any,
    *,
    message_id: str,
    session_id: str,
    thread_id: str,
    response: str | None,
    response_exchange_id: str | None,
) -> dict[str, Any]:
    row = mq.get(conn, message_id)
    if row is None:
        raise RuntimeError("worker completion row does not exist")
    if row["session_id"] != session_id or row["thread_id"] != thread_id:
        raise RuntimeError("worker completion IDs do not match the queue row")
    if row["state"] == "done":
        existing = str(row["response_message_id"] or "")
        if not re.fullmatch(r"[1-9][0-9]{16,19}", existing):
            raise RuntimeError("completed worker row has no valid Discord message ID")
        if response_exchange_id:
            safe_files.delete("response", response_exchange_id)
        return {"ok": True, "message_id": existing, "replayed": True}

    source = response if response is not None else row["response_content"]
    if not isinstance(source, str):
        raise RuntimeError("prepared worker response content is unavailable")
    safe_response = public_safe_output(source, agent_name="Claude")
    if not safe_response or len(safe_response) > 1900:
        raise RuntimeError("worker response is outside the Discord size limit")
    response_sha256 = hashlib.sha256(safe_response.encode("utf-8")).hexdigest()
    prepared = mq.prepare_response_completion(
        conn,
        message_id,
        session_id=session_id,
        thread_id=thread_id,
        response_sha256=response_sha256,
        response_content=safe_response,
    )
    nonce = str(prepared["response_nonce"] or "")
    if not re.fullmatch(r"tk[a-f0-9]{23}", nonce):
        raise RuntimeError("prepared worker response has an invalid nonce")

    token = load_discord_token(allow_environment=False)
    validate_principal(token)
    validate_destination(token, thread_id)
    sent_id = _deliver_prepared_response(
        conn,
        message_id=message_id,
        thread_id=thread_id,
        content=safe_response,
        response_sha256=response_sha256,
        nonce=nonce,
        token=token,
    )
    lib.append_turn_once(
        session_id,
        "claude",
        safe_response,
        completion_token=str(prepared["completion_token"] or ""),
        text_sha256=response_sha256,
        marker_kind="response",
    )
    mq.finish_response_completion(
        conn,
        message_id,
        response_sha256=response_sha256,
        response_message_id=sent_id,
    )
    if response_exchange_id:
        safe_files.delete("response", response_exchange_id)
    return {"ok": True, "message_id": sent_id, "replayed": False}


def complete_response(
    conn: Any,
    *,
    message_id: str,
    session_id: str,
    thread_id: str,
    response_exchange_id: str,
) -> dict[str, Any]:
    response = safe_files.read("response", response_exchange_id, consume=False)
    return _complete_response(
        conn,
        message_id=message_id,
        session_id=session_id,
        thread_id=thread_id,
        response=response,
        response_exchange_id=response_exchange_id,
    )


def reconcile_response(conn: Any, *, message_id: str) -> dict[str, Any]:
    row = mq.get(conn, message_id)
    if row is None or not row["session_id"] or not row["thread_id"]:
        raise RuntimeError("response reconciliation row has no worker binding")
    return _complete_response(
        conn,
        message_id=message_id,
        session_id=str(row["session_id"]),
        thread_id=str(row["thread_id"]),
        response=None,
        response_exchange_id=None,
    )


def startup_replay(conn: Any) -> dict[str, Any]:
    """On drainer/listener startup: re-arm stale claims and report what is left
    to replay so a crash mid-burst loses nothing.

    Returns {"rearmed": [ids], "pending": [{message_id,state,chat_id}...]}.
    """
    rearmed = mq.recover_stale(conn)
    pend = mq.pending(conn)
    return {
        "rearmed": rearmed,
        "pending": [
            {"message_id": r["message_id"], "state": r["state"],
             "chat_id": r["chat_id"]}
            for r in pend
        ],
    }


# --- thin CLI so the listener / cron can drive it without importing Python ---

def _main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="drainer")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("drain-one")
    sub.add_parser("replay")
    sub.add_parser("metrics")
    dd = sub.add_parser("dispatch-claimed")
    dd.add_argument("--message-id", required=True)
    dd.add_argument("--title-exchange-id", default=None)
    spawned = sub.add_parser("mark-spawned")
    spawned.add_argument("--message-id", required=True)
    complete = sub.add_parser("complete-response")
    complete.add_argument("--message-id", required=True)
    complete.add_argument("--session-id", required=True)
    complete.add_argument("--thread-id", required=True)
    complete.add_argument("--response-exchange-id", required=True)
    reconcile = sub.add_parser("reconcile-response")
    reconcile.add_argument("--message-id", required=True)
    me = sub.add_parser("mark-errored")
    me.add_argument("--message-id", required=True)
    me.add_argument("--error", required=True)
    args = p.parse_args(argv)

    conn = mq.connect()
    try:
        if args.cmd == "drain-one":
            print(json.dumps(drain_one(conn)))
        elif args.cmd == "replay":
            print(json.dumps(startup_replay(conn)))
        elif args.cmd == "metrics":
            print(json.dumps(mq.metrics(conn)))
        elif args.cmd == "dispatch-claimed":
            row = mq.get(conn, args.message_id)
            if row is None:
                print(json.dumps({"error": "no such message"}), file=sys.stderr)
                return 2
            title = None
            if args.title_exchange_id:
                title = safe_files.read(
                    "title", args.title_exchange_id, consume=True
                ).strip()
                if not title or len(title) > 100 or "\n" in title:
                    print(json.dumps({"error": "invalid title"}), file=sys.stderr)
                    return 2
            print(json.dumps(dispatch_claimed(conn, row, title=title)))
        elif args.cmd == "mark-spawned":
            mq.mark_spawned(conn, args.message_id)
            print(json.dumps({"ok": True}))
        elif args.cmd == "complete-response":
            print(json.dumps(complete_response(
                conn,
                message_id=args.message_id,
                session_id=args.session_id,
                thread_id=args.thread_id,
                response_exchange_id=args.response_exchange_id,
            )))
        elif args.cmd == "reconcile-response":
            print(json.dumps(reconcile_response(conn, message_id=args.message_id)))
        elif args.cmd == "mark-errored":
            mq.mark_errored(conn, args.message_id, args.error)
            print(json.dumps({"ok": True}))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
