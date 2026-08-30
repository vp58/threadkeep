#!/usr/bin/env python3
"""Durable, idempotent message queue for the cx-chat orchestrator.

SQLite with WAL. One row per inbound Discord message, keyed on the Discord
message_id (UNIQUE). This is the single source of truth for "the system has seen
this message". It gives us, for free:

  - ack-once       : INSERT OR IGNORE on a UNIQUE message_id
  - dispatch-once  : an atomic claim-by-UPDATE (received -> claimed)
  - per-thread order: claims always hand back the oldest unclaimed row of a
                      chat_id, and a chat_id never has two rows in flight at once
  - crash replay   : non-terminal rows survive restart; recover_stale re-arms
                      anything stuck in a transient state past a timeout
  - observability  : oldest_unacked_age / oldest_undispatched_age / queue_depth

State machine (the `state` column):

    received   -> row inserted by intake (eye reaction already added)
    claimed    -> a drainer has taken ownership to dispatch it
    dispatched -> dispatch.py ran (thread bound, transcript appended)
    spawned    -> a worker subagent was launched
    done       -> worker finished
    errored    -> terminal failure (see error column); dead-lettered

Nothing here calls an LLM or shells out to Discord. It is pure deterministic
state. Intake (eye reaction) and dispatch (thread creation) are layered on top
in intake.py and dispatch.py respectively.

This module is ADDITIVE. The legacy dispatch.py/cli.py path keeps working with
or without this DB present.

State DB resolution order:
    1. explicit db_path argument
    2. DISCOPARTY_MQ_DB env var
    3. <DISCOPARTY_CONVERSATIONS_DIR>/state/mq.sqlite3 when that env is set
    4. <repo>/conversations/state/mq.sqlite3 (default)
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import sqlite3
import stat
import sys
import time
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
_CONVERSATIONS = _HERE.parent
sys.path.insert(0, str(_CONVERSATIONS))
from config import CONFIG  # noqa: E402

# A row in a transient (claimed) state for longer than this many seconds is
# assumed to belong to a crashed worker and is re-armed on recover_stale().
STALE_CLAIM_SECONDS = 300

TERMINAL_STATES = ("done", "errored")
NONTERMINAL_STATES = ("received", "claimed", "dispatched", "spawned")


def _db_path(db_path: Optional[str | Path] = None) -> Path:
    if db_path is not None:
        return Path(db_path)
    env = os.environ.get("DISCOPARTY_MQ_DB")
    if env:
        return Path(env).expanduser()
    base = CONFIG.paths.conversations_dir
    return base / "state" / "mq.sqlite3"


def connect(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    """Open the private queue DB and fail closed on unsafe state or corruption."""
    p = _db_path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = p.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
    ):
        raise RuntimeError("queue state directory must be real and current-user-owned")
    os.chmod(p.parent, 0o700, follow_symlinks=False)
    if p.is_symlink():
        raise RuntimeError("queue DB must not be a symlink")
    if not p.exists():
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(p, flags, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
    before = p.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
    ):
        raise RuntimeError("queue DB must be a private regular file")
    conn = sqlite3.connect(str(p), timeout=30, isolation_level=None)
    after = p.lstat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        conn.close()
        raise RuntimeError("queue DB changed while opening")
    os.chmod(p, 0o600, follow_symlinks=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=FULL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    check = conn.execute("PRAGMA quick_check;").fetchone()
    if check is None or check[0] != "ok":
        conn.close()
        raise RuntimeError("queue DB failed integrity check")
    _init(conn)
    return conn


def _init(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS messages (
            message_id   TEXT PRIMARY KEY,
            chat_id      TEXT NOT NULL,
            user         TEXT,
            ts           TEXT,
            body         TEXT NOT NULL,
            kind         TEXT,              -- 'top-level' | 'reply' (best-effort hint)
            title        TEXT,              -- LLM-provided title (top-level only)
            state        TEXT NOT NULL DEFAULT 'received',
            session_id   TEXT,              -- bound once dispatched
            thread_id    TEXT,              -- bound once dispatched
            error        TEXT,
            attempts     INTEGER NOT NULL DEFAULT 0,
            received_at  REAL NOT NULL,     -- epoch seconds, when intake saw it
            acked_at     REAL,             -- when eye reaction confirmed
            claimed_at   REAL,
            dispatched_at REAL,
            updated_at   REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_state ON messages(state);
        CREATE INDEX IF NOT EXISTS idx_chat ON messages(chat_id);
        CREATE INDEX IF NOT EXISTS idx_received ON messages(received_at);
        """
    )
    _migrate(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Idempotent, additive column migrations for an existing DB.

    Safe on rows that predate a column: ALTER TABLE ADD COLUMN backfills NULL,
    so an old errored row simply reads dead_letter_acked_at IS NULL (treated as
    not-yet-acked, so it pages once then is auto-acked by the monitor).
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(messages)")}
    # dead_letter_acked_at: set once the monitor has emitted the dead-letter
    # WARN for an errored row, so a handled-but-errored row cannot page forever.
    if "dead_letter_acked_at" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN dead_letter_acked_at REAL")
    if "completion_token" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN completion_token TEXT")
    if "response_sha256" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN response_sha256 TEXT")
    if "response_message_id" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN response_message_id TEXT")
    if "response_content" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN response_content TEXT")
    if "response_nonce" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN response_nonce TEXT")
    if "response_attempted_at" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN response_attempted_at REAL")
    if "response_ambiguous_at" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN response_ambiguous_at REAL")
    if "response_confirmed_at" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN response_confirmed_at REAL")


# ---------------------------------------------------------------------------
# Intake: record a message exactly once.
# ---------------------------------------------------------------------------

def enqueue(
    conn: sqlite3.Connection,
    *,
    message_id: str,
    chat_id: str,
    body: str,
    user: Optional[str] = None,
    ts: Optional[str] = None,
    kind: Optional[str] = None,
    title: Optional[str] = None,
) -> bool:
    """Durably record an inbound message. Idempotent on message_id.

    Returns True if a NEW row was inserted, False if this message_id was already
    present (a duplicate / retry). Either way the message is durably recorded
    exactly once. ack-once invariant lives here.
    """
    now = time.time()
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO messages
                (message_id, chat_id, user, ts, body, kind, title,
                 state, received_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'received', ?, ?)
            """,
            (message_id, chat_id, user, ts, body, kind, title, now, now),
        )
        if cur.rowcount == 0:
            existing = conn.execute(
                "SELECT chat_id,user,ts,body,kind,title FROM messages WHERE message_id=?",
                (message_id,),
            ).fetchone()
            immutable_matches = (
                existing is not None
                and tuple(existing[:5]) == (chat_id, user, ts, body, kind)
                and (title is None or existing["title"] == title)
            )
            if not immutable_matches:
                raise RuntimeError("duplicate message ID changed immutable intake data")
        conn.execute("COMMIT")
        return cur.rowcount == 1
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise


def freeze_title(
    conn: sqlite3.Connection, message_id: str, supplied_title: str | None
) -> str:
    """Bind the first valid generated title to one claimed top-level row."""

    if supplied_title is not None and (
        not supplied_title.strip()
        or len(supplied_title) > 100
        or "\n" in supplied_title
        or "\r" in supplied_title
    ):
        raise ValueError("invalid generated title")
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT state,title FROM messages WHERE message_id=?", (message_id,)
        ).fetchone()
        if row is None:
            raise RuntimeError("queue row disappeared while freezing title")
        if row["state"] != "claimed":
            raise RuntimeError("title can only be frozen for a claimed row")
        frozen = row["title"]
        if frozen is None:
            if supplied_title is None:
                raise RuntimeError("top-level dispatch requires a title")
            frozen = supplied_title.strip()
            cursor = conn.execute(
                "UPDATE messages SET title=?,updated_at=? "
                "WHERE message_id=? AND state='claimed' AND title IS NULL",
                (frozen, time.time(), message_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("queue title freeze lost its claimed row")
        elif supplied_title is not None and frozen != supplied_title.strip():
            raise RuntimeError("generated title changed after it was frozen")
        conn.execute("COMMIT")
        return str(frozen)
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise


def mark_acked(conn: sqlite3.Connection, message_id: str) -> None:
    """Record that the eye reaction was confirmed on this message."""
    now = time.time()
    cursor = conn.execute(
        "UPDATE messages SET acked_at=COALESCE(acked_at, ?), updated_at=? "
        "WHERE message_id=?",
        (now, now, message_id),
    )
    if cursor.rowcount != 1:
        raise RuntimeError("queue row disappeared before acknowledgment")


# ---------------------------------------------------------------------------
# Drainer: claim, dispatch, finish. All transitions atomic.
# ---------------------------------------------------------------------------

def claim_next(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    """Atomically claim the oldest dispatch-ready message, preserving per-thread
    order and per-thread mutual exclusion.

    Per-thread ordering guarantee: a chat_id is only eligible if it has NO row
    currently in flight (claimed/dispatched/spawned). So at most one message per
    thread is being worked at a time, and it is always the oldest received one.

    Returns the claimed Row, or None if nothing is claimable right now.
    """
    now = time.time()
    # BEGIN IMMEDIATE takes a write lock up front so two concurrent drainers
    # cannot both claim the same row.
    conn.execute("BEGIN IMMEDIATE;")
    try:
        row = conn.execute(
            """
            SELECT * FROM messages m
            WHERE m.state = 'received'
              AND NOT EXISTS (
                  SELECT 1 FROM messages b
                  WHERE b.chat_id = m.chat_id
                    AND b.state IN ('claimed', 'dispatched', 'spawned')
              )
            ORDER BY m.received_at ASC, m.rowid ASC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            conn.execute("COMMIT;")
            return None
        conn.execute(
            "UPDATE messages SET state='claimed', claimed_at=?, "
            "attempts=attempts+1, updated_at=? WHERE message_id=?",
            (now, now, row["message_id"]),
        )
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        raise
    return conn.execute(
        "SELECT * FROM messages WHERE message_id=?", (row["message_id"],)
    ).fetchone()


def mark_dispatched(
    conn: sqlite3.Connection,
    message_id: str,
    *,
    session_id: str,
    thread_id: str,
) -> None:
    now = time.time()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT state,session_id,thread_id FROM messages WHERE message_id=?",
            (message_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("queue row disappeared before dispatch binding")
        if row["state"] == "dispatched":
            if row["session_id"] != session_id or row["thread_id"] != thread_id:
                raise RuntimeError("dispatch replay changed immutable queue binding")
            conn.execute("COMMIT")
            return
        if row["state"] != "claimed":
            raise RuntimeError("queue row is not claimed for dispatch")
        cursor = conn.execute(
            "UPDATE messages SET state='dispatched', session_id=?, thread_id=?, "
            "dispatched_at=?, updated_at=? WHERE message_id=? AND state='claimed'",
            (session_id, thread_id, now, now, message_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("dispatch binding lost its claimed queue row")
        conn.execute("COMMIT")
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise


def mark_spawned(conn: sqlite3.Connection, message_id: str) -> None:
    now = time.time()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT state,completion_token FROM messages WHERE message_id=?",
            (message_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("queue row disappeared before spawn authorization")
        if row["state"] == "spawned" and row["completion_token"]:
            conn.execute("COMMIT")
            return
        if row["state"] != "dispatched":
            raise RuntimeError("worker can only be authorized from dispatched state")
        completion_token = row["completion_token"] or secrets.token_hex(16)
        cursor = conn.execute(
            "UPDATE messages SET state='spawned',completion_token=?,updated_at=? "
            "WHERE message_id=? AND state='dispatched'",
            (completion_token, now, message_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("spawn authorization lost its dispatched row")
        conn.execute("COMMIT")
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise


def mark_done(conn: sqlite3.Connection, message_id: str) -> None:
    raise RuntimeError("direct mark_done is disabled; use complete-response")


def prepare_response_completion(
    conn: sqlite3.Connection,
    message_id: str,
    *,
    session_id: str,
    thread_id: str,
    response_sha256: str,
    response_content: str,
) -> sqlite3.Row:
    """Freeze one complete immutable delivery manifest before Discord POST."""

    if len(response_sha256) != 64 or any(c not in "0123456789abcdef" for c in response_sha256):
        raise ValueError("response_sha256 must be lowercase hexadecimal")
    if not response_content or len(response_content) > 1900:
        raise ValueError("response_content is outside the Discord size limit")
    if secrets.compare_digest(
        hashlib.sha256(response_content.encode("utf-8")).hexdigest(),
        response_sha256,
    ) is False:
        raise RuntimeError("response content does not match its digest")
    conn.execute("BEGIN IMMEDIATE;")
    try:
        row = conn.execute(
            "SELECT * FROM messages WHERE message_id=?", (message_id,)
        ).fetchone()
        if row is None:
            raise RuntimeError("worker completion row does not exist")
        if row["session_id"] != session_id or row["thread_id"] != thread_id:
            raise RuntimeError("worker completion does not match its queue binding")
        if row["state"] not in {"spawned", "done"}:
            raise RuntimeError("worker completion row is not spawned")
        token = row["completion_token"] or secrets.token_hex(16)
        nonce = "tk" + hashlib.sha256(
            f"{message_id}:{token}".encode("utf-8")
        ).hexdigest()[:23]
        frozen_sha = row["response_sha256"]
        if frozen_sha is not None and frozen_sha != response_sha256:
            raise RuntimeError("worker completion response changed after preparation")
        frozen_content = row["response_content"]
        if frozen_content is not None and frozen_content != response_content:
            raise RuntimeError("worker completion content changed after preparation")
        frozen_nonce = row["response_nonce"]
        if frozen_nonce is not None and frozen_nonce != nonce:
            raise RuntimeError("worker completion nonce changed after preparation")
        conn.execute(
            "UPDATE messages SET completion_token=?,response_sha256=?,"
            "response_content=?,response_nonce=?,updated_at=? "
            "WHERE message_id=?",
            (token, response_sha256, response_content, nonce, time.time(), message_id),
        )
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        raise
    result = conn.execute(
        "SELECT * FROM messages WHERE message_id=?", (message_id,)
    ).fetchone()
    if result is None:
        raise RuntimeError("worker completion row disappeared")
    return result


def begin_response_attempt(
    conn: sqlite3.Connection, message_id: str
) -> tuple[bool, float]:
    """Durably cross the local side of the one unknown-commit POST boundary."""

    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT state,response_nonce,response_attempted_at,response_ambiguous_at,"
            "response_message_id FROM messages WHERE message_id=?",
            (message_id,),
        ).fetchone()
        if row is None or row["state"] != "spawned" or not row["response_nonce"]:
            raise RuntimeError("response attempt lost its prepared spawned row")
        if row["response_message_id"] is not None:
            raise RuntimeError("confirmed response cannot be attempted again")
        if row["response_ambiguous_at"] is not None:
            raise RuntimeError("response delivery is quarantined as ambiguous")
        attempted_at = row["response_attempted_at"]
        if attempted_at is None:
            attempted_at = time.time()
            cursor = conn.execute(
                "UPDATE messages SET response_attempted_at=?,updated_at=? "
                "WHERE message_id=? AND state='spawned' AND response_attempted_at IS NULL",
                (attempted_at, attempted_at, message_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("response attempt lost its prepared row")
            conn.execute("COMMIT")
            return True, float(attempted_at)
        conn.execute("COMMIT")
        return False, float(attempted_at)
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise


def clear_response_attempt(
    conn: sqlite3.Connection, message_id: str, attempted_at: float
) -> None:
    """Reset only this call's first attempt after a definitive HTTP rejection."""

    cursor = conn.execute(
        "UPDATE messages SET response_attempted_at=NULL,updated_at=? "
        "WHERE message_id=? AND state='spawned' AND response_attempted_at=? "
        "AND response_message_id IS NULL AND response_ambiguous_at IS NULL",
        (time.time(), message_id, attempted_at),
    )
    if cursor.rowcount != 1:
        raise RuntimeError("response attempt reset lost its prepared row")


def mark_response_ambiguous(conn: sqlite3.Connection, message_id: str) -> None:
    now = time.time()
    cursor = conn.execute(
        "UPDATE messages SET response_ambiguous_at=?,updated_at=? "
        "WHERE message_id=? AND state='spawned' AND response_attempted_at IS NOT NULL "
        "AND response_message_id IS NULL AND response_ambiguous_at IS NULL",
        (now, now, message_id),
    )
    if cursor.rowcount != 1:
        row = get(conn, message_id)
        if row is not None and row["response_ambiguous_at"] is not None:
            return
        raise RuntimeError("response ambiguity quarantine lost its prepared row")


def confirm_response_delivery(
    conn: sqlite3.Connection,
    message_id: str,
    *,
    response_sha256: str,
    response_nonce: str,
    response_message_id: str,
) -> None:
    """Persist exact Discord readback confirmation without terminalizing yet."""

    now = time.time()
    cursor = conn.execute(
        "UPDATE messages SET response_message_id=?,response_confirmed_at=?,updated_at=? "
        "WHERE message_id=? AND state='spawned' AND response_sha256=? "
        "AND response_nonce=? AND response_attempted_at IS NOT NULL "
        "AND response_message_id IS NULL AND response_ambiguous_at IS NULL",
        (
            response_message_id,
            now,
            now,
            message_id,
            response_sha256,
            response_nonce,
        ),
    )
    if cursor.rowcount == 1:
        return
    row = get(conn, message_id)
    if (
        row is not None
        and row["state"] in {"spawned", "done"}
        and row["response_sha256"] == response_sha256
        and row["response_nonce"] == response_nonce
        and row["response_message_id"] == response_message_id
        and row["response_ambiguous_at"] is None
    ):
        return
    raise RuntimeError("response delivery confirmation lost its immutable binding")


def finish_response_completion(
    conn: sqlite3.Connection,
    message_id: str,
    *,
    response_sha256: str,
    response_message_id: str,
) -> None:
    """Terminalize only after Discord readback and transcript append succeed."""

    now = time.time()
    cursor = conn.execute(
        "UPDATE messages SET state='done', response_message_id=?, updated_at=? "
        "WHERE message_id=? AND state='spawned' AND response_sha256=? "
        "AND response_message_id=? AND response_confirmed_at IS NOT NULL "
        "AND response_ambiguous_at IS NULL",
        (response_message_id, now, message_id, response_sha256, response_message_id),
    )
    if cursor.rowcount == 1:
        return
    row = conn.execute(
        "SELECT state,response_sha256,response_message_id FROM messages WHERE message_id=?",
        (message_id,),
    ).fetchone()
    if (
        row is not None
        and row["state"] == "done"
        and row["response_sha256"] == response_sha256
        and row["response_message_id"] == response_message_id
    ):
        return
    raise RuntimeError("worker response completion lost its immutable binding")


def mark_errored(conn: sqlite3.Connection, message_id: str, error: str) -> None:
    now = time.time()
    row = get(conn, message_id)
    if row is None:
        raise RuntimeError("queue row disappeared before dead-letter transition")
    if (
        row["state"] == "spawned"
        and row["response_attempted_at"] is not None
        and row["response_message_id"] is None
    ):
        raise RuntimeError(
            "an unresolved Discord response attempt cannot be dead-lettered"
        )
    if row["state"] == "done":
        raise RuntimeError("a completed queue row cannot be dead-lettered")
    # Reset dead_letter_acked_at so a row that (re-)enters errored pages once
    # more, even if a prior errored alert for the same id was already acked.
    cursor = conn.execute(
        "UPDATE messages SET state='errored', error=?, "
        "dead_letter_acked_at=NULL, updated_at=? "
        "WHERE message_id=? AND state NOT IN ('done','errored')",
        (error[:2000], now, message_id),
    )
    if cursor.rowcount != 1:
        if row["state"] == "errored" and row["error"] == error[:2000]:
            return
        raise RuntimeError("dead-letter transition lost its queue row")


def errored_unacked(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Errored rows whose dead-letter WARN has not yet been emitted/acked.

    These are the only rows the monitor should page on. Once paged, the monitor
    calls ack_dead_letters so the same handled-but-errored row does not re-warn
    every interval forever (the dead-letter siren bug).
    """
    return conn.execute(
        "SELECT * FROM messages WHERE state='errored' AND dead_letter_acked_at IS NULL "
        "ORDER BY updated_at ASC, rowid ASC"
    ).fetchall()


def ack_dead_letters(conn: sqlite3.Connection, message_ids: list[str]) -> None:
    """Mark errored rows as dead-letter-acked so they stop paging.

    Only touches rows still in 'errored'; a row that has since moved on is left
    alone. A later mark_errored on the same id clears this again (re-pages once).
    """
    now = time.time()
    for mid in message_ids:
        conn.execute(
            "UPDATE messages SET dead_letter_acked_at=? "
            "WHERE message_id=? AND state='errored'",
            (now, mid),
        )


def release_claim(conn: sqlite3.Connection, message_id: str) -> None:
    """Return a claimed-but-not-dispatched row to 'received' so it can be retried.

    Used when a drainer claims a row but fails before dispatch.py succeeds.
    """
    now = time.time()
    conn.execute(
        "UPDATE messages SET state='received', claimed_at=NULL, updated_at=? "
        "WHERE message_id=? AND state='claimed'",
        (now, message_id),
    )


# ---------------------------------------------------------------------------
# Crash recovery: re-arm rows abandoned by a crashed drainer/worker.
# ---------------------------------------------------------------------------

def recover_stale(conn: sqlite3.Connection, stale_seconds: int = STALE_CLAIM_SECONDS) -> list[str]:
    """Re-arm rows stuck in 'claimed' past the timeout (crashed before dispatch).

    A 'claimed' row whose claim is older than stale_seconds is assumed orphaned
    and returned to 'received' for another drainer to pick up. dispatched/spawned
    rows are NOT auto-reset here (dispatch.py is idempotent, but a half-spawned
    worker is the listener's call to replay); pending() lists those.

    Returns the list of message_ids that were re-armed.
    """
    cutoff = time.time() - stale_seconds
    rows = conn.execute(
        "SELECT message_id FROM messages WHERE state='claimed' AND claimed_at < ?",
        (cutoff,),
    ).fetchall()
    ids = [r["message_id"] for r in rows]
    now = time.time()
    for mid in ids:
        conn.execute(
            "UPDATE messages SET state='received', claimed_at=NULL, updated_at=? "
            "WHERE message_id=?",
            (now, mid),
        )
    return ids


def pending(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """All non-terminal rows, oldest first. Used by the drainer on startup to
    replay anything left mid-flight by a crash."""
    placeholders = ",".join("?" for _ in NONTERMINAL_STATES)
    return conn.execute(
        f"SELECT * FROM messages WHERE state IN ({placeholders}) "
        "ORDER BY received_at ASC, rowid ASC",
        NONTERMINAL_STATES,
    ).fetchall()


def get(conn: sqlite3.Connection, message_id: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM messages WHERE message_id=?", (message_id,)
    ).fetchone()


# ---------------------------------------------------------------------------
# Observability: real measured backlog numbers.
# ---------------------------------------------------------------------------

def metrics(conn: sqlite3.Connection) -> dict[str, Any]:
    now = time.time()
    out: dict[str, Any] = {
        "queue_depth": 0,            # non-terminal rows
        "received_depth": 0,         # rows not yet claimed
        "inflight_depth": 0,         # claimed/dispatched/spawned
        "errored_count": 0,
        "errored_unacked_count": 0,  # errored rows not yet dead-letter-acked
        "oldest_unacked_age": 0.0,   # received but eye not confirmed
        "oldest_undispatched_age": 0.0,  # received AND claimable (no same-thread predecessor in flight)
        "oldest_inflight_age": 0.0,  # longest a row has been in flight (claimed/dispatched/spawned)
        "by_state": {},
    }
    for r in conn.execute("SELECT state, COUNT(*) c FROM messages GROUP BY state"):
        out["by_state"][r["state"]] = r["c"]
    out["queue_depth"] = sum(
        out["by_state"].get(s, 0) for s in NONTERMINAL_STATES
    )
    out["received_depth"] = out["by_state"].get("received", 0)
    out["inflight_depth"] = sum(
        out["by_state"].get(s, 0) for s in ("claimed", "dispatched", "spawned")
    )
    out["errored_count"] = out["by_state"].get("errored", 0)
    r = conn.execute(
        "SELECT COUNT(*) c FROM messages "
        "WHERE state='errored' AND dead_letter_acked_at IS NULL"
    ).fetchone()
    out["errored_unacked_count"] = r["c"] if r else 0

    r = conn.execute(
        "SELECT MIN(received_at) m FROM messages WHERE acked_at IS NULL "
        "AND state NOT IN ('done','errored')"
    ).fetchone()
    if r and r["m"] is not None:
        out["oldest_unacked_age"] = max(0.0, now - r["m"])

    # Oldest undispatched age counts a 'received' row ONLY if it is actually
    # claimable right now, i.e. its thread has nothing in flight ahead of it.
    # A message legitimately serialized behind an in-flight same-thread
    # predecessor (one-in-flight-per-thread) is NOT the drainer falling behind,
    # so it must not trip the WARN. This mirrors claim_next's eligibility.
    r = conn.execute(
        """
        SELECT MIN(received_at) AS mn FROM messages msg
        WHERE msg.state = 'received'
          AND NOT EXISTS (
              SELECT 1 FROM messages b
              WHERE b.chat_id = msg.chat_id
                AND b.state IN ('claimed', 'dispatched', 'spawned')
          )
        """
    ).fetchone()
    if r and r["mn"] is not None:
        out["oldest_undispatched_age"] = max(0.0, now - r["mn"])

    # Oldest in-flight age: longest any row has sat in a working state. A normal
    # long task shows here; only a much higher threshold (set in monitor.py)
    # flags a genuinely hung worker, so legitimate long renders don't false-page.
    r = conn.execute(
        "SELECT MIN(claimed_at) AS mn FROM messages "
        "WHERE state IN ('claimed','dispatched','spawned') AND claimed_at IS NOT NULL"
    ).fetchone()
    if r and r["mn"] is not None:
        out["oldest_inflight_age"] = max(0.0, now - r["mn"])

    return out
