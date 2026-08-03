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
    2. THREADKEEP_MQ_DB env var
    3. <THREADKEEP_CONVERSATIONS_DIR>/state/mq.sqlite3 when that env is set
    4. <repo>/conversations/state/mq.sqlite3 (default)
"""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
_CONVERSATIONS = _HERE.parent

# A row in a transient (claimed) state for longer than this many seconds is
# assumed to belong to a crashed worker and is re-armed on recover_stale().
STALE_CLAIM_SECONDS = 300

TERMINAL_STATES = ("done", "errored")
NONTERMINAL_STATES = ("received", "claimed", "dispatched", "spawned")


def _db_path(db_path: Optional[str | Path] = None) -> Path:
    if db_path is not None:
        return Path(db_path)
    env = os.environ.get("THREADKEEP_MQ_DB")
    if env:
        return Path(env).expanduser()
    conv = os.environ.get("THREADKEEP_CONVERSATIONS_DIR")
    base = Path(conv).expanduser() if conv else _CONVERSATIONS
    return base / "state" / "mq.sqlite3"


def connect(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    """Open (and lazily initialize) the queue DB with WAL + sane busy timeout."""
    p = _db_path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA foreign_keys=ON;")
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
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO messages
            (message_id, chat_id, user, ts, body, kind, title,
             state, received_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'received', ?, ?)
        """,
        (message_id, chat_id, user, ts, body, kind, title, now, now),
    )
    return cur.rowcount == 1


def mark_acked(conn: sqlite3.Connection, message_id: str) -> None:
    """Record that the eye reaction was confirmed on this message."""
    now = time.time()
    conn.execute(
        "UPDATE messages SET acked_at=COALESCE(acked_at, ?), updated_at=? "
        "WHERE message_id=?",
        (now, now, message_id),
    )


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
    conn.execute(
        "UPDATE messages SET state='dispatched', session_id=?, thread_id=?, "
        "dispatched_at=?, updated_at=? WHERE message_id=?",
        (session_id, thread_id, now, now, message_id),
    )


def mark_spawned(conn: sqlite3.Connection, message_id: str) -> None:
    now = time.time()
    conn.execute(
        "UPDATE messages SET state='spawned', updated_at=? WHERE message_id=?",
        (now, message_id),
    )


def mark_done(conn: sqlite3.Connection, message_id: str) -> None:
    now = time.time()
    conn.execute(
        "UPDATE messages SET state='done', updated_at=? WHERE message_id=?",
        (now, message_id),
    )


def mark_errored(conn: sqlite3.Connection, message_id: str, error: str) -> None:
    now = time.time()
    # Reset dead_letter_acked_at so a row that (re-)enters errored pages once
    # more, even if a prior errored alert for the same id was already acked.
    conn.execute(
        "UPDATE messages SET state='errored', error=?, "
        "dead_letter_acked_at=NULL, updated_at=? "
        "WHERE message_id=?",
        (error[:2000], now, message_id),
    )


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
