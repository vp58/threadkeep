#!/usr/bin/env python3
"""Idempotency ledger for dispatch.py, keyed on Discord message_id.

A tiny, self-contained SQLite table that remembers the exact JSON dispatch.py
returned for a given message_id. If dispatch.py is run a second time for the
same message_id (a retry, a replayed burst, a crash-recovery re-drain), it
returns the SAME success JSON and does NOT re-create the thread or re-append the
transcript.

Design constraints:
  - Fully ADDITIVE. If anything here fails, dispatch.py must fall back to its
    original behavior. Never let idempotency bookkeeping break the live path.
  - A NEW message_id behaves exactly as before (record stores, returns).
  - A REPEAT message_id is a no-op that returns the identical stored JSON.

This is intentionally a separate, minimal table (not the full mq.messages
schema) so it can ship with zero new processes and zero dependency on the intake
daemon. It shares the same DB file so operators have one place to look.

DB resolution mirrors mq.py:
    1. explicit db_path argument
    2. THREADKEEP_MQ_DB env var
    3. <THREADKEEP_CONVERSATIONS_DIR>/state/mq.sqlite3 when that env is set
    4. <repo>/conversations/state/mq.sqlite3 (default)
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
_CONVERSATIONS = _HERE.parent


def _db_path(db_path: Optional[str | Path] = None) -> Path:
    if db_path is not None:
        return Path(db_path)
    env = os.environ.get("THREADKEEP_MQ_DB")
    if env:
        return Path(env).expanduser()
    conv = os.environ.get("THREADKEEP_CONVERSATIONS_DIR")
    base = Path(conv).expanduser() if conv else _CONVERSATIONS
    return base / "state" / "mq.sqlite3"


def _connect(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    p = _db_path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=30, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dispatch_ledger (
            message_id TEXT PRIMARY KEY,
            mode       TEXT,
            result_json TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        """
    )
    return conn


def lookup(message_id: str, db_path: Optional[str | Path] = None) -> Optional[dict[str, Any]]:
    """Return the stored dispatch JSON for this message_id, or None.

    Never raises: on any DB error returns None so dispatch.py proceeds normally.
    """
    if not message_id:
        return None
    try:
        conn = _connect(db_path)
        try:
            row = conn.execute(
                "SELECT result_json FROM dispatch_ledger WHERE message_id=?",
                (message_id,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return json.loads(row[0])
    except Exception:
        return None


def record(
    message_id: str,
    mode: str,
    result: dict[str, Any],
    db_path: Optional[str | Path] = None,
) -> None:
    """Store the dispatch result for this message_id. Idempotent (INSERT OR
    IGNORE so a race does not clobber the first writer's result).

    Never raises: a failure here must not fail the dispatch.
    """
    if not message_id:
        return
    try:
        conn = _connect(db_path)
        try:
            conn.execute(
                "INSERT OR IGNORE INTO dispatch_ledger "
                "(message_id, mode, result_json, created_at) VALUES (?,?,?,?)",
                (message_id, mode, json.dumps(result), time.time()),
            )
        finally:
            conn.close()
    except Exception:
        pass
