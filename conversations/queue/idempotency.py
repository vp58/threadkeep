#!/usr/bin/env python3
"""Crash-safe dispatch operation ledger.

Every Discord message is bound to one immutable dispatch request before any
external side effect occurs. The ledger is fail closed: database and locking
errors stop dispatch instead of falling back to a duplicate-prone path.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import uuid
from pathlib import Path
from typing import Any, Iterator, Optional

_HERE = Path(__file__).resolve().parent
_CONVERSATIONS = _HERE.parent
import sys

sys.path.insert(0, str(_CONVERSATIONS))
from config import CONFIG  # noqa: E402

_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_TOKEN = re.compile(r"[a-f0-9]{32}\Z")
_STATES = {
    "prepared",
    "thread_create_attempted",
    "thread_absence_confirmed",
    "thread_confirmed",
    "conversation_ready",
    "turn_appended",
    "completed",
}


def _db_path(db_path: Optional[str | Path] = None) -> Path:
    if db_path is not None:
        return Path(db_path)
    configured = os.environ.get("DISCOPARTY_MQ_DB")
    if configured:
        return Path(configured).expanduser()
    return CONFIG.paths.conversations_dir / "state" / "mq.sqlite3"


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("dispatch state directory must be a real directory")
    if metadata.st_uid != os.getuid():
        raise RuntimeError("dispatch state directory must be owned by the current user")
    os.chmod(path, 0o700, follow_symlinks=False)


def _secure_state_file(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("dispatch state file must not be a symlink")
    if not path.exists():
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise RuntimeError("dispatch state file is not a private regular file")
    os.chmod(path, 0o600, follow_symlinks=False)


def _connect(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    path = _db_path(db_path)
    _secure_directory(path.parent)
    _secure_state_file(path)
    before = path.lstat()
    conn = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    after = path.lstat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        conn.close()
        raise RuntimeError("dispatch state file changed while opening")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    check = conn.execute("PRAGMA quick_check").fetchone()
    if check is None or check[0] != "ok":
        conn.close()
        raise RuntimeError("dispatch state database failed integrity check")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS dispatch_operations (
            message_id          TEXT PRIMARY KEY,
            mode                TEXT NOT NULL CHECK(mode IN ('top-level','reply')),
            request_sha256      TEXT NOT NULL,
            body_sha256         TEXT NOT NULL,
            state               TEXT NOT NULL,
            channel_id          TEXT NOT NULL,
            source_thread_id    TEXT,
            thread_id           TEXT,
            session_id          TEXT NOT NULL,
            title               TEXT NOT NULL,
            turn_token          TEXT NOT NULL,
            result_json         TEXT,
            thread_attempted_at REAL,
            thread_absence_confirmed_at REAL,
            last_error          TEXT,
            created_at          REAL NOT NULL,
            updated_at          REAL NOT NULL
        );
        """
    )
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(dispatch_operations)")
    }
    if "thread_absence_confirmed_at" not in columns:
        conn.execute(
            "ALTER TABLE dispatch_operations "
            "ADD COLUMN thread_absence_confirmed_at REAL"
        )
    return conn


@contextlib.contextmanager
def operation_lock(db_path: Optional[str | Path] = None) -> Iterator[None]:
    """Serialize dispatch side effects across processes and release on crash."""

    path = _db_path(db_path)
    _secure_directory(path.parent)
    lock_path = path.parent / ".dispatch.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise RuntimeError("dispatch lock is not a private regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        with contextlib.suppress(Exception):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def request_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_digest(value: str, name: str) -> None:
    if not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    if result["state"] not in _STATES:
        raise RuntimeError("dispatch operation contains an invalid state")
    if not _TOKEN.fullmatch(str(result["turn_token"])):
        raise RuntimeError("dispatch operation contains an invalid turn token")
    return result


def _legacy_result(
    conn: sqlite3.Connection, message_id: str
) -> dict[str, Any] | None:
    table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='dispatch_ledger'"
    ).fetchone()
    if table is None:
        return None
    row = conn.execute(
        "SELECT result_json FROM dispatch_ledger WHERE message_id=?", (message_id,)
    ).fetchone()
    if row is None:
        return None
    try:
        result = json.loads(row[0])
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("legacy dispatch result is corrupt") from exc
    if not isinstance(result, dict):
        raise RuntimeError("legacy dispatch result is not an object")
    return result


def prepare(
    *,
    message_id: str,
    mode: str,
    request_sha256: str,
    body_sha256: str,
    channel_id: str,
    source_thread_id: str | None,
    title: str,
    session_id: str | None = None,
    db_path: Optional[str | Path] = None,
) -> dict[str, Any]:
    """Create or verify one immutable operation before external side effects."""

    if mode not in {"top-level", "reply"}:
        raise ValueError("unsupported dispatch mode")
    _validate_digest(request_sha256, "request_sha256")
    _validate_digest(body_sha256, "body_sha256")
    if not message_id or len(message_id) > 128 or "\x00" in message_id:
        raise ValueError("invalid dispatch message ID")
    if not channel_id or len(channel_id) > 128 or "\x00" in channel_id:
        raise ValueError("invalid dispatch channel ID")
    if mode == "reply" and not source_thread_id:
        raise ValueError("reply dispatch requires a source thread")
    if mode == "top-level" and source_thread_id is not None:
        raise ValueError("top-level dispatch cannot have a source thread")
    if not title or len(title) > 100 or "\n" in title or "\r" in title:
        raise ValueError("invalid frozen dispatch title")
    now = time.time()
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM dispatch_operations WHERE message_id=?", (message_id,)
        ).fetchone()
        if row is None:
            selected_session = session_id or str(uuid.uuid4())
            expected_thread = message_id if mode == "top-level" else source_thread_id
            legacy = _legacy_result(conn, message_id)
            state = "prepared"
            result_json = None
            if legacy is not None:
                required = {"mode", "session_id", "thread_id", "channel_id", "title"}
                if not required <= set(legacy):
                    raise RuntimeError("legacy dispatch result is incomplete")
                if str(legacy["mode"]) != mode:
                    raise RuntimeError("legacy dispatch mode conflicts with replay")
                if mode == "top-level" and str(legacy["channel_id"]) != channel_id:
                    raise RuntimeError("legacy dispatch channel conflicts with replay")
                if mode == "reply" and str(legacy["thread_id"]) != source_thread_id:
                    raise RuntimeError("legacy dispatch thread conflicts with replay")
                selected_session = str(legacy["session_id"])
                expected_thread = str(legacy["thread_id"])
                title = str(legacy["title"])
                state = "completed"
                result_json = json.dumps(legacy, sort_keys=True, separators=(",", ":"))
            conn.execute(
                "INSERT INTO dispatch_operations "
                "(message_id,mode,request_sha256,body_sha256,state,channel_id,"
                "source_thread_id,thread_id,session_id,title,turn_token,result_json,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    message_id,
                    mode,
                    request_sha256,
                    body_sha256,
                    state,
                    channel_id,
                    source_thread_id,
                    expected_thread,
                    selected_session,
                    title,
                    os.urandom(16).hex(),
                    result_json,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM dispatch_operations WHERE message_id=?", (message_id,)
            ).fetchone()
        if row is None:
            raise RuntimeError("dispatch reservation disappeared after insert")
        immutable = (
            row["mode"],
            row["request_sha256"],
            row["body_sha256"],
            row["channel_id"],
            row["source_thread_id"],
        )
        expected = (mode, request_sha256, body_sha256, channel_id, source_thread_id)
        if immutable != expected:
            raise RuntimeError("dispatch replay changed its immutable request")
        if session_id is not None and row["session_id"] != session_id:
            raise RuntimeError("dispatch replay changed its immutable session")
        if row["title"] != title and row["state"] != "completed":
            raise RuntimeError("dispatch replay changed its immutable title")
        conn.execute("COMMIT")
        return _row_dict(row)
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get(message_id: str, db_path: Optional[str | Path] = None) -> dict[str, Any] | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM dispatch_operations WHERE message_id=?", (message_id,)
        ).fetchone()
        return None if row is None else _row_dict(row)
    finally:
        conn.close()


def _transition(
    message_id: str,
    expected: set[str],
    target: str,
    *,
    assignments: dict[str, Any] | None = None,
    db_path: Optional[str | Path] = None,
) -> dict[str, Any]:
    if target not in _STATES:
        raise ValueError("invalid dispatch transition target")
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM dispatch_operations WHERE message_id=?", (message_id,)
        ).fetchone()
        if row is None:
            raise RuntimeError("dispatch operation disappeared")
        values = assignments or {}
        if row["state"] == target:
            for key, value in values.items():
                if row[key] != value:
                    raise RuntimeError("dispatch transition replay changed frozen state")
            conn.execute("COMMIT")
            return _row_dict(row)
        if row["state"] not in expected:
            raise RuntimeError(
                f"invalid dispatch transition {row['state']} -> {target}"
            )
        for key in values:
            if key not in {
                "thread_attempted_at",
                "thread_absence_confirmed_at",
                "thread_id",
                "result_json",
                "last_error",
            }:
                raise ValueError("unsupported dispatch transition assignment")
        columns = ["state=?", "updated_at=?"]
        params: list[Any] = [target, time.time()]
        for key, value in values.items():
            columns.append(f"{key}=?")
            params.append(value)
        params.append(message_id)
        conn.execute(
            f"UPDATE dispatch_operations SET {','.join(columns)} WHERE message_id=?",
            params,
        )
        updated = conn.execute(
            "SELECT * FROM dispatch_operations WHERE message_id=?", (message_id,)
        ).fetchone()
        if updated is None:
            raise RuntimeError("dispatch operation disappeared after transition")
        conn.execute("COMMIT")
        return _row_dict(updated)
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def mark_thread_attempted(
    message_id: str, db_path: Optional[str | Path] = None
) -> dict[str, Any]:
    current = get(message_id, db_path)
    if current is None:
        raise RuntimeError("dispatch operation disappeared")
    attempted_at = current["thread_attempted_at"] or time.time()
    return _transition(
        message_id,
        {"prepared"},
        "thread_create_attempted",
        assignments={"thread_attempted_at": attempted_at},
        db_path=db_path,
    )


def mark_thread_absence_confirmed(
    message_id: str, db_path: Optional[str | Path] = None
) -> dict[str, Any]:
    """Persist bounded GET evidence that the deterministic thread is absent.

    This transition is the only route from an unknown create outcome to a
    recovery POST. A crash after the transition re-enters the same recovery
    path instead of reverting to an unconstrained create.
    """

    current = get(message_id, db_path)
    if current is None:
        raise RuntimeError("dispatch operation disappeared")
    observed_at = current["thread_absence_confirmed_at"] or time.time()
    return _transition(
        message_id,
        {"thread_create_attempted"},
        "thread_absence_confirmed",
        assignments={"thread_absence_confirmed_at": observed_at},
        db_path=db_path,
    )


def confirm_thread(
    message_id: str, thread_id: str, db_path: Optional[str | Path] = None
) -> dict[str, Any]:
    current = get(message_id, db_path)
    if current is None or current["thread_id"] != thread_id:
        raise RuntimeError("Discord thread does not match its frozen message binding")
    return _transition(
        message_id,
        {"thread_create_attempted", "thread_absence_confirmed"},
        "thread_confirmed",
        assignments={"thread_id": thread_id},
        db_path=db_path,
    )


def mark_conversation_ready(
    message_id: str, db_path: Optional[str | Path] = None
) -> dict[str, Any]:
    return _transition(
        message_id,
        {"thread_confirmed"},
        "conversation_ready",
        db_path=db_path,
    )


def mark_turn_appended(
    message_id: str, db_path: Optional[str | Path] = None
) -> dict[str, Any]:
    return _transition(
        message_id,
        {"prepared", "conversation_ready"},
        "turn_appended",
        db_path=db_path,
    )


def complete(
    message_id: str,
    result: dict[str, Any],
    db_path: Optional[str | Path] = None,
) -> dict[str, Any]:
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    row = _transition(
        message_id,
        {"turn_appended"},
        "completed",
        assignments={"result_json": encoded},
        db_path=db_path,
    )
    parsed = json.loads(row["result_json"])
    if parsed != result:
        raise RuntimeError("completed dispatch result changed during replay")
    return row


def result(row: dict[str, Any]) -> dict[str, Any]:
    if row["state"] != "completed" or not row.get("result_json"):
        raise RuntimeError("dispatch operation is not complete")
    try:
        value = json.loads(row["result_json"])
    except json.JSONDecodeError as exc:
        raise RuntimeError("completed dispatch result is corrupt") from exc
    if not isinstance(value, dict):
        raise RuntimeError("completed dispatch result is not an object")
    return value


def record_error(
    message_id: str, error: str, db_path: Optional[str | Path] = None
) -> None:
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "UPDATE dispatch_operations SET last_error=?,updated_at=? WHERE message_id=?",
            (error[:1000], time.time(), message_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("dispatch operation disappeared while recording failure")
    finally:
        conn.close()
