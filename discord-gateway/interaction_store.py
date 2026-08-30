"""Durable inbox for Discord interaction dispatches.

An interaction first enters the ``received`` state with its short-lived Discord
callback token removed. The Gateway activates it only after the initial Discord
ACK succeeds. A process-local drainer claims active rows and marks them complete
after the router reports a handled result. Recent completed rows remain as
replay tombstones so the same interaction ID cannot execute twice.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2
MAX_PAYLOAD_BYTES = 1_000_000
MAX_ACTIVE_INTERACTIONS = 256
MAX_DELIVERY_ATTEMPTS = 12
MAX_DATABASE_BYTES = 64 * 1024 * 1024
DONE_RETENTION_SECONDS = 7 * 24 * 60 * 60
RECEIVED_RETENTION_SECONDS = 24 * 60 * 60
RECEIVED_ACK_GRACE_SECONDS = 4.0


class InteractionStoreError(RuntimeError):
    """The durable interaction inbox cannot safely accept or process work."""


class InteractionConflictError(InteractionStoreError):
    """One interaction ID was replayed with different authenticated content."""


@dataclass(frozen=True)
class InteractionJob:
    interaction_id: str
    interaction: dict[str, Any]
    expected_application_id: str
    expected_bot_user_id: str
    expected_guild_id: str
    attempts: int


def _validate_private_path(path: Path, *, directory: bool) -> None:
    metadata = path.lstat()
    expected = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(
        metadata.st_mode
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected:
        raise InteractionStoreError(f"unsafe interaction store path: {path}")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise InteractionStoreError(f"interaction store path is not private: {path}")
    if not directory and metadata.st_nlink != 1:
        raise InteractionStoreError(f"interaction store must have one link: {path}")


def _prepare_parent(path: Path) -> None:
    parent = path.parent
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise InteractionStoreError("could not create interaction store directory") from exc
    try:
        metadata = parent.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise InteractionStoreError("interaction store directory is unsafe")
        os.chmod(parent, 0o700)
        _validate_private_path(parent, directory=True)
    except OSError as exc:
        raise InteractionStoreError("could not secure interaction store directory") from exc


def connect(path: Path) -> sqlite3.Connection:
    """Open and initialize a private, fully synchronous SQLite inbox."""

    path = Path(path)
    _prepare_parent(path)
    if path.is_symlink():
        raise InteractionStoreError("interaction store must not be a symlink")
    if path.exists():
        _validate_private_path(path, directory=False)

    try:
        connection = sqlite3.connect(str(path), timeout=30, isolation_level=None)
        os.chmod(path, 0o600)
        _validate_private_path(path, directory=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 30000")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        max_pages = max(1, MAX_DATABASE_BYTES // page_size)
        configured_max = int(
            connection.execute(f"PRAGMA max_page_count = {max_pages}").fetchone()[0]
        )
        if configured_max > max_pages:
            raise InteractionStoreError("could not enforce interaction database cap")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS interaction_inbox (
                interaction_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                expected_application_id TEXT NOT NULL,
                expected_bot_user_id TEXT NOT NULL,
                expected_guild_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('received', 'pending', 'processing', 'done')
                ),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                next_attempt_at REAL NOT NULL,
                claimed_at REAL,
                last_error TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                completed_at REAL
            );
            CREATE INDEX IF NOT EXISTS interaction_inbox_ready
            ON interaction_inbox(status, next_attempt_at, created_at);
            """
        )
        version = connection.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        if version is None:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        elif version["value"] != str(SCHEMA_VERSION):
            raise InteractionStoreError("unsupported interaction store schema")
        return connection
    except BaseException:
        if "connection" in locals():
            connection.close()
        raise


def enqueue(
    path: Path,
    interaction: dict[str, Any],
    *,
    expected_application_id: str,
    expected_bot_user_id: str,
    expected_guild_id: str,
    now: float | None = None,
) -> bool:
    """Commit one interaction, returning True only for the first receipt."""

    interaction_id = str(interaction.get("id") or "")
    if not interaction_id:
        raise InteractionStoreError("interaction is missing its ID")
    persisted_interaction = dict(interaction)
    persisted_interaction.pop("token", None)
    payload = json.dumps(
        persisted_interaction,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    payload_bytes = payload.encode("utf-8")
    if len(payload_bytes) > MAX_PAYLOAD_BYTES:
        raise InteractionStoreError("interaction payload exceeds the durable limit")
    digest = hashlib.sha256(payload_bytes).hexdigest()
    timestamp = time.time() if now is None else float(now)

    with closing(connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "DELETE FROM interaction_inbox WHERE status = 'done' "
                "AND completed_at < ?",
                (timestamp - DONE_RETENTION_SECONDS,),
            )
            connection.execute(
                "DELETE FROM interaction_inbox WHERE status = 'received' "
                "AND created_at < ?",
                (timestamp - RECEIVED_RETENTION_SECONDS,),
            )
            existing = connection.execute(
                """
                SELECT payload_sha256, expected_application_id,
                       expected_bot_user_id, expected_guild_id
                FROM interaction_inbox WHERE interaction_id = ?
                """,
                (interaction_id,),
            ).fetchone()
            identity = (
                digest,
                expected_application_id,
                expected_bot_user_id,
                expected_guild_id,
            )
            if existing is not None:
                stored = tuple(existing)
                if stored != identity:
                    raise InteractionConflictError(
                        "interaction ID replayed with different content or principal binding"
                    )
                connection.execute("COMMIT")
                return False
            active = int(
                connection.execute(
                    "SELECT COUNT(*) FROM interaction_inbox "
                    "WHERE status IN ('received', 'pending', 'processing')"
                ).fetchone()[0]
            )
            if active >= MAX_ACTIVE_INTERACTIONS:
                raise InteractionStoreError("interaction inbox active-row cap reached")
            connection.execute(
                """
                INSERT INTO interaction_inbox(
                    interaction_id, payload_json, payload_sha256,
                    expected_application_id, expected_bot_user_id,
                    expected_guild_id, status, attempts, next_attempt_at,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'received', 0, ?, ?)
                """,
                (
                    interaction_id,
                    payload,
                    digest,
                    expected_application_id,
                    expected_bot_user_id,
                    expected_guild_id,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute("COMMIT")
            return True
        except BaseException:
            connection.execute("ROLLBACK")
            raise


def mark_ready(path: Path, interaction_id: str) -> None:
    """Activate a durably received row after Discord accepts its initial ACK."""

    with closing(connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                "SELECT status FROM interaction_inbox WHERE interaction_id = ?",
                (interaction_id,),
            ).fetchone()
            if row is None:
                raise InteractionStoreError("ACKed interaction is absent from inbox")
            if row["status"] == "received":
                connection.execute(
                    "UPDATE interaction_inbox SET status = 'pending', "
                    "next_attempt_at = 0 WHERE interaction_id = ?",
                    (interaction_id,),
                )
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise


def activate_stale_received(path: Path, *, now: float | None = None) -> int:
    """Activate rows whose initial Discord ACK window has already elapsed."""

    timestamp = time.time() if now is None else float(now)
    with closing(connect(path)) as connection:
        cursor = connection.execute(
            """
            UPDATE interaction_inbox
            SET status = 'pending', next_attempt_at = 0,
                last_error = 'initial ACK outcome unknown; using PATCH fallback'
            WHERE status = 'received' AND created_at <= ?
            """,
            (timestamp - RECEIVED_ACK_GRACE_SECONDS,),
        )
        return cursor.rowcount


def recover_processing(path: Path) -> int:
    """Return claims interrupted by a prior client process to pending."""

    with closing(connect(path)) as connection:
        cursor = connection.execute(
            """
            UPDATE interaction_inbox
            SET status = 'pending', claimed_at = NULL, next_attempt_at = 0,
                last_error = 'client restarted while processing'
            WHERE status = 'processing'
            """
        )
        return cursor.rowcount


def claim_next(path: Path, *, now: float | None = None) -> InteractionJob | None:
    timestamp = time.time() if now is None else float(now)
    with closing(connect(path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                """
                SELECT * FROM interaction_inbox
                WHERE status = 'pending' AND next_attempt_at <= ?
                ORDER BY created_at, interaction_id
                LIMIT 1
                """,
                (timestamp,),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            attempts = int(row["attempts"]) + 1
            cursor = connection.execute(
                """
                UPDATE interaction_inbox
                SET status = 'processing', attempts = ?, claimed_at = ?
                WHERE interaction_id = ? AND status = 'pending'
                """,
                (attempts, timestamp, row["interaction_id"]),
            )
            if cursor.rowcount != 1:
                raise InteractionStoreError("interaction claim lost its serialization lock")
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise

    interaction = json.loads(row["payload_json"])
    if not isinstance(interaction, dict):
        raise InteractionStoreError("stored interaction payload is not an object")
    return InteractionJob(
        interaction_id=row["interaction_id"],
        interaction=interaction,
        expected_application_id=row["expected_application_id"],
        expected_bot_user_id=row["expected_bot_user_id"],
        expected_guild_id=row["expected_guild_id"],
        attempts=attempts,
    )


def mark_done(path: Path, interaction_id: str, *, now: float | None = None) -> None:
    timestamp = time.time() if now is None else float(now)
    with closing(connect(path)) as connection:
        cursor = connection.execute(
            """
            UPDATE interaction_inbox
            SET status = 'done', claimed_at = NULL, completed_at = ?, last_error = ''
            WHERE interaction_id = ? AND status = 'processing'
            """,
            (timestamp, interaction_id),
        )
        if cursor.rowcount != 1:
            raise InteractionStoreError("interaction completion did not match a claim")


def release_for_retry(
    path: Path,
    interaction_id: str,
    error: str,
    *,
    attempts: int,
    now: float | None = None,
) -> float | None:
    timestamp = time.time() if now is None else float(now)
    if attempts >= MAX_DELIVERY_ATTEMPTS:
        with closing(connect(path)) as connection:
            cursor = connection.execute(
                """
                UPDATE interaction_inbox
                SET status = 'done', claimed_at = NULL, completed_at = ?,
                    last_error = ?
                WHERE interaction_id = ? AND status = 'processing'
                """,
                (
                    timestamp,
                    f"dead-letter after {attempts} attempts: {error}"[:1000],
                    interaction_id,
                ),
            )
            if cursor.rowcount != 1:
                raise InteractionStoreError(
                    "interaction dead-letter did not match a claim"
                )
        return None
    delay = float(min(60, 2 ** min(max(attempts - 1, 0), 6)))
    with closing(connect(path)) as connection:
        cursor = connection.execute(
            """
            UPDATE interaction_inbox
            SET status = 'pending', claimed_at = NULL, next_attempt_at = ?,
                last_error = ?
            WHERE interaction_id = ? AND status = 'processing'
            """,
            (timestamp + delay, error[:1000], interaction_id),
        )
        if cursor.rowcount != 1:
            raise InteractionStoreError("interaction retry did not match a claim")
    return delay


def get(path: Path, interaction_id: str) -> dict[str, Any] | None:
    with closing(connect(path)) as connection:
        row = connection.execute(
            "SELECT * FROM interaction_inbox WHERE interaction_id = ?",
            (interaction_id,),
        ).fetchone()
        return None if row is None else dict(row)
