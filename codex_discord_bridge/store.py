from __future__ import annotations

import sqlite3
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  event_id TEXT PRIMARY KEY,
  guild_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  author_id TEXT NOT NULL,
  content TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('queued','running','completed','failed','cancelled','uncertain')),
  owner TEXT,
  generation INTEGER NOT NULL DEFAULT 0,
  lease_until INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  result_message_id TEXT,
  discord_thread_id TEXT,
  ready INTEGER NOT NULL DEFAULT 1 CHECK(ready IN (0,1)),
  policy_binding TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
  scope TEXT PRIMARY KEY,
  thread_id TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
  event_id TEXT NOT NULL,
  chunk_index INTEGER NOT NULL,
  destination_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('prepared','sent')),
  message_id TEXT,
  attempted_at INTEGER,
  ambiguous_at INTEGER,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(event_id, chunk_index)
);
CREATE TABLE IF NOT EXISTS delivery_manifests (
  event_id TEXT PRIMARY KEY,
  destination_id TEXT NOT NULL,
  response_hash TEXT NOT NULL,
  chunk_count INTEGER NOT NULL CHECK(chunk_count > 0),
  state TEXT NOT NULL CHECK(state IN ('prepared','sent')),
  updated_at INTEGER NOT NULL,
  policy_binding TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS channel_cursors (
  channel_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
"""

DELIVERY_ATTEMPT_SCHEMA_VERSION = 1


class IngressLimitExceeded(RuntimeError):
    """A durable ingress limit rejected a new Discord event."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class JobStore:
    def __init__(
        self,
        path: Path,
        *,
        max_database_bytes: int = 268_435_456,
        retention_days: int = 30,
        policy_binding: str = "",
    ):
        self.path = path
        self.max_database_bytes = max_database_bytes
        self.retention_days = retention_days
        self.policy_binding = policy_binding

    @contextmanager
    def connect(self):
        parent = self.path.parent
        created_parent = False
        try:
            parent_metadata = parent.lstat()
        except FileNotFoundError:
            parent.mkdir(mode=0o700, parents=True)
            created_parent = True
            parent_metadata = parent.lstat()
        if created_parent:
            parent.chmod(0o700)
            parent_metadata = parent.lstat()
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise RuntimeError("job store directory must be a private, owned real directory")
        try:
            database_metadata = self.path.lstat()
        except FileNotFoundError:
            database_metadata = None
        if database_metadata is not None and (
            stat.S_ISLNK(database_metadata.st_mode)
            or not stat.S_ISREG(database_metadata.st_mode)
            or database_metadata.st_uid != os.getuid()
            or stat.S_IMODE(database_metadata.st_mode) != 0o600
        ):
            raise RuntimeError("job store database path is unsafe")
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(SCHEMA)
            columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
            if "discord_thread_id" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN discord_thread_id TEXT")
            if "ready" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN ready INTEGER NOT NULL DEFAULT 1")
            if "policy_binding" not in columns:
                db.execute(
                    "ALTER TABLE jobs ADD COLUMN policy_binding TEXT NOT NULL DEFAULT ''"
                )
            manifest_columns = {
                row[1] for row in db.execute("PRAGMA table_info(delivery_manifests)")
            }
            if "policy_binding" not in manifest_columns:
                db.execute(
                    "ALTER TABLE delivery_manifests ADD COLUMN policy_binding TEXT NOT NULL DEFAULT ''"
                )
            schema_version = int(db.execute("PRAGMA user_version").fetchone()[0])
            if schema_version > DELIVERY_ATTEMPT_SCHEMA_VERSION:
                raise RuntimeError("job store schema is newer than this Disco Party build")
            if schema_version < DELIVERY_ATTEMPT_SCHEMA_VERSION:
                # SQLite DDL is transactional inside an explicit transaction.
                # The version marker, both columns, and the legacy backfill
                # must commit together so a crash cannot make an unknown old
                # POST look like a never-attempted delivery.
                db.execute("BEGIN IMMEDIATE")
                delivery_columns = {
                    row[1] for row in db.execute("PRAGMA table_info(deliveries)")
                }
                if "attempted_at" not in delivery_columns:
                    db.execute(
                        "ALTER TABLE deliveries ADD COLUMN attempted_at INTEGER"
                    )
                if "ambiguous_at" not in delivery_columns:
                    db.execute(
                        "ALTER TABLE deliveries ADD COLUMN ambiguous_at INTEGER"
                    )
                db.execute(
                    "UPDATE deliveries SET attempted_at=updated_at "
                    "WHERE state='prepared' AND attempted_at IS NULL"
                )
                db.execute(f"PRAGMA user_version={DELIVERY_ATTEMPT_SCHEMA_VERSION}")
                db.commit()
            delivery_columns = {
                row[1] for row in db.execute("PRAGMA table_info(deliveries)")
            }
            if not {"attempted_at", "ambiguous_at"}.issubset(delivery_columns):
                raise RuntimeError("job store delivery schema is incomplete")
            if database_metadata is None:
                self.path.chmod(0o600)
            yield db
        finally:
            db.close()

    def enqueue(self, *, event_id: str, guild_id: str, channel_id: str, author_id: str, content: str, ready: bool = True) -> bool:
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute(
                "INSERT OR IGNORE INTO jobs(event_id,guild_id,channel_id,author_id,content,state,ready,created_at,updated_at,policy_binding) VALUES(?,?,?,?,?,'queued',?,?,?,?)",
                (event_id, guild_id, channel_id, author_id, content, int(ready), now, now, self.policy_binding),
            )
            db.commit()
            return cur.rowcount == 1

    @staticmethod
    def _logical_database_bytes(db: sqlite3.Connection) -> int:
        page_count = int(db.execute("PRAGMA page_count").fetchone()[0])
        free_pages = int(db.execute("PRAGMA freelist_count").fetchone()[0])
        page_size = int(db.execute("PRAGMA page_size").fetchone()[0])
        return max(0, page_count - free_pages) * page_size

    def _prune_terminal_in_transaction(
        self,
        db: sqlite3.Connection, before: int
    ) -> int:
        rows = db.execute(
            "SELECT candidate.event_id,candidate.discord_thread_id FROM jobs AS candidate "
            "WHERE candidate.state IN ('completed','failed','cancelled','uncertain') "
            "AND candidate.updated_at < ? "
            "AND (candidate.discord_thread_id IS NULL OR NOT EXISTS ("
            "SELECT 1 FROM jobs AS child "
            "WHERE child.channel_id=candidate.discord_thread_id "
            "AND (child.updated_at >= ? OR child.state IN ('queued','running'))"
            "))",
            (before, before),
        ).fetchall()
        if not rows:
            db.execute(
                "DELETE FROM deliveries WHERE event_id IN ("
                "SELECT event_id FROM delivery_manifests "
                "WHERE updated_at < ? AND event_id NOT IN (SELECT event_id FROM jobs))",
                (before,),
            )
            db.execute(
                "DELETE FROM delivery_manifests "
                "WHERE updated_at < ? AND event_id NOT IN (SELECT event_id FROM jobs)",
                (before,),
            )
            return 0
        event_ids = [str(row[0]) for row in rows]
        thread_ids = [str(row[1]) for row in rows if row[1]]
        placeholders = ",".join("?" for _ in event_ids)
        db.execute(
            f"DELETE FROM deliveries WHERE event_id IN ({placeholders})", event_ids
        )
        db.execute(
            f"DELETE FROM delivery_manifests WHERE event_id IN ({placeholders})",
            event_ids,
        )
        scopes = [f"discord:{event_id}" for event_id in event_ids]
        if scopes:
            scope_placeholders = ",".join("?" for _ in scopes)
            db.execute(
                f"DELETE FROM sessions WHERE scope IN ({scope_placeholders})", scopes
            )
        if thread_ids:
            for thread_id in thread_ids:
                db.execute(
                    "DELETE FROM sessions WHERE scope LIKE ? OR scope LIKE ?",
                    (f"managed:%:{thread_id}", f"codex:%:{thread_id}"),
                )
            db.execute(
                "DELETE FROM channel_cursors WHERE "
                + " OR ".join("channel_id LIKE ?" for _ in thread_ids),
                [f"%:{thread_id}" for thread_id in thread_ids],
            )
        db.execute(f"DELETE FROM jobs WHERE event_id IN ({placeholders})", event_ids)
        db.execute(
            "DELETE FROM deliveries WHERE event_id IN ("
            "SELECT event_id FROM delivery_manifests "
            "WHERE updated_at < ? AND event_id NOT IN (SELECT event_id FROM jobs))",
            (before,),
        )
        db.execute(
            "DELETE FROM delivery_manifests "
            "WHERE updated_at < ? AND event_id NOT IN (SELECT event_id FROM jobs)",
            (before,),
        )
        return len(event_ids)

    def prune_terminal(self, *, now: int | None = None) -> int:
        current = int(time.time()) if now is None else int(now)
        before = current - self.retention_days * 86_400
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            deleted = self._prune_terminal_in_transaction(db, before)
            db.commit()
            return deleted

    def enqueue_limited(
        self,
        *,
        event_id: str,
        guild_id: str,
        channel_id: str,
        author_id: str,
        content: str,
        max_messages_per_minute: int,
        max_messages_per_hour: int,
        max_pending_jobs: int,
        ready: bool = True,
    ) -> bool:
        """Atomically deduplicate, prune, rate-check, and reserve an event."""

        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT 1 FROM jobs WHERE event_id=?", (event_id,)
            ).fetchone()
            if existing:
                db.commit()
                return False
            self._prune_terminal_in_transaction(
                db, now - self.retention_days * 86_400
            )
            if self._logical_database_bytes(db) >= self.max_database_bytes:
                db.rollback()
                raise IngressLimitExceeded("database capacity reached")
            pending = int(
                db.execute(
                    "SELECT COUNT(*) FROM jobs "
                    "WHERE state IN ('queued','running','uncertain') AND policy_binding=?",
                    (self.policy_binding,),
                ).fetchone()[0]
            )
            if pending >= max_pending_jobs:
                db.rollback()
                raise IngressLimitExceeded("pending job limit reached")
            minute_count = int(
                db.execute(
                    "SELECT COUNT(*) FROM jobs WHERE author_id=? AND created_at>? AND policy_binding=?",
                    (author_id, now - 60, self.policy_binding),
                ).fetchone()[0]
            )
            if minute_count >= max_messages_per_minute:
                db.rollback()
                raise IngressLimitExceeded("per-minute message limit reached")
            hour_count = int(
                db.execute(
                    "SELECT COUNT(*) FROM jobs WHERE author_id=? AND created_at>? AND policy_binding=?",
                    (author_id, now - 3_600, self.policy_binding),
                ).fetchone()[0]
            )
            if hour_count >= max_messages_per_hour:
                db.rollback()
                raise IngressLimitExceeded("per-hour message limit reached")
            cur = db.execute(
                "INSERT INTO jobs(event_id,guild_id,channel_id,author_id,content,state,ready,created_at,updated_at,policy_binding) "
                "VALUES(?,?,?,?,?,'queued',?,?,?,?)",
                (
                    event_id,
                    guild_id,
                    channel_id,
                    author_id,
                    content,
                    int(ready),
                    now,
                    now,
                    self.policy_binding,
                ),
            )
            db.commit()
            return cur.rowcount == 1

    def claim(self, owner: str, lease_seconds: int = 300):
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT candidate.event_id FROM jobs AS candidate "
                "WHERE candidate.state='queued' AND candidate.ready=1 "
                "AND candidate.policy_binding=? AND NOT EXISTS ("
                "SELECT 1 FROM jobs AS active "
                "WHERE active.state IN ('running','uncertain') "
                "AND active.policy_binding=candidate.policy_binding "
                "AND COALESCE(active.discord_thread_id,active.channel_id)="
                "COALESCE(candidate.discord_thread_id,candidate.channel_id)"
                ") ORDER BY candidate.created_at,candidate.event_id LIMIT 1",
                (self.policy_binding,),
            ).fetchone()
            if row is None:
                db.commit(); return None
            event_id = row[0]
            cur = db.execute(
                "UPDATE jobs SET state='running',owner=?,generation=generation+1,lease_until=?,updated_at=? "
                "WHERE event_id=? AND state='queued' AND policy_binding=?",
                (owner, now + lease_seconds, now, event_id, self.policy_binding),
            )
            if cur.rowcount != 1:
                db.rollback(); return None
            job = db.execute("SELECT event_id,content,generation FROM jobs WHERE event_id=?", (event_id,)).fetchone()
            db.commit(); return job

    def set_discord_thread(self, event_id: str, thread_id: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET discord_thread_id=?,updated_at=? WHERE event_id=? AND policy_binding=?",
                (thread_id, int(time.time()), event_id, self.policy_binding),
            )

    def make_ready(self, event_id: str, thread_id: str) -> bool:
        with self.connect() as db:
            cur = db.execute(
                "UPDATE jobs SET discord_thread_id=?,ready=1,updated_at=? "
                "WHERE event_id=? AND state='queued' AND policy_binding=?",
                (thread_id, int(time.time()), event_id, self.policy_binding),
            )
            return cur.rowcount == 1

    def job_status(self, event_id: str):
        with self.connect() as db:
            return db.execute(
                "SELECT state,ready,discord_thread_id,guild_id,channel_id,author_id,content FROM jobs WHERE event_id=?",
                (event_id,),
            ).fetchone()

    def job_policy_binding(self, event_id: str) -> str | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT policy_binding FROM jobs WHERE event_id=?", (event_id,)
            ).fetchone()
            return str(row[0]) if row else None

    def discord_thread_for(self, event_id: str) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT discord_thread_id FROM jobs WHERE event_id=?", (event_id,)).fetchone()
            return row[0] if row else None

    def job_channel_for(self, event_id: str) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT channel_id FROM jobs WHERE event_id=?", (event_id,)).fetchone()
            return row[0] if row else None

    def reclaim_expired(self, owner: str, lease_seconds: int = 300):
        """Claim one expired job with a new fencing generation.

        An expired job is uncertain. The caller must reconcile any possible
        external result before producing another external effect.
        """
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT event_id FROM jobs WHERE state='running' AND lease_until < ? "
                "AND policy_binding=? ORDER BY lease_until,event_id LIMIT 1",
                (now, self.policy_binding),
            ).fetchone()
            if row is None:
                db.commit(); return None
            event_id = row[0]
            cur = db.execute(
                "UPDATE jobs SET state='uncertain',owner=?,generation=generation+1,lease_until=?,updated_at=? "
                "WHERE event_id=? AND state='running' AND lease_until < ? AND policy_binding=?",
                (owner, now + lease_seconds, now, event_id, now, self.policy_binding),
            )
            if cur.rowcount != 1:
                db.rollback(); return None
            row = db.execute("SELECT event_id,content,generation FROM jobs WHERE event_id=?", (event_id,)).fetchone()
            db.commit(); return row

    def reclaim_abandoned(self, owner: str, lease_seconds: int = 300):
        """Fence one running job left by an earlier bridge process.

        This is valid only during startup, before the current bridge launches
        its worker pool. Once slots are live, their distinct owner values are
        healthy siblings and must never be compared with this method.
        """
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT event_id FROM jobs WHERE state='running' AND owner IS NOT ? AND policy_binding=? "
                "ORDER BY updated_at,event_id LIMIT 1",
                (owner, self.policy_binding),
            ).fetchone()
            if row is None:
                db.commit(); return None
            event_id = row[0]
            cur = db.execute(
                "UPDATE jobs SET state='uncertain',owner=?,generation=generation+1,lease_until=?,updated_at=? "
                "WHERE event_id=? AND state='running' AND owner IS NOT ? AND policy_binding=?",
                (owner, now + lease_seconds, now, event_id, owner, self.policy_binding),
            )
            if cur.rowcount != 1:
                db.rollback(); return None
            row = db.execute(
                "SELECT event_id,content,generation FROM jobs WHERE event_id=?", (event_id,)
            ).fetchone()
            db.commit(); return row

    def renew(self, event_id: str, owner: str, generation: int, lease_seconds: int = 300) -> bool:
        now = int(time.time())
        with self.connect() as db:
            cur = db.execute(
                "UPDATE jobs SET lease_until=?,updated_at=? WHERE event_id=? AND state='running' "
                "AND owner=? AND generation=? AND policy_binding=?",
                (now + lease_seconds, now, event_id, owner, generation, self.policy_binding),
            )
            return cur.rowcount == 1

    def cancel(self, event_id: str) -> bool:
        with self.connect() as db:
            cur = db.execute(
                "UPDATE jobs SET state='cancelled',updated_at=? WHERE event_id=? "
                "AND state='queued' AND policy_binding=?",
                (int(time.time()), event_id, self.policy_binding),
            )
            return cur.rowcount == 1

    def cancel_unready_root(self, event_id: str, root_channel_id: str) -> bool:
        """Cancel a vanished root reservation and remove partial routing state."""

        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,ready,channel_id,discord_thread_id,policy_binding "
                "FROM jobs WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if (
                row is None
                or row[:3] != ("queued", 0, root_channel_id)
                or row[4] != self.policy_binding
            ):
                db.rollback()
                return False
            mapped = db.execute(
                "SELECT thread_id FROM sessions WHERE scope=?",
                (f"discord:{event_id}",),
            ).fetchone()
            thread_id = str(row[3] or (mapped[0] if mapped else ""))
            updated = db.execute(
                "UPDATE jobs SET state='cancelled',updated_at=? "
                "WHERE event_id=? AND channel_id=? AND state='queued' AND ready=0 "
                "AND policy_binding=?",
                (
                    now,
                    event_id,
                    root_channel_id,
                    self.policy_binding,
                ),
            )
            if updated.rowcount != 1:
                db.rollback()
                return False
            db.execute(
                "DELETE FROM sessions WHERE scope=?",
                (f"discord:{event_id}",),
            )
            if thread_id:
                db.execute(
                    "DELETE FROM sessions WHERE scope=? AND thread_id=?",
                    (
                        f"managed:{self.policy_binding}:{thread_id}",
                        event_id,
                    ),
                )
                db.execute(
                    "DELETE FROM sessions WHERE scope=?",
                    (f"codex:{self.policy_binding}:{thread_id}",),
                )
                db.execute(
                    "DELETE FROM channel_cursors WHERE channel_id=?",
                    (f"policy:{self.policy_binding}:{thread_id}",),
                )
            db.commit()
            return True

    def finish(self, event_id: str, owner: str, generation: int, state: str, result_message_id: str | None = None) -> bool:
        if state not in {"completed", "failed", "cancelled", "uncertain"}:
            raise ValueError("invalid terminal state")
        with self.connect() as db:
            cur = db.execute(
                "UPDATE jobs SET state=?,result_message_id=?,updated_at=? WHERE event_id=? "
                "AND state='running' AND owner=? AND generation=? AND policy_binding=?",
                (
                    state,
                    result_message_id,
                    int(time.time()),
                    event_id,
                    owner,
                    generation,
                    self.policy_binding,
                ),
            )
            return cur.rowcount == 1

    def complete_uncertain(self, event_id: str, generation: int, result_message_id: str) -> bool:
        with self.connect() as db:
            cur = db.execute(
                "UPDATE jobs SET state='completed',result_message_id=?,updated_at=? "
                "WHERE event_id=? AND state='uncertain' AND generation=? AND policy_binding=?",
                (
                    result_message_id,
                    int(time.time()),
                    event_id,
                    generation,
                    self.policy_binding,
                ),
            )
            return cur.rowcount == 1

    def uncertain_jobs(self):
        with self.connect() as db:
            return db.execute(
                "SELECT event_id,generation FROM jobs WHERE state='uncertain' AND policy_binding=? ORDER BY updated_at,event_id",
                (self.policy_binding,),
            ).fetchall()

    def unready_root_ids(self, root_channel_id: str) -> list[str]:
        with self.connect() as db:
            return [
                row[0]
                for row in db.execute(
                    "SELECT event_id FROM jobs WHERE channel_id=? AND state='queued' AND ready=0 AND policy_binding=? "
                    "ORDER BY created_at,event_id",
                    (root_channel_id, self.policy_binding),
                )
            ]

    def thread_for(self, scope: str) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT thread_id FROM sessions WHERE scope=?", (scope,)).fetchone()
            return row[0] if row else None

    def save_thread(self, scope: str, thread_id: str) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO sessions(scope,thread_id,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(scope) DO UPDATE SET thread_id=excluded.thread_id,updated_at=excluded.updated_at",
                (scope, thread_id, int(time.time())),
            )

    def save_managed_thread(self, thread_id: str, root_event_id: str) -> None:
        self.save_thread(
            f"managed:{self.policy_binding}:{thread_id}", root_event_id
        )

    def managed_root(self, thread_id: str) -> str | None:
        return self.thread_for(f"managed:{self.policy_binding}:{thread_id}")

    def managed_threads(self) -> list[str]:
        with self.connect() as db:
            prefix = f"managed:{self.policy_binding}:"
            return [
                row[0].removeprefix(prefix)
                for row in db.execute(
                    "SELECT scope FROM sessions WHERE scope LIKE ?", (prefix + "%",)
                )
            ]

    def cursor_for(self, channel_id: str) -> str | None:
        scope = f"policy:{self.policy_binding}:{channel_id}"
        with self.connect() as db:
            row = db.execute(
                "SELECT event_id FROM channel_cursors WHERE channel_id=?", (scope,)
            ).fetchone()
            return row[0] if row else None

    def save_cursor(self, channel_id: str, event_id: str) -> None:
        if not event_id.isdecimal():
            raise ValueError("Discord cursor must be a numeric snowflake")
        scope = f"policy:{self.policy_binding}:{channel_id}"
        with self.connect() as db:
            db.execute(
                "INSERT INTO channel_cursors(channel_id,event_id,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(channel_id) DO UPDATE SET "
                "event_id=CASE WHEN CAST(excluded.event_id AS INTEGER) > CAST(channel_cursors.event_id AS INTEGER) "
                "THEN excluded.event_id ELSE channel_cursors.event_id END,updated_at=excluded.updated_at",
                (scope, event_id, int(time.time())),
            )

    def prepare_delivery_manifest(
        self,
        event_id: str,
        destination_id: str,
        response_hash: str,
        chunks: list[tuple[str, str, str]],
    ) -> None:
        """Persist the complete immutable output before the first Discord POST.

        Each chunk tuple is (nonce, content, content_hash).
        """
        if not chunks:
            raise ValueError("delivery manifest cannot be empty")
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            projected = sum(len(content.encode("utf-8")) for _, content, _ in chunks)
            if self._logical_database_bytes(db) + projected >= self.max_database_bytes:
                db.rollback()
                raise IngressLimitExceeded("database capacity reached before delivery")
            db.execute(
                "INSERT OR IGNORE INTO delivery_manifests"
                "(event_id,destination_id,response_hash,chunk_count,state,updated_at,policy_binding) "
                "VALUES(?,?,?,?,'prepared',?,?)",
                (event_id, destination_id, response_hash, len(chunks), now, self.policy_binding),
            )
            manifest = db.execute(
                "SELECT destination_id,response_hash,chunk_count,policy_binding FROM delivery_manifests WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if manifest != (
                destination_id,
                response_hash,
                len(chunks),
                self.policy_binding,
            ):
                db.rollback()
                raise RuntimeError("delivery replay changed immutable manifest")
            for index, (nonce, content, content_hash) in enumerate(chunks):
                db.execute(
                    "INSERT OR IGNORE INTO deliveries"
                    "(event_id,chunk_index,destination_id,nonce,content,content_hash,state,updated_at) "
                    "VALUES(?,?,?,?,?,?,'prepared',?)",
                    (event_id, index, destination_id, nonce, content, content_hash, now),
                )
                row = db.execute(
                    "SELECT destination_id,nonce,content,content_hash FROM deliveries "
                    "WHERE event_id=? AND chunk_index=?",
                    (event_id, index),
                ).fetchone()
                if row != (destination_id, nonce, content, content_hash):
                    db.rollback()
                    raise RuntimeError("delivery replay changed immutable chunk")
            actual = db.execute(
                "SELECT COUNT(*) FROM deliveries WHERE event_id=?", (event_id,)
            ).fetchone()[0]
            if actual != len(chunks):
                db.rollback()
                raise RuntimeError("delivery manifest chunk count mismatch")
            db.commit()

    def prepare_delivery(
        self,
        event_id: str,
        chunk_index: int,
        destination_id: str,
        nonce: str,
        content: str,
        content_hash: str,
    ) -> tuple[str, str | None]:
        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR IGNORE INTO deliveries(event_id,chunk_index,destination_id,nonce,content,content_hash,state,updated_at) "
                "VALUES(?,?,?,?,?,?,'prepared',?)",
                (event_id, chunk_index, destination_id, nonce, content, content_hash, now),
            )
            row = db.execute(
                "SELECT destination_id,nonce,content_hash,state,message_id FROM deliveries WHERE event_id=? AND chunk_index=?",
                (event_id, chunk_index),
            ).fetchone()
            if row[:3] != (destination_id, nonce, content_hash):
                db.rollback()
                raise RuntimeError("delivery replay changed immutable payload")
            db.commit()
            return row[3], row[4]

    def confirm_delivery(self, event_id: str, chunk_index: int, message_id: str) -> None:
        with self.connect() as db:
            cur = db.execute(
                "UPDATE deliveries SET state='sent',message_id=?,updated_at=? "
                "WHERE event_id=? AND chunk_index=? AND state IN ('prepared','sent') "
                "AND ambiguous_at IS NULL",
                (message_id, int(time.time()), event_id, chunk_index),
            )
            if cur.rowcount != 1:
                raise RuntimeError("delivery confirmation lost its prepared row")

    def begin_delivery_attempt(
        self, event_id: str, chunk_index: int, *, now: int | None = None
    ) -> tuple[bool, int]:
        """Durably cross the local side of the Discord POST boundary.

        Returns ``(first_attempt, attempted_at)``. Once this timestamp is old,
        callers must reconcile Discord history or fail closed rather than
        trusting Discord's short nonce de-duplication window.
        """

        timestamp = int(time.time()) if now is None else now
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT deliveries.state,deliveries.attempted_at,deliveries.ambiguous_at "
                "FROM deliveries JOIN delivery_manifests USING(event_id) "
                "WHERE deliveries.event_id=? AND deliveries.chunk_index=? "
                "AND delivery_manifests.policy_binding=?",
                (event_id, chunk_index, self.policy_binding),
            ).fetchone()
            if not row or row[0] != "prepared":
                db.rollback()
                raise RuntimeError("delivery attempt lost its prepared row")
            if row[2] is not None:
                db.rollback()
                raise RuntimeError("delivery attempt is quarantined as ambiguous")
            attempted_at = row[1]
            if attempted_at is None:
                db.execute(
                    "UPDATE deliveries SET attempted_at=?,updated_at=? "
                    "WHERE event_id=? AND chunk_index=? AND attempted_at IS NULL",
                    (timestamp, timestamp, event_id, chunk_index),
                )
                db.commit()
                return True, timestamp
            db.commit()
            return False, int(attempted_at)

    def mark_delivery_ambiguous(
        self, event_id: str, chunk_index: int, *, now: int | None = None
    ) -> None:
        timestamp = int(time.time()) if now is None else now
        with self.connect() as db:
            cur = db.execute(
                "UPDATE deliveries SET attempted_at=COALESCE(attempted_at,?),"
                "ambiguous_at=?,updated_at=? "
                "WHERE event_id=? AND chunk_index=? AND state IN ('prepared','sent') "
                "AND (attempted_at IS NOT NULL OR state='sent') "
                "AND ambiguous_at IS NULL",
                (timestamp, timestamp, timestamp, event_id, chunk_index),
            )
            if cur.rowcount != 1:
                raise RuntimeError("delivery ambiguity quarantine lost its prepared row")

    def clear_delivery_attempt(
        self, event_id: str, chunk_index: int, attempted_at: int
    ) -> None:
        """Reset an attempt after Discord definitively rejected the POST."""

        with self.connect() as db:
            cur = db.execute(
                "UPDATE deliveries SET attempted_at=NULL,updated_at=? "
                "WHERE event_id=? AND chunk_index=? AND state='prepared' "
                "AND attempted_at=? AND ambiguous_at IS NULL",
                (int(time.time()), event_id, chunk_index, attempted_at),
            )
            if cur.rowcount != 1:
                raise RuntimeError("delivery attempt reset lost its prepared row")

    def confirm_manifest(self, event_id: str) -> None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT chunk_count FROM delivery_manifests "
                "WHERE event_id=? AND policy_binding=?",
                (event_id, self.policy_binding),
            ).fetchone()
            if not row:
                db.rollback()
                raise RuntimeError("delivery manifest disappeared")
            sent = db.execute(
                "SELECT COUNT(*) FROM deliveries WHERE event_id=? AND state='sent' "
                "AND message_id IS NOT NULL AND ambiguous_at IS NULL",
                (event_id,),
            ).fetchone()[0]
            if sent != row[0]:
                db.rollback()
                raise RuntimeError("delivery manifest is not fully confirmed")
            db.execute(
                "UPDATE delivery_manifests SET state='sent',updated_at=? "
                "WHERE event_id=? AND policy_binding=?",
                (int(time.time()), event_id, self.policy_binding),
            )
            db.commit()

    def delivery_manifest(self, event_id: str):
        with self.connect() as db:
            manifest = db.execute(
                "SELECT destination_id,response_hash,chunk_count,state FROM delivery_manifests "
                "WHERE event_id=? AND policy_binding=?",
                (event_id, self.policy_binding),
            ).fetchone()
            if not manifest:
                return None
            chunks = db.execute(
                "SELECT chunk_index,nonce,content,content_hash,state,message_id,"
                "attempted_at,ambiguous_at FROM deliveries "
                "WHERE event_id=? ORDER BY chunk_index",
                (event_id,),
            ).fetchall()
            return (*manifest, chunks)

    def incomplete_manifest_ids(self) -> list[str]:
        with self.connect() as db:
            return [
                row[0]
                for row in db.execute(
                    "SELECT manifest.event_id FROM delivery_manifests AS manifest "
                    "WHERE manifest.state='prepared' AND manifest.policy_binding=? "
                    "AND NOT EXISTS (SELECT 1 FROM deliveries AS delivery "
                    "WHERE delivery.event_id=manifest.event_id "
                    "AND delivery.ambiguous_at IS NOT NULL) "
                    "ORDER BY manifest.updated_at,manifest.event_id",
                    (self.policy_binding,),
                )
            ]

    def quarantine_stale_jobs(self) -> tuple[int, int]:
        """Prevent jobs reserved under a prior configuration from executing."""

        now = int(time.time())
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cancelled = db.execute(
                "UPDATE jobs SET state='cancelled',updated_at=? "
                "WHERE state='queued' AND policy_binding<>?",
                (now, self.policy_binding),
            ).rowcount
            uncertain = db.execute(
                "UPDATE jobs SET state='uncertain',updated_at=? "
                "WHERE state='running' AND policy_binding<>?",
                (now, self.policy_binding),
            ).rowcount
            current_cursor_prefix = f"policy:{self.policy_binding}:"
            db.execute(
                "DELETE FROM channel_cursors WHERE channel_id NOT LIKE ?",
                (current_cursor_prefix + "%",),
            )
            current_managed_prefix = f"managed:{self.policy_binding}:"
            current_codex_prefix = f"codex:{self.policy_binding}:"
            db.execute(
                "DELETE FROM sessions WHERE "
                "(scope LIKE 'managed:%' AND scope NOT LIKE ?) OR "
                "(scope LIKE 'codex:%' AND scope NOT LIKE ?)",
                (current_managed_prefix + "%", current_codex_prefix + "%"),
            )
            db.commit()
            return cancelled, uncertain

    def deliveries_for(self, event_id: str):
        with self.connect() as db:
            return db.execute(
                "SELECT chunk_index,destination_id,nonce,content,content_hash,state,message_id FROM deliveries WHERE event_id=? ORDER BY chunk_index",
                (event_id,),
            ).fetchall()
