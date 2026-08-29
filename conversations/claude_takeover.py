#!/usr/bin/env python3
"""Fail-closed migration from the legacy Claude Discord runtime.

The takeover is deliberately split into three phases:

``prepare``
    Validate the exact legacy deployment, stop it in a fixed order, prove that
    its processes are gone, create a verified private backup, quarantine queue
    work whose side effects cannot be proven, and reconcile Discord messages
    through a captured maintenance boundary.

``begin-replacement``
    Freeze a queue baseline immediately before the replacement services may be
    started. This makes the automatic rollback decision evidence based.

``finalize``
    Prove the exact replacement listener, reconcile the overlap window, prove
    readiness again, and permanently commit the takeover.

``abort`` may restart the legacy runtime only while the queue proves that the
replacement has accepted no work. Once any row is added or any nonterminal row
changes, automatic rollback is forbidden.

This module never runs merely because it is imported. The destructive CLI
requires both ``--take-over-legacy`` and an exact maintenance phrase on stdin.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
import plistlib
import pwd
import re
import secrets
import shlex
import shutil
import signal
import sqlite3
import stat
import subprocess  # nosec B404
import sys
import tempfile
import time
import urllib.parse
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

import listener_contract

MAINTENANCE_PHRASE = (
    "I HAVE STOPPED POSTING AND AUTHORIZE LEGACY CLAUDE TAKEOVER"
)
LEGACY_SESSION = "cx-chat"
LEGACY_LABELS = (
    "com.thesystem.cx-chat-healthcheck",
    "com.thesystem.discord-gateway-client",
    "com.thesystem.discord-marker-watcher",
    "com.thesystem.cx-chat-queue-monitor",
    "com.thesystem.cx-chat-archive-sync",
)
LEGACY_STOP_ORDER = LEGACY_LABELS
HEALTHCHECK_LABEL = LEGACY_LABELS[0]
SNOWFLAKE = re.compile(r"^[1-9][0-9]{16,19}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
RECEIPT_VERSION = 1
MAX_STDIN_BYTES = 8192
MAX_DISCORD_PAGES_PER_CHANNEL = 10_000
DISCORD_PAGE_SIZE = 100
TAKEOVER_DRAIN_TTL_SECONDS = 15 * 60
# Public protocol marker, not a credential.
TAKEOVER_DRAIN_TOKEN_PREFIX = (  # nosec B105
    "THREADKEEP_TAKEOVER_DRAIN_COMPLETE_v1_4c18a7d2:"
)
TAKEOVER_DRAIN_CHALLENGE = re.compile(r"^[a-f0-9]{64}$")
DISPATCH_OPERATION_STATES = frozenset(
    {
        "prepared",
        "thread_create_attempted",
        "thread_confirmed",
        "conversation_ready",
        "turn_appended",
        "completed",
    }
)
REPLACEMENT_DISCORD_EGRESS_TOOLS = (
    "mcp__plugin_discord_discord__reply,"
    "mcp__plugin_discord_discord__edit_message,"
    "mcp__plugin_discord_discord__react,"
    "mcp__plugin_discord_discord__fetch_messages,"
    "mcp__plugin_discord_discord__download_attachment"
)

class TakeoverError(RuntimeError):
    """A takeover safety gate failed."""


class UnsafeRollback(TakeoverError):
    """The replacement accepted work, so the legacy runtime cannot restart."""


@dataclass(frozen=True)
class LegacyInventory:
    labels: tuple[str, ...]
    plist_paths: tuple[str, ...]
    plist_sha256s: tuple[str, ...]
    tmux_session: str
    pane_pid: int
    pane_pgid: int
    pane_command: str
    pane_cwd: str
    process_ids: tuple[int, ...]
    process_commands: tuple[str, ...]


@dataclass(frozen=True)
class QueueClassification:
    resumable: tuple[str, ...]
    quarantine: tuple[str, ...]
    blockers: tuple[str, ...]
    reasons: dict[str, str]


class Host(Protocol):
    def prove_replacement_absent(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
    ) -> None: ...

    def inspect_legacy(
        self, *, plist_dir: Path, workspace_root: Path
    ) -> LegacyInventory: ...

    def stop_label(self, label: str) -> None: ...

    def stop_legacy_session(self, inventory: LegacyInventory) -> None: ...

    def prove_legacy_stopped(self, inventory: LegacyInventory) -> None: ...

    def restart_legacy(self, inventory: LegacyInventory) -> None: ...

    def mark_gateway_session_fresh(self, path: Path, backup_dir: Path) -> None: ...

    def restore_gateway_state(self, path: Path, backup_dir: Path) -> None: ...

    def verify_replacement(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
    ) -> None: ...

    def run_takeover_drain(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
        challenge: str,
        issued_at: float,
        expires_at: float,
    ) -> float: ...

    def stop_replacement(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
    ) -> None: ...


class Discord(Protocol):
    def capture_upper(self, channel_ids: Sequence[str], lower: str) -> str: ...

    def messages_between(
        self, channel_id: str, lower: str, upper: str
    ) -> list[dict[str, Any]]: ...

    def add_eyes(self, channel_id: str, message_id: str) -> None: ...


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with _owned_binary_reader(path) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
    ):
        raise TakeoverError(f"unsafe takeover directory: {path}")
    os.chmod(path, 0o700, follow_symlinks=False)


@contextlib.contextmanager
def _receipt_transaction_lock(receipt_path: Path) -> Iterator[None]:
    """Serialize every post-prepare receipt transition across processes."""

    parent = receipt_path.parent
    metadata = parent.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise TakeoverError("takeover receipt directory is not private")
    lock_path = parent / ".takeover.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        lock_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_uid != os.getuid()
            or lock_metadata.st_nlink != 1
        ):
            raise TakeoverError("takeover lock is not a private regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TakeoverError("another takeover operation holds the lock") from exc
        yield
    finally:
        with contextlib.suppress(Exception):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _require_owned_real_directory_chain(root: Path, leaf: Path) -> None:
    root = root.expanduser().absolute()
    leaf = leaf.expanduser().absolute()
    if leaf != root and root not in leaf.parents:
        raise TakeoverError("takeover state is outside its configured workspace")
    current = root
    relative_parts = leaf.relative_to(root).parts
    for part in (None, *relative_parts):
        if part is not None:
            current = current / part
        metadata = current.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise TakeoverError(f"unsafe takeover directory ancestry: {current}")


def _require_owned_regular(path: Path, *, allow_missing: bool = False) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return False
        raise TakeoverError(f"required takeover file is missing: {path}") from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise TakeoverError(f"unsafe takeover source file: {path}")
    return True


@contextlib.contextmanager
def _owned_binary_reader(path: Path):
    """Open one owned regular file without following a swapped final symlink."""

    _require_owned_regular(path)
    expected = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    stream = os.fdopen(descriptor, "rb")
    try:
        opened = os.fstat(stream.fileno())
        identity = (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_nlink)
        expected_identity = (
            expected.st_dev,
            expected.st_ino,
            expected.st_uid,
            expected.st_nlink,
        )
        if (
            identity != expected_identity
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
        ):
            raise TakeoverError(f"takeover source changed while opening: {path}")
        yield stream
        after = os.fstat(stream.fileno())
        stable = (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            opened.st_nlink,
            opened.st_size,
            opened.st_mtime_ns,
        )
        if stable != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise TakeoverError(f"takeover source changed while reading: {path}")
    finally:
        stream.close()


def _private_copy(source: Path, destination: Path) -> None:
    _require_owned_regular(source)
    _ensure_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise TakeoverError(f"backup destination already exists: {destination}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        with (
            _owned_binary_reader(source) as input_stream,
            os.fdopen(descriptor, "wb", closefd=False) as output_stream,
        ):
            shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
            output_stream.flush()
            os.fsync(output_stream.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    os.chmod(destination, 0o600, follow_symlinks=False)


def _copy_tree_private(source: Path, destination: Path) -> None:
    metadata = source.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
    ):
        raise TakeoverError(f"unsafe takeover source directory: {source}")
    _ensure_private_directory(destination)
    for entry in sorted(os.scandir(source), key=lambda item: item.name):
        source_entry = Path(entry.path)
        destination_entry = destination / entry.name
        entry_metadata = source_entry.lstat()
        if stat.S_ISLNK(entry_metadata.st_mode):
            raise TakeoverError(f"takeover backup refuses symlink: {source_entry}")
        if stat.S_ISDIR(entry_metadata.st_mode):
            _copy_tree_private(source_entry, destination_entry)
        elif stat.S_ISREG(entry_metadata.st_mode):
            _private_copy(source_entry, destination_entry)
        else:
            raise TakeoverError(f"takeover backup refuses special file: {source_entry}")
    _fsync_directory(destination)


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    _ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(_canonical_json(payload) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600, follow_symlinks=False)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _read_private_json(path: Path) -> dict[str, Any]:
    _require_owned_regular(path)
    metadata = path.lstat()
    if stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_size > 5_000_000:
        raise TakeoverError(f"unsafe takeover control file: {path}")
    with _owned_binary_reader(path) as stream:
        raw = stream.read(5_000_001)
    if len(raw) > 5_000_000:
        raise TakeoverError(f"takeover control file is too large: {path}")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise TakeoverError("takeover receipt is not a JSON object")
    expected_digest = value.pop("receipt_sha256", None)
    actual_digest = hashlib.sha256(_canonical_json(value)).hexdigest()
    if expected_digest != actual_digest:
        raise TakeoverError("takeover receipt digest does not match")
    value["receipt_sha256"] = expected_digest
    if value.get("version") != RECEIPT_VERSION:
        raise TakeoverError("unsupported takeover receipt version")
    return value


def _save_receipt(path: Path, receipt: dict[str, Any]) -> None:
    value = dict(receipt)
    value.pop("receipt_sha256", None)
    value["receipt_sha256"] = hashlib.sha256(_canonical_json(value)).hexdigest()
    _write_private_json(path, value)


def _connect_existing_queue(
    path: Path, *, read_only: bool = False
) -> sqlite3.Connection:
    _require_owned_regular(path)
    target = str(path)
    uri = False
    if read_only:
        target = f"file:{urllib.parse.quote(str(path))}?mode=ro"
        uri = True
    connection = sqlite3.connect(
        target, uri=uri, timeout=30, isolation_level=None
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA foreign_keys=ON")
    check = connection.execute("PRAGMA quick_check").fetchone()
    if check is None or check[0] != "ok":
        connection.close()
        raise TakeoverError("legacy queue failed SQLite integrity check")
    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='messages'"
    ).fetchone()
    if table is None:
        connection.close()
        raise TakeoverError("legacy queue has no messages table")
    return connection


def _sqlite_backup(source: Path, destination: Path) -> None:
    _require_owned_regular(source)
    _ensure_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise TakeoverError("SQLite backup destination already exists")
    source_connection = sqlite3.connect(
        f"file:{urllib.parse.quote(str(source))}?mode=ro", uri=True, timeout=30
    )
    destination_connection = sqlite3.connect(str(destination), timeout=30)
    try:
        source_connection.backup(destination_connection)
        destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        check = destination_connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise TakeoverError("SQLite API backup failed integrity check")
    finally:
        source_connection.close()
        destination_connection.close()
    os.chmod(destination, 0o600, follow_symlinks=False)


def _manifest_files(root: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
            raise TakeoverError(f"unsafe file inside takeover backup: {path}")
        result.append(
            {
                "path": str(path.relative_to(root)),
                "bytes": metadata.st_size,
                "sha256": _sha256_file(path),
            }
        )
    return result


def create_backup(
    *,
    conversations_dir: Path,
    queue_db: Path,
    backup_root: Path,
    inventory: LegacyInventory,
    legacy_approval_root: Path | None,
    new_gateway_state: Path,
    takeover_id: str,
) -> Path:
    """Create a private, hash-manifested backup after legacy quiescence."""

    _ensure_private_directory(backup_root)
    backup_dir = backup_root / takeover_id
    if backup_dir.exists() or backup_dir.is_symlink():
        raise TakeoverError("takeover backup ID already exists")
    backup_dir.mkdir(mode=0o700)
    _sqlite_backup(queue_db, backup_dir / "sqlite" / "mq.sqlite3.snapshot")
    raw_dir = backup_dir / "sqlite" / "raw"
    _ensure_private_directory(raw_dir)
    for suffix in ("", "-wal", "-shm"):
        source = Path(str(queue_db) + suffix)
        if _require_owned_regular(source, allow_missing=True):
            _private_copy(source, raw_dir / source.name)

    for name in ("_registry.json", "INDEX.md"):
        source = conversations_dir / name
        if _require_owned_regular(source, allow_missing=True):
            _private_copy(source, backup_dir / "conversations" / name)
    for name in ("active", "archived", "state"):
        source = conversations_dir / name
        if source.exists():
            destination = backup_dir / "conversations" / name
            if name == "state":
                _ensure_private_directory(destination)
                for entry in sorted(os.scandir(source), key=lambda item: item.name):
                    if entry.name == "takeover-backups":
                        continue
                    path = Path(entry.path)
                    if path == queue_db or path.name in {
                        queue_db.name + "-wal",
                        queue_db.name + "-shm",
                    }:
                        continue
                    if path.is_dir() and not path.is_symlink():
                        _copy_tree_private(path, destination / path.name)
                    elif path.is_file() and not path.is_symlink():
                        _private_copy(path, destination / path.name)
                    else:
                        raise TakeoverError(f"unsafe state backup source: {path}")
            else:
                _copy_tree_private(source, destination)

    if legacy_approval_root is not None and legacy_approval_root.exists():
        _copy_tree_private(
            legacy_approval_root, backup_dir / "legacy-approval-state"
        )

    plist_backup = backup_dir / "legacy-plists"
    _ensure_private_directory(plist_backup)
    if len(inventory.plist_paths) != len(inventory.plist_sha256s):
        raise TakeoverError("legacy plist backup inventory is malformed")
    for raw_path, expected_sha256 in zip(
        inventory.plist_paths, inventory.plist_sha256s
    ):
        source = Path(raw_path)
        destination = plist_backup / source.name
        _private_copy(source, destination)
        if _sha256_file(destination) != expected_sha256:
            raise TakeoverError("legacy plist changed before its private backup")

    if _require_owned_regular(new_gateway_state, allow_missing=True):
        _private_copy(
            new_gateway_state, backup_dir / "new-gateway-state" / new_gateway_state.name
        )

    approval_inventory: list[dict[str, Any]] = []
    approval_backup = backup_dir / "legacy-approval-state"
    if approval_backup.exists():
        for path in sorted(approval_backup.rglob("*")):
            if path.is_file():
                approval_inventory.append(
                    {
                        "path": str(path.relative_to(approval_backup)),
                        "sha256": _sha256_file(path),
                        "disposition": "quarantined-never-imported",
                    }
                )
    _write_private_json(
        backup_dir / "legacy-approval-quarantine.json",
        {
            "takeover_id": takeover_id,
            "files": approval_inventory,
            "policy": "Legacy approval schemas are not imported into Threadkeep.",
        },
    )
    snapshot_path = backup_dir / "sqlite" / "mq.sqlite3.snapshot"
    snapshot_connection = sqlite3.connect(
        f"file:{urllib.parse.quote(str(snapshot_path))}?mode=ro&immutable=1",
        uri=True,
    )
    snapshot_connection.row_factory = sqlite3.Row
    try:
        nonterminal_rows = [
            dict(row)
            for row in snapshot_connection.execute(
                "SELECT rowid,* FROM messages WHERE state NOT IN ('done','errored') "
                "ORDER BY rowid"
            )
        ]
        operation_rows: list[dict[str, Any]] = []
        if snapshot_connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='dispatch_operations'"
        ).fetchone():
            operation_rows = [
                dict(row)
                for row in snapshot_connection.execute(
                    "SELECT * FROM dispatch_operations ORDER BY message_id"
                )
            ]
    finally:
        snapshot_connection.close()
    _write_private_json(
        backup_dir / "queue-nonterminal-snapshot.json",
        {
            "takeover_id": takeover_id,
            "messages": nonterminal_rows,
            "dispatch_operations": operation_rows,
            "snapshot_sha256": hashlib.sha256(
                _canonical_json(
                    {"messages": nonterminal_rows, "operations": operation_rows}
                )
            ).hexdigest(),
        },
    )
    manifest = {
        "version": 1,
        "takeover_id": takeover_id,
        "created_at": time.time(),
        "conversations_dir": str(conversations_dir),
        "queue_db": str(queue_db),
        "files": _manifest_files(backup_dir),
    }
    _write_private_json(backup_dir / "manifest.json", manifest)
    _fsync_directory(backup_dir)
    return backup_dir


def verify_backup(backup_dir: Path) -> None:
    manifest_path = backup_dir / "manifest.json"
    with _owned_binary_reader(manifest_path) as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        raise TakeoverError("backup manifest is invalid")
    expected = manifest.get("files")
    if not isinstance(expected, list):
        raise TakeoverError("backup manifest has no file inventory")
    actual = _manifest_files(backup_dir)
    if expected != actual:
        raise TakeoverError("takeover backup hash manifest does not verify")
    snapshot = backup_dir / "sqlite" / "mq.sqlite3.snapshot"
    connection = sqlite3.connect(
        f"file:{urllib.parse.quote(str(snapshot))}?mode=ro&immutable=1", uri=True
    )
    try:
        row = connection.execute("PRAGMA quick_check").fetchone()
        if row is None or row[0] != "ok":
            raise TakeoverError("verified SQLite snapshot is corrupt")
    finally:
        connection.close()


def classify_queue(connection: sqlite3.Connection) -> QueueClassification:
    op_table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='dispatch_operations'"
    ).fetchone()
    operation_states: dict[str, str] = {}
    if op_table is not None:
        operation_states = {
            str(row["message_id"]): str(row["state"])
            for row in connection.execute(
                "SELECT message_id,state FROM dispatch_operations"
            )
        }
    resumable: list[str] = []
    quarantine: list[str] = []
    blockers: list[str] = []
    reasons: dict[str, str] = {}
    for row in connection.execute(
        "SELECT * FROM messages WHERE state NOT IN ('done','errored') "
        "ORDER BY rowid"
    ):
        message_id = str(row["message_id"])
        if not SNOWFLAKE.fullmatch(message_id):
            raise TakeoverError("legacy queue contains an invalid message ID")
        state = str(row["state"])
        operation_state = operation_states.get(message_id)
        if state == "received":
            resumable.append(message_id)
            reasons[message_id] = "received before any dispatch side effect"
        elif state == "claimed" and operation_state in DISPATCH_OPERATION_STATES:
            resumable.append(message_id)
            reasons[message_id] = f"claimed with operation state {operation_state}"
        elif state == "claimed" and operation_state is not None:
            blockers.append(message_id)
            reasons[message_id] = (
                f"claimed with unknown operation state {operation_state}"
            )
        elif state == "claimed":
            quarantine.append(message_id)
            reasons[message_id] = "legacy claim has no operation ledger"
        elif state == "dispatched":
            quarantine.append(message_id)
            reasons[message_id] = "legacy worker launch is ambiguous"
        elif state == "spawned":
            blockers.append(message_id)
            reasons[message_id] = (
                "spawned work requires manual response and side-effect reconciliation"
            )
        else:
            blockers.append(message_id)
            reasons[message_id] = f"unknown nonterminal state {state}"
    return QueueClassification(
        tuple(resumable), tuple(quarantine), tuple(blockers), reasons
    )


def queue_takeover_plan(connection: sqlite3.Connection) -> dict[str, Any]:
    """Return count-bound authorization text and a full nonterminal digest."""

    classification = classify_queue(connection)
    claimed_without_ledger = 0
    dispatched = 0
    spawned_blockers = 0
    other_blockers = 0
    for message_id in classification.quarantine:
        row = connection.execute(
            "SELECT state FROM messages WHERE message_id=?", (message_id,)
        ).fetchone()
        if row is None:
            raise TakeoverError("queue row disappeared while building takeover plan")
        if row["state"] == "claimed":
            claimed_without_ledger += 1
        elif row["state"] == "dispatched":
            dispatched += 1
        else:
            raise TakeoverError("takeover quarantine plan contains an unknown state")
    for message_id in classification.blockers:
        row = connection.execute(
            "SELECT state FROM messages WHERE message_id=?", (message_id,)
        ).fetchone()
        if row is None:
            raise TakeoverError("queue blocker disappeared while building takeover plan")
        if row["state"] == "spawned":
            spawned_blockers += 1
        else:
            other_blockers += 1
    operations: list[dict[str, Any]] = []
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='dispatch_operations'"
    ).fetchone():
        operations = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM dispatch_operations ORDER BY message_id"
            )
        ]
    nonterminal = [
        dict(row)
        for row in connection.execute(
            "SELECT rowid,* FROM messages WHERE state NOT IN ('done','errored') "
            "ORDER BY rowid"
        )
    ]
    snapshot_sha256 = hashlib.sha256(
        _canonical_json({"messages": nonterminal, "operations": operations})
    ).hexdigest()
    acknowledgment = (
        f"QUARANTINE {claimed_without_ledger} CLAIMED-WITHOUT-LEDGER AND "
        f"{dispatched} DISPATCHED ROWS FOR MANUAL REVIEW"
    )
    return {
        "version": 1,
        "claimed_without_ledger": claimed_without_ledger,
        "dispatched": dispatched,
        "hard_blockers": len(classification.blockers),
        "spawned_blockers": spawned_blockers,
        "other_blockers": other_blockers,
        "resumable": len(classification.resumable),
        "quarantine": len(classification.quarantine),
        "snapshot_sha256": snapshot_sha256,
        "acknowledgment": acknowledgment,
    }


def quarantine_ambiguous(
    connection: sqlite3.Connection,
    classification: QueueClassification,
    *,
    takeover_id: str,
) -> None:
    if classification.blockers:
        raise TakeoverError(
            "takeover has hard queue blockers: "
            + ", ".join(classification.blockers)
        )
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS takeover_quarantine (
                message_id TEXT PRIMARY KEY,
                takeover_id TEXT NOT NULL,
                original_state TEXT NOT NULL,
                original_row_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                quarantined_at REAL NOT NULL
            )
            """
        )
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(messages)")
        }
        for message_id in classification.quarantine:
            row = connection.execute(
                "SELECT rowid,* FROM messages WHERE message_id=?", (message_id,)
            ).fetchone()
            if row is None:
                raise TakeoverError("queue row disappeared during quarantine")
            encoded = json.dumps(dict(row), sort_keys=True, separators=(",", ":"))
            existing = connection.execute(
                "SELECT takeover_id,original_row_json FROM takeover_quarantine "
                "WHERE message_id=?",
                (message_id,),
            ).fetchone()
            if existing is not None:
                if existing["takeover_id"] != takeover_id or existing[
                    "original_row_json"
                ] != encoded:
                    raise TakeoverError("queue quarantine binding changed")
                continue
            connection.execute(
                "INSERT INTO takeover_quarantine "
                "(message_id,takeover_id,original_state,original_row_json,reason,quarantined_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    message_id,
                    takeover_id,
                    row["state"],
                    encoded,
                    classification.reasons[message_id],
                    time.time(),
                ),
            )
            quarantine_error = (
                "Takeover quarantine: " + classification.reasons[message_id]
            )
            quarantine_time = time.time()
            if "dead_letter_acked_at" in columns:
                cursor = connection.execute(
                    "UPDATE messages SET state='errored',error=?,updated_at=?,"
                    "dead_letter_acked_at=NULL WHERE message_id=? AND state=?",
                    (quarantine_error, quarantine_time, message_id, row["state"]),
                )
            else:
                cursor = connection.execute(
                    "UPDATE messages SET state='errored',error=?,updated_at=? "
                    "WHERE message_id=? AND state=?",
                    (quarantine_error, quarantine_time, message_id, row["state"]),
                )
            if cursor.rowcount != 1:
                raise TakeoverError("queue quarantine lost its immutable row")
        connection.execute("COMMIT")
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            connection.execute("ROLLBACK")
        raise


def restore_quarantine(connection: sqlite3.Connection, takeover_id: str) -> None:
    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='takeover_quarantine'"
    ).fetchone()
    if table is None:
        return
    rows = connection.execute(
        "SELECT * FROM takeover_quarantine WHERE takeover_id=? ORDER BY message_id",
        (takeover_id,),
    ).fetchall()
    connection.execute("BEGIN IMMEDIATE")
    try:
        for quarantine in rows:
            original = json.loads(quarantine["original_row_json"])
            current = connection.execute(
                "SELECT state,error FROM messages WHERE message_id=?",
                (quarantine["message_id"],),
            ).fetchone()
            expected_error = "Takeover quarantine: " + quarantine["reason"]
            if (
                current is None
                or current["state"] != "errored"
                or current["error"] != expected_error
            ):
                raise UnsafeRollback(
                    "a quarantined queue row changed after replacement preparation"
                )
            update_columns = [
                key
                for key in original
                if key != "rowid" and key not in {"message_id"}
            ]
            assignments = ",".join(f"{column}=?" for column in update_columns)
            # update_columns comes only from SQLite's own table schema and the
            # private frozen row. Every data value remains parameterized.
            connection.execute(
                f"UPDATE messages SET {assignments} WHERE message_id=?",  # nosec B608
                tuple(original[column] for column in update_columns)
                + (quarantine["message_id"],),
            )
            connection.execute(
                "DELETE FROM takeover_quarantine WHERE message_id=? AND takeover_id=?",
                (quarantine["message_id"], takeover_id),
            )
        connection.execute("COMMIT")
    except Exception:
        with contextlib.suppress(sqlite3.Error):
            connection.execute("ROLLBACK")
        raise


def _registry_threads(conversations_dir: Path, root_channel: str) -> list[str]:
    if not SNOWFLAKE.fullmatch(root_channel):
        raise TakeoverError("root Discord channel ID is invalid")
    registry_path = conversations_dir / "_registry.json"
    _require_owned_regular(registry_path)
    with _owned_binary_reader(registry_path) as stream:
        value = json.load(stream)
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("by_thread"), dict)
        or not isinstance(value.get("conversations"), dict)
    ):
        raise TakeoverError("conversation registry indexes are malformed")
    channel_ids = {root_channel}
    by_thread = value["by_thread"]
    conversations = value["conversations"]
    for thread_id, session_id in by_thread.items():
        normalized = str(thread_id)
        if not SNOWFLAKE.fullmatch(normalized):
            raise TakeoverError("conversation registry contains an invalid thread ID")
        conversation = conversations.get(str(session_id))
        if (
            not isinstance(session_id, str)
            or not isinstance(conversation, dict)
            or str(conversation.get("thread_id") or "") != normalized
        ):
            raise TakeoverError("conversation registry reverse index is inconsistent")
        channel_ids.add(normalized)
    for session_id, conversation in conversations.items():
        if not isinstance(session_id, str) or not isinstance(conversation, dict):
            raise TakeoverError("conversation registry entry is malformed")
        thread_id = str(conversation.get("thread_id") or "")
        if thread_id and by_thread.get(thread_id) != session_id:
            raise TakeoverError("conversation registry forward index is inconsistent")
    return sorted(channel_ids, key=int)


def _global_lower(
    connection: sqlite3.Connection, channel_ids: Sequence[str]
) -> str:
    """Return one lower bound that cannot skip a quieter registered channel."""

    if not channel_ids or any(
        not SNOWFLAKE.fullmatch(channel_id) for channel_id in channel_ids
    ):
        raise TakeoverError("Discord reconciliation channels are invalid")
    # A channel/thread snowflake predates every message posted within it. It is
    # therefore the conservative cursor for a registered channel with no queue
    # rows. For channels with rows, use their own newest durable message. The
    # minimum of those per-channel cursors is the only single global boundary
    # that cannot skip a message in a quieter thread.
    cursors = {channel_id: int(channel_id) for channel_id in channel_ids}
    for row in connection.execute("SELECT message_id,chat_id FROM messages"):
        message_id = str(row["message_id"])
        if not SNOWFLAKE.fullmatch(message_id):
            raise TakeoverError("legacy queue contains an invalid message ID")
        channel_id = str(row["chat_id"])
        if channel_id in cursors:
            cursors[channel_id] = max(cursors[channel_id], int(message_id))
    return str(min(cursors.values()))


def _render_reconciled_body(message: dict[str, Any]) -> str:
    content = message.get("content")
    if not isinstance(content, str):
        raise TakeoverError("Discord message content is not text")
    lines = [content] if content else []
    attachments = message.get("attachments") or []
    if not isinstance(attachments, list):
        raise TakeoverError("Discord message attachments are malformed")
    for attachment in attachments:
        if not isinstance(attachment, dict):
            raise TakeoverError("Discord attachment is not an object")
        attachment_id = str(attachment.get("id") or "")
        filename = str(attachment.get("filename") or "")
        url = str(attachment.get("url") or "")
        if not SNOWFLAKE.fullmatch(attachment_id) or not filename or not url.startswith(
            "https://"
        ):
            raise TakeoverError("Discord attachment metadata is incomplete")
        lines.append(f"[Discord attachment: {filename} | {url}]")
    return "\n".join(lines)


def _reconciled_payload_binding(message: dict[str, Any]) -> dict[str, Any]:
    """Bind durable message semantics while excluding volatile reactions."""

    author = message.get("author")
    attachments = message.get("attachments") or []
    if not isinstance(author, dict) or not isinstance(attachments, list):
        raise TakeoverError("Discord replay payload binding is malformed")
    stable_attachments: list[dict[str, Any]] = []
    for attachment in attachments:
        if not isinstance(attachment, dict):
            raise TakeoverError("Discord replay attachment binding is malformed")
        stable_attachments.append(
            {
                key: attachment.get(key)
                for key in ("id", "filename", "size", "content_type")
            }
        )
    return {
        "id": message.get("id"),
        "channel_id": message.get("channel_id"),
        "content": message.get("content"),
        "timestamp": message.get("timestamp"),
        "edited_timestamp": message.get("edited_timestamp"),
        "type": message.get("type"),
        "author": {
            "id": author.get("id"),
            "bot": author.get("bot"),
        },
        "attachments": stable_attachments,
    }


def _record_reconciled_payload(
    connection: sqlite3.Connection,
    *,
    message: dict[str, Any],
    channel_id: str,
    upper: str,
    takeover_id: str,
    inserted: bool,
) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS takeover_reconciled_messages (
            message_id TEXT PRIMARY KEY,
            takeover_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            window_upper TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            inserted INTEGER NOT NULL CHECK(inserted IN (0,1)),
            recorded_at REAL NOT NULL
        )
        """
    )
    encoded = _canonical_json(message)
    binding = _canonical_json(_reconciled_payload_binding(message))
    digest = hashlib.sha256(binding).hexdigest()
    existing = connection.execute(
        "SELECT channel_id,payload_sha256 FROM takeover_reconciled_messages "
        "WHERE message_id=?",
        (message["id"],),
    ).fetchone()
    if existing is not None:
        if existing["channel_id"] != channel_id or existing["payload_sha256"] != digest:
            raise TakeoverError("Discord replay changed a recorded message")
        return
    connection.execute(
        "INSERT INTO takeover_reconciled_messages "
        "(message_id,takeover_id,channel_id,window_upper,payload_json,payload_sha256,inserted,recorded_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (
            message["id"],
            takeover_id,
            channel_id,
            upper,
            encoded.decode("utf-8"),
            digest,
            1 if inserted else 0,
            time.time(),
        ),
    )


def _enqueue_reconciled(
    connection: sqlite3.Connection,
    *,
    message: dict[str, Any],
    channel_id: str,
    root_channel: str,
    owner_user_id: str,
    lower: str,
    upper: str,
    takeover_id: str,
) -> bool:
    message_id = str(message.get("id") or "")
    if not SNOWFLAKE.fullmatch(message_id):
        raise TakeoverError("Discord replay returned an invalid message ID")
    if not int(lower) < int(message_id) <= int(upper):
        raise TakeoverError("Discord replay crossed its captured bounds")
    if str(message.get("channel_id") or "") != channel_id:
        raise TakeoverError("Discord replay returned the wrong channel")
    author = message.get("author")
    if not isinstance(author, dict):
        raise TakeoverError("Discord replay returned no author")
    author_id = str(author.get("id") or "")
    if author_id != owner_user_id or author.get("bot") is True:
        return False
    body = _render_reconciled_body(message)
    existing = connection.execute(
        "SELECT chat_id,acked_at FROM messages WHERE message_id=?", (message_id,)
    ).fetchone()
    inserted = existing is None
    if existing is not None:
        if str(existing["chat_id"]) != channel_id:
            raise TakeoverError("existing queue row conflicts with Discord channel")
    else:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(messages)")
        }
        required = {
            "message_id",
            "chat_id",
            "user",
            "ts",
            "body",
            "kind",
            "state",
            "received_at",
            "updated_at",
        }
        if not required <= columns:
            raise TakeoverError("legacy queue schema cannot accept reconciled messages")
        timestamp = str(message.get("timestamp") or "")
        display_name = str(
            message.get("member", {}).get("nick")
            if isinstance(message.get("member"), dict)
            else ""
        ) or str(author.get("global_name") or author.get("username") or owner_user_id)
        now = time.time()
        connection.execute(
            "INSERT INTO messages "
            "(message_id,chat_id,user,ts,body,kind,state,received_at,updated_at) "
            "VALUES(?,?,?,?,?,?,'received',?,?)",
            (
                message_id,
                channel_id,
                display_name,
                timestamp,
                body,
                "top-level" if channel_id == root_channel else "reply",
                now,
                now,
            ),
        )
    _record_reconciled_payload(
        connection,
        message=message,
        channel_id=channel_id,
        upper=upper,
        takeover_id=takeover_id,
        inserted=inserted,
    )
    return inserted


def reconcile_window(
    connection: sqlite3.Connection,
    discord: Discord,
    *,
    channel_ids: Sequence[str],
    root_channel: str,
    owner_user_id: str,
    lower: str,
    upper: str,
    takeover_id: str,
) -> tuple[str, ...]:
    if (
        not SNOWFLAKE.fullmatch(owner_user_id)
        or not SNOWFLAKE.fullmatch(lower)
        or not SNOWFLAKE.fullmatch(upper)
        or int(lower) > int(upper)
    ):
        raise TakeoverError("Discord reconciliation boundary is invalid")
    inserted_ids: list[str] = []
    for channel_id in channel_ids:
        messages = discord.messages_between(channel_id, lower, upper)
        for message in sorted(messages, key=lambda item: int(str(item.get("id") or 0))):
            connection.execute("BEGIN IMMEDIATE")
            try:
                inserted = _enqueue_reconciled(
                    connection,
                    message=message,
                    channel_id=channel_id,
                    root_channel=root_channel,
                    owner_user_id=owner_user_id,
                    lower=lower,
                    upper=upper,
                    takeover_id=takeover_id,
                )
                connection.execute("COMMIT")
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise
            message_id = str(message.get("id") or "")
            author = message.get("author") or {}
            owner_message = (
                str(author.get("id") or "") == owner_user_id
                and author.get("bot") is not True
            )
            if not owner_message:
                continue
            row = connection.execute(
                "SELECT acked_at FROM messages WHERE message_id=?", (message_id,)
            ).fetchone()
            if row is None:
                raise TakeoverError("owner message disappeared after reconciliation")
            if row["acked_at"] is None:
                discord.add_eyes(channel_id, message_id)
                cursor = connection.execute(
                    "UPDATE messages SET acked_at=COALESCE(acked_at,?),updated_at=? "
                    "WHERE message_id=?",
                    (time.time(), time.time(), message_id),
                )
                if cursor.rowcount != 1:
                    raise TakeoverError("reconciled message disappeared before ack")
            if inserted:
                inserted_ids.append(message_id)
    return tuple(sorted(set(inserted_ids), key=int))


def queue_baseline(connection: sqlite3.Connection) -> dict[str, Any]:
    max_rowid = connection.execute("SELECT COALESCE(MAX(rowid),0) FROM messages").fetchone()[
        0
    ]
    nonterminal = {
        str(row["message_id"]): {
            "state": str(row["state"]),
            "updated_at": row["updated_at"],
        }
        for row in connection.execute(
            "SELECT message_id,state,updated_at FROM messages "
            "WHERE state NOT IN ('done','errored') ORDER BY message_id"
        )
    }
    return {"max_rowid": int(max_rowid), "nonterminal": nonterminal}


def replacement_accepted_work(
    connection: sqlite3.Connection, baseline: dict[str, Any]
) -> bool:
    max_rowid = int(baseline.get("max_rowid", -1))
    if connection.execute(
        "SELECT 1 FROM messages WHERE rowid>? LIMIT 1", (max_rowid,)
    ).fetchone():
        return True
    expected = baseline.get("nonterminal")
    if not isinstance(expected, dict):
        raise TakeoverError("takeover baseline is malformed")
    for message_id, frozen in expected.items():
        row = connection.execute(
            "SELECT state,updated_at FROM messages WHERE message_id=?", (message_id,)
        ).fetchone()
        if row is None:
            return True
        if row["state"] != frozen.get("state") or row["updated_at"] != frozen.get(
            "updated_at"
        ):
            return True
    return False


def safe_pre_dispatch_backlog(
    connection: sqlite3.Connection,
) -> list[dict[str, str]]:
    """Return work that a new listener must resume before takeover commit."""

    return [
        {"message_id": str(row["message_id"]), "state": str(row["state"])}
        for row in connection.execute(
            "SELECT message_id,state FROM messages "
            "WHERE state NOT IN ('done','errored','spawned') "
            "ORDER BY received_at,rowid"
        )
    ]


class DiscordREST:
    """Narrow direct Discord client used only for takeover reconciliation."""

    def __init__(self, token: str) -> None:
        token = token.strip()
        if not token or len(token) > 4096 or any(character.isspace() for character in token):
            raise TakeoverError("Discord bot credential is malformed")
        self._token = token
        try:
            from discord_http import request, require_direct_discord_transport  # gitleaks:allow - module import, not a credential.
        except ImportError:
            from conversations.discord_http import (  # type: ignore
                request,
                require_direct_discord_transport,
            )
        require_direct_discord_transport()
        self._request = request

    def _list(self, path: str) -> list[dict[str, Any]]:
        _, raw = self._request("GET", path, self._token, timeout=30, max_attempts=4)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TakeoverError("Discord message list is not JSON") from exc
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise TakeoverError("Discord message list has an invalid shape")
        return value

    def capture_upper(self, channel_ids: Sequence[str], lower: str) -> str:
        maximum = int(lower)
        for channel_id in channel_ids:
            messages = self._list(f"/channels/{channel_id}/messages?limit=1")
            for message in messages:
                message_id = str(message.get("id") or "")
                if not SNOWFLAKE.fullmatch(message_id):
                    raise TakeoverError("Discord latest-message boundary is invalid")
                maximum = max(maximum, int(message_id))
        return str(maximum)

    def messages_between(
        self, channel_id: str, lower: str, upper: str
    ) -> list[dict[str, Any]]:
        # Discord returns channel history newest first. Walk backward from one
        # greater than the frozen upper bound so a window larger than 100
        # messages cannot skip the older portion of the maintenance gap.
        before = str(int(upper) + 1)
        collected: dict[str, dict[str, Any]] = {}
        for _ in range(MAX_DISCORD_PAGES_PER_CHANNEL):
            query = urllib.parse.urlencode(
                {"limit": DISCORD_PAGE_SIZE, "before": before}
            )
            page = self._list(f"/channels/{channel_id}/messages?{query}")
            if not page:
                break
            page_min = int(before)
            for message in page:
                message_id = str(message.get("id") or "")
                if not SNOWFLAKE.fullmatch(message_id):
                    raise TakeoverError("Discord history contains an invalid ID")
                numeric = int(message_id)
                page_min = min(page_min, numeric)
                if int(lower) < numeric <= int(upper):
                    if message_id in collected and collected[message_id] != message:
                        raise TakeoverError("Discord history changed during pagination")
                    collected[message_id] = message
            if page_min >= int(before):
                raise TakeoverError("Discord history pagination did not advance")
            before = str(page_min)
            if page_min <= int(lower) or len(page) < DISCORD_PAGE_SIZE:
                break
        else:
            raise TakeoverError("Discord history exceeded the takeover page limit")
        return [collected[key] for key in sorted(collected, key=int)]

    def add_eyes(self, channel_id: str, message_id: str) -> None:
        encoded = urllib.parse.quote("👀", safe="")
        status, _ = self._request(
            "PUT",
            f"/channels/{channel_id}/messages/{message_id}/reactions/{encoded}/@me",
            self._token,
            timeout=30,
            max_attempts=4,
        )
        if status not in {200, 204}:
            raise TakeoverError("Discord did not confirm the reconciliation reaction")


def _run(
    argv: Sequence[str], *, timeout: float = 30, check: bool = True
) -> subprocess.CompletedProcess[str]:
    # Every caller supplies a fixed executable and option vector. No shell is
    # used and no Discord content reaches argv.
    result = subprocess.run(  # nosec B603
        list(argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={
            "HOME": pwd.getpwuid(os.getuid()).pw_dir,
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "USER": os.environ.get("USER", ""),
            "LOGNAME": os.environ.get("LOGNAME", ""),
        },
    )
    if check and result.returncode != 0:
        raise TakeoverError(f"system command failed: {Path(argv[0]).name}")
    return result


def _expected_legacy_program_arguments(
    label: str, workspace_root: Path
) -> list[str]:
    assistant = workspace_root / "x_System/Assistant"
    python = "/opt/homebrew/bin/python3"
    values = {
        "com.thesystem.cx-chat-healthcheck": [
            str(assistant / "scripts/healthcheck/cx-chat-healthcheck.sh")
        ],
        "com.thesystem.discord-gateway-client": [
            python,
            str(assistant / "discord-gateway/client.py"),
        ],
        "com.thesystem.discord-marker-watcher": [
            python,
            str(assistant / "discord-gateway/marker-watcher.py"),
        ],
        "com.thesystem.cx-chat-queue-monitor": [
            python,
            str(assistant / "conversations/scripts/queue/monitor.py"),
        ],
        "com.thesystem.cx-chat-archive-sync": [
            str(assistant / "scripts/run-cron.sh"),
            "cx-chat-archive-sync",
            "EXEC "
            + python
            + " "
            + str(assistant / "conversations/scripts/sync-discord-archive-state.py"),
        ],
    }
    return values[label]


def _exact_legacy_listener_command(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if tokens and tokens[0] == "exec":
        tokens = tokens[1:]
    executable = tokens[0] if tokens else ""
    reviewed_executable = Path(executable).name == "claude" or executable.endswith(
        "/.local/share/claude/versions/2.1.251"
    )
    return (
        len(tokens) == 4
        and reviewed_executable
        and tokens[1:] == [
            "--dangerously-skip-permissions",
            "--channels",
            "plugin:discord@claude-plugins-official",
        ]
    )


def _reviewed_legacy_descendant(command: str) -> bool:
    if _exact_legacy_listener_command(command):
        return True
    lowered = command.lower()
    executable = Path(command.split(None, 1)[0]).name.lower() if command.split() else ""
    if (
        "claude/versions/2.1.251" in lowered
        and "--channels plugin:discord@claude-plugins-official" in lowered
    ):
        return True
    return executable in {"bun", "node"} and "discord" in lowered and (
        "claude-plugins-official" in lowered
        or "application support/threadkeep/claude-discord" in lowered
        or ".claude/plugins" in lowered
    )


def _expected_replacement_arguments(
    repo_root: Path, workspace_root: Path
) -> list[str]:
    expected_binary = str(
        Path(pwd.getpwuid(os.getuid()).pw_dir)
        / ".local/share/claude/versions/2.1.251"
    )
    return [
        expected_binary,
        "--dangerously-skip-permissions",
        "--permission-mode",
        "bypassPermissions",
        "--channels",
        "plugin:discord@claude-plugins-official",
        "--append-system-prompt-file",
        str(
            (
                Path(pwd.getpwuid(os.getuid()).pw_dir)
                / "Library/Application Support/Threadkeep/claude-discord"
                / listener_contract.POLICY_DIRECTORY_NAME
                / listener_contract.RUNTIME_PROMPT_NAME
            ).resolve()
        ),
        "--append-subagent-system-prompt",
        listener_contract.SUBAGENT_POLICY_PROMPT,
        "--add-dir",
        str(repo_root.resolve()),
        "--add-dir",
        str(workspace_root.resolve()),
        "--strict-mcp-config",
        "--setting-sources",
        "",
        "--no-chrome",
        "--disallowedTools",
        REPLACEMENT_DISCORD_EGRESS_TOOLS,
    ]


def _reviewed_replacement_listener(
    command: str, repo_root: Path, workspace_root: Path
) -> bool:
    """Compatibility check for flattened ps text used by read-only plans."""

    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    # macOS ps loses the empty setting-sources argv and does not quote spaces.
    # This helper is never sufficient for an action gate. Action gates use
    # KERN_PROCARGS2 through _reviewed_replacement_arguments below.
    expected = _expected_replacement_arguments(repo_root, workspace_root)
    expected.remove("")
    return tokens == expected


def _reviewed_replacement_arguments(
    arguments: Sequence[str], repo_root: Path, workspace_root: Path
) -> bool:
    return list(arguments) == _expected_replacement_arguments(
        repo_root, workspace_root
    )


class MacHost:
    def __init__(self) -> None:
        self.launchctl = "/bin/launchctl"
        discovered_tmux = shutil.which(
            "tmux", path="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        )
        if discovered_tmux is None:
            raise TakeoverError("tmux is unavailable on the fixed system path")
        resolved_tmux = Path(discovered_tmux).resolve()
        tmux_metadata = resolved_tmux.stat()
        if (
            not stat.S_ISREG(tmux_metadata.st_mode)
            or tmux_metadata.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(tmux_metadata.st_mode) & 0o022
        ):
            raise TakeoverError("tmux executable metadata is unsafe")
        self.tmux = str(resolved_tmux)
        self.ps = "/bin/ps"

    def _loaded(self, label: str) -> bool:
        return (
            _run(
                [self.launchctl, "print", f"gui/{os.getuid()}/{label}"],
                check=False,
            ).returncode
            == 0
        )

    def prove_replacement_absent(
        self, *, label_prefix: str, session: str, repo_root: Path
    ) -> None:
        if not SAFE_ID.fullmatch(label_prefix) or not SAFE_ID.fullmatch(session):
            raise TakeoverError("replacement identity is invalid")
        for component in ("cx-chat-healthcheck", "discord-gateway-client"):
            label = f"{label_prefix}.{component}"
            if self._loaded(label):
                raise TakeoverError(
                    f"replacement service is already loaded before takeover: {label}"
                )
        if (
            _run([self.tmux, "has-session", "-t", f"={session}"], check=False).returncode
            == 0
        ):
            raise TakeoverError("replacement tmux session is already running")
        launcher = str((repo_root / "cx-launcher.sh").resolve())
        listener_prompt = str((repo_root / "cx-chat-listener/CLAUDE.md").resolve())
        gateway_client = str((repo_root / "discord-gateway/client.py").resolve())
        for pid, _, _, command in self._process_table():
            if pid != os.getpid() and (
                launcher in command
                or listener_prompt in command
                or gateway_client in command
            ):
                raise TakeoverError("replacement process exists before takeover")

    def _read_plist(self, path: Path, label: str, workspace_root: Path) -> str:
        _require_owned_regular(path)
        with _owned_binary_reader(path) as stream:
            raw = stream.read()
        value = plistlib.loads(raw)
        arguments = value.get("ProgramArguments")
        environment = value.get("EnvironmentVariables", {})
        dangerous_environment = {
            "BASH_ENV",
            "ENV",
            "PYTHONINSPECT",
            "PYTHONSTARTUP",
            "ZDOTDIR",
        }
        if (
            value.get("Label") != label
            or not isinstance(arguments, list)
            or any(not isinstance(argument, str) for argument in arguments)
            or arguments
            != _expected_legacy_program_arguments(label, workspace_root)
            or not isinstance(environment, dict)
            or any(
                not isinstance(key, str)
                or not isinstance(item, str)
                or key in dangerous_environment
                or key.startswith("DYLD_")
                for key, item in environment.items()
            )
        ):
            raise TakeoverError(f"legacy plist is not the reviewed service: {label}")
        expected_working_directory = (
            None
            if label == "com.thesystem.cx-chat-healthcheck"
            else str(workspace_root)
        )
        if value.get("WorkingDirectory") != expected_working_directory:
            raise TakeoverError(
                f"legacy plist working directory is not reviewed: {label}"
            )
        return hashlib.sha256(raw).hexdigest()

    def _process_table(self) -> list[tuple[int, int, int, str]]:
        result = _run([self.ps, "-axo", "pid=,ppid=,pgid=,command="])
        rows: list[tuple[int, int, int, str]] = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) != 4 or not all(part.isdigit() for part in parts[:3]):
                continue
            rows.append((int(parts[0]), int(parts[1]), int(parts[2]), parts[3]))
        return rows

    @staticmethod
    def _process_arguments(pid: int) -> tuple[str, ...]:
        """Read exact NUL-separated argv from macOS KERN_PROCARGS2."""

        if sys.platform != "darwin" or pid <= 0:
            raise TakeoverError("exact process argv is unavailable on this host")
        control_kern = 1
        kern_procargs2 = 49
        mib = (ctypes.c_int * 3)(control_kern, kern_procargs2, pid)
        size = ctypes.c_size_t()
        libc = ctypes.CDLL(None, use_errno=True)
        sysctl = libc.sysctl
        sysctl.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        sysctl.restype = ctypes.c_int
        if sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            raise TakeoverError("could not size the exact process argv")
        if size.value <= ctypes.sizeof(ctypes.c_int) or size.value > 8 * 1024 * 1024:
            raise TakeoverError("exact process argv size is unsafe")
        buffer = ctypes.create_string_buffer(size.value)
        if sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
            raise TakeoverError("could not read the exact process argv")
        raw = bytes(buffer.raw[: size.value])
        integer_size = ctypes.sizeof(ctypes.c_int)
        argument_count = int.from_bytes(raw[:integer_size], sys.byteorder, signed=True)
        if argument_count <= 0 or argument_count > 4096:
            raise TakeoverError("exact process argv count is unsafe")
        cursor = raw.find(b"\0", integer_size)
        if cursor < 0:
            raise TakeoverError("exact process argv executable is malformed")
        cursor += 1
        while cursor < len(raw) and raw[cursor] == 0:
            cursor += 1
        arguments: list[str] = []
        for _ in range(argument_count):
            end = raw.find(b"\0", cursor)
            if end < 0:
                raise TakeoverError("exact process argv is truncated")
            try:
                arguments.append(raw[cursor:end].decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise TakeoverError("exact process argv is not UTF-8") from exc
            cursor = end + 1
        if not arguments or not arguments[0]:
            raise TakeoverError("exact process argv is empty")
        return tuple(arguments)

    @staticmethod
    def _descendants(
        rows: Sequence[tuple[int, int, int, str]], root_pid: int
    ) -> list[tuple[int, int, int, str]]:
        selected: list[tuple[int, int, int, str]] = []
        frontier = {root_pid}
        while frontier:
            next_frontier: set[int] = set()
            for row in rows:
                if (row[0] in frontier or row[1] in frontier) and row not in selected:
                    selected.append(row)
                    next_frontier.add(row[0])
            frontier = next_frontier
        return selected

    def inspect_legacy(
        self, *, plist_dir: Path, workspace_root: Path
    ) -> LegacyInventory:
        workspace_root = workspace_root.resolve()
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        expected_plist_dir = account_home / "Library/LaunchAgents"
        if Path(os.path.abspath(plist_dir.expanduser())) != expected_plist_dir:
            raise TakeoverError("legacy plist directory is not canonical")
        plist_metadata = plist_dir.lstat()
        if (
            stat.S_ISLNK(plist_metadata.st_mode)
            or not stat.S_ISDIR(plist_metadata.st_mode)
            or plist_metadata.st_uid != os.getuid()
            or stat.S_IMODE(plist_metadata.st_mode) & 0o022
        ):
            raise TakeoverError("legacy plist directory metadata is unsafe")
        plist_paths: list[str] = []
        plist_sha256s: list[str] = []
        for label in LEGACY_LABELS:
            path = plist_dir / f"{label}.plist"
            plist_sha256 = self._read_plist(path, label, workspace_root)
            if not self._loaded(label):
                raise TakeoverError(f"required legacy service is not loaded: {label}")
            plist_paths.append(str(path))
            plist_sha256s.append(plist_sha256)
        panes = _run(
            [
                self.tmux,
                "list-panes",
                "-t",
                f"={LEGACY_SESSION}",
                "-F",
                "#{pane_pid}\t#{pane_start_command}\t#{pane_current_path}",
            ]
        ).stdout.splitlines()
        if len(panes) != 1:
            raise TakeoverError("legacy cx-chat must contain exactly one tmux pane")
        parts = panes[0].split("\t", 2)
        if len(parts) != 3 or not parts[0].isdigit():
            raise TakeoverError("legacy cx-chat pane identity is malformed")
        pane_pid = int(parts[0])
        pane_command = parts[1]
        pane_cwd = Path(parts[2]).resolve()
        expected_root = workspace_root.resolve()
        if pane_cwd != expected_root and expected_root not in pane_cwd.parents:
            raise TakeoverError("legacy cx-chat pane is outside the expected workspace")
        if not _exact_legacy_listener_command(pane_command):
            raise TakeoverError("legacy cx-chat command is not the reviewed listener")
        process_rows = self._process_table()
        matching = [row for row in process_rows if row[0] == pane_pid]
        if len(matching) != 1 or matching[0][2] <= 1:
            raise TakeoverError("legacy cx-chat process group is unsafe")
        descendants = self._descendants(process_rows, pane_pid)
        if not descendants:
            raise TakeoverError("legacy cx-chat process tree is missing")
        ordered_descendants = sorted(descendants, key=lambda row: row[0])
        process_ids = tuple(row[0] for row in ordered_descendants)
        commands = tuple(row[3] for row in ordered_descendants)
        if not any("claude" in command for command in commands):
            raise TakeoverError("legacy cx-chat process tree contains no Claude listener")
        unexpected = [
            command for command in commands if not _reviewed_legacy_descendant(command)
        ]
        if unexpected:
            raise TakeoverError(
                "legacy cx-chat has an unreviewed descendant; wait for all work to stop"
            )
        return LegacyInventory(
            labels=LEGACY_LABELS,
            plist_paths=tuple(plist_paths),
            plist_sha256s=tuple(plist_sha256s),
            tmux_session=LEGACY_SESSION,
            pane_pid=pane_pid,
            pane_pgid=matching[0][2],
            pane_command=pane_command,
            pane_cwd=str(pane_cwd),
            process_ids=process_ids,
            process_commands=commands,
        )

    def stop_label(self, label: str) -> None:
        if label not in LEGACY_LABELS:
            raise TakeoverError("refusing to stop an unreviewed launchd label")
        if self._loaded(label):
            _run([self.launchctl, "bootout", f"gui/{os.getuid()}/{label}"])
        if self._loaded(label):
            raise TakeoverError(f"legacy service remained loaded: {label}")

    def stop_legacy_session(self, inventory: LegacyInventory) -> None:
        current_pgid = os.getpgrp()
        if inventory.pane_pgid <= 1 or inventory.pane_pgid == current_pgid:
            raise TakeoverError("refusing to signal an unsafe legacy process group")
        with contextlib.suppress(ProcessLookupError):
            os.killpg(inventory.pane_pgid, signal.SIGTERM)
        for _ in range(20):
            try:
                os.killpg(inventory.pane_pgid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(inventory.pane_pgid, signal.SIGKILL)
        _run(
            [self.tmux, "kill-session", "-t", f"={inventory.tmux_session}"],
            check=False,
        )

    def prove_legacy_stopped(self, inventory: LegacyInventory) -> None:
        for label in inventory.labels:
            if self._loaded(label):
                raise TakeoverError(f"legacy service restarted during quiescence: {label}")
        if (
            _run(
                [self.tmux, "has-session", "-t", f"={inventory.tmux_session}"],
                check=False,
            ).returncode
            == 0
        ):
            raise TakeoverError("legacy cx-chat tmux session is still running")
        current_processes = self._process_table()
        captured = dict(zip(inventory.process_ids, inventory.process_commands))
        if (
            len(inventory.process_ids) != len(inventory.process_commands)
            or len(captured) != len(inventory.process_ids)
        ):
            raise TakeoverError("legacy descendant inventory is malformed")
        captured_ids = set(captured)
        remaining_captured = [
            str(pid) for pid, _, _, _ in current_processes if pid in captured_ids
        ]
        if remaining_captured:
            raise TakeoverError(
                "captured legacy descendants remain after quiescence: "
                + ", ".join(remaining_captured)
            )
        try:
            os.killpg(inventory.pane_pgid, 0)
        except ProcessLookupError:
            pass
        except PermissionError as exc:
            raise TakeoverError(
                "legacy process group could not be proven absent"
            ) from exc
        else:
            raise TakeoverError("legacy process group remains after quiescence")
        suspicious = []
        signatures = (
            "/x_System/Assistant/conversations/scripts/queue/",
            "sync-discord-archive-state.py",
            "run-cron.sh cx-chat-archive-sync",
            "--channels plugin:discord@claude-plugins-official",
        )
        for pid, _, _, command in current_processes:
            if pid == os.getpid():
                continue
            if any(signature in command for signature in signatures):
                suspicious.append(str(pid))
        if suspicious:
            raise TakeoverError(
                "legacy Claude descendants remain after quiescence: "
                + ", ".join(suspicious)
            )

    def restart_legacy(self, inventory: LegacyInventory) -> None:
        if len(inventory.plist_sha256s) != len(inventory.plist_paths):
            raise TakeoverError("legacy rollback plist inventory is malformed")
        for raw_path, expected_sha256 in zip(
            inventory.plist_paths, inventory.plist_sha256s
        ):
            if _sha256_file(Path(raw_path)) != expected_sha256:
                raise TakeoverError("legacy plist changed after takeover validation")
        session_running = (
            _run(
                [self.tmux, "has-session", "-t", f"={inventory.tmux_session}"],
                check=False,
            ).returncode
            == 0
        )
        if session_running:
            panes = _run(
                [
                    self.tmux,
                    "list-panes",
                    "-t",
                    f"={inventory.tmux_session}",
                    "-F",
                    "#{pane_pid}\t#{pane_start_command}\t#{pane_current_path}",
                ]
            ).stdout.splitlines()
            expected = (
                f"{inventory.pane_pid}\t{inventory.pane_command}\t{inventory.pane_cwd}"
            )
            if panes != [expected]:
                raise TakeoverError(
                    "legacy rollback found an inexact surviving tmux session"
                )
        else:
            processes = self._process_table()
            captured_ids = set(inventory.process_ids)
            if any(pid in captured_ids for pid, _, _, _ in processes):
                raise TakeoverError(
                    "legacy rollback found a surviving captured descendant"
                )
            try:
                os.killpg(inventory.pane_pgid, 0)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise TakeoverError(
                    "legacy rollback could not prove the old process group absent"
                ) from exc
            else:
                raise TakeoverError(
                    "legacy rollback found the old process group still alive"
                )
        for label, raw_path in zip(inventory.labels[1:], inventory.plist_paths[1:]):
            if not self._loaded(label):
                _run(
                    [
                        self.launchctl,
                        "bootstrap",
                        f"gui/{os.getuid()}",
                        raw_path,
                    ]
                )
        health_path = inventory.plist_paths[0]
        if not self._loaded(HEALTHCHECK_LABEL):
            _run(
                [
                    self.launchctl,
                    "bootstrap",
                    f"gui/{os.getuid()}",
                    health_path,
                ]
            )
        _run(
            [
                self.launchctl,
                "kickstart",
                "-k",
                f"gui/{os.getuid()}/{HEALTHCHECK_LABEL}",
            ],
            check=False,
        )
        for label in inventory.labels:
            if not self._loaded(label):
                raise TakeoverError(f"legacy rollback did not reload {label}")
        last_error: TakeoverError | None = None
        for _ in range(25):
            try:
                restored = self.inspect_legacy(
                    plist_dir=Path(inventory.plist_paths[0]).parent,
                    workspace_root=Path(inventory.pane_cwd),
                )
            except TakeoverError as exc:
                last_error = exc
                time.sleep(0.2)
                continue
            if restored.labels != inventory.labels:
                raise TakeoverError("legacy rollback identity changed")
            return
        raise TakeoverError(
            "legacy rollback did not restore the exact listener process tree"
        ) from last_error

    def mark_gateway_session_fresh(self, path: Path, backup_dir: Path) -> None:
        if path.is_symlink():
            raise TakeoverError("new Gateway state path is a symlink")
        if path.exists():
            _require_owned_regular(path)
            path.unlink()
            _fsync_directory(path.parent)

    def restore_gateway_state(self, path: Path, backup_dir: Path) -> None:
        source = backup_dir / "new-gateway-state" / path.name
        if source.exists():
            _ensure_private_directory(path.parent)
            path.unlink(missing_ok=True)
            _private_copy(source, path)
        else:
            path.unlink(missing_ok=True)

    def verify_replacement(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
    ) -> None:
        if not SAFE_ID.fullmatch(label_prefix) or not SAFE_ID.fullmatch(session):
            raise TakeoverError("replacement identity is invalid")
        for component in ("cx-chat-healthcheck", "discord-gateway-client"):
            label = f"{label_prefix}.{component}"
            if not self._loaded(label):
                raise TakeoverError(f"replacement service is not loaded: {label}")
        output = _run(
            [
                self.tmux,
                "list-panes",
                "-t",
                f"={session}",
                "-F",
                "#{pane_pid}\t#{pane_start_command}\t#{pane_current_path}",
            ]
        ).stdout.splitlines()
        if len(output) != 1:
            raise TakeoverError("replacement listener has an unexpected pane layout")
        parts = output[0].split("\t", 2)
        expected_launcher = str((repo_root / "cx-launcher.sh").resolve())
        expected_cwd = str((repo_root / "cx-chat-listener").resolve())
        if (
            len(parts) != 3
            or not parts[0].isdigit()
            or parts[1] != expected_launcher
            or parts[2] != expected_cwd
        ):
            raise TakeoverError("replacement listener identity is not exact")
        process_rows = [
            row for row in self._process_table() if row[0] == int(parts[0])
        ]
        if len(process_rows) != 1 or not _reviewed_replacement_arguments(
            self._process_arguments(process_rows[0][0]),
            repo_root,
            workspace_root,
        ):
            raise TakeoverError("replacement listener process is not exact")
        captured = _run(
            [self.tmux, "capture-pane", "-p", "-t", f"={session}:0.0", "-S", "-2000"]
        ).stdout
        if "THREADKEEP_LISTENER_READY_v1_7f29c4b1" not in captured:
            raise TakeoverError("replacement listener readiness token is absent")

    def run_takeover_drain(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
        challenge: str,
        issued_at: float,
        expires_at: float,
    ) -> float:
        """Issue one local-only queue drain challenge to the exact listener."""

        now = time.time()
        if not TAKEOVER_DRAIN_CHALLENGE.fullmatch(challenge):
            raise TakeoverError("takeover drain challenge is invalid")
        if (
            issued_at > now + 5
            or now - issued_at > 30
            or expires_at != issued_at + TAKEOVER_DRAIN_TTL_SECONDS
            or expires_at <= now
        ):
            raise TakeoverError("takeover drain challenge is not fresh")
        self.verify_replacement(
            label_prefix=label_prefix,
            session=session,
            repo_root=repo_root,
            workspace_root=workspace_root,
        )
        target = f"={session}:0.0"
        expected = TAKEOVER_DRAIN_TOKEN_PREFIX + challenge

        def capture() -> str:
            return _run(
                [self.tmux, "capture-pane", "-p", "-J", "-t", target, "-S", "-4000"]
            ).stdout

        if expected in capture():
            raise TakeoverError("takeover drain challenge was already present")
        prompt = (
            "Run the pending Threadkeep takeover drain defined in your pinned "
            f"system prompt. Challenge={challenge} Deadline={int(expires_at)}."
        )
        _run([self.tmux, "send-keys", "-t", target, prompt, "Enter"])
        time.sleep(1)
        _run([self.tmux, "send-keys", "-t", target, "Enter"])
        while time.time() < expires_at:
            captured = capture()
            occurrences = captured.count(expected)
            if occurrences == 1:
                observed_at = time.time()
                if observed_at > expires_at:
                    raise TakeoverError(
                        "takeover drain completion arrived after its deadline"
                    )
                return observed_at
            if occurrences > 1:
                raise TakeoverError(
                    "takeover drain completion token was repeated"
                )
            time.sleep(1)
        raise TakeoverError("takeover drain challenge expired without completion")

    def stop_replacement(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
    ) -> None:
        if not SAFE_ID.fullmatch(label_prefix) or not SAFE_ID.fullmatch(session):
            raise TakeoverError("replacement identity is invalid")
        session_running = (
            _run(
                [self.tmux, "has-session", "-t", f"={session}"],
                check=False,
            ).returncode
            == 0
        )
        captured_ids: set[int] = set()
        captured_group: int | None = None
        if session_running:
            panes = _run(
                [
                    self.tmux,
                    "list-panes",
                    "-t",
                    f"={session}",
                    "-F",
                    "#{pane_pid}\t#{pane_start_command}\t#{pane_current_path}",
                ]
            ).stdout.splitlines()
            expected = (
                str((repo_root / "cx-launcher.sh").resolve())
                + "\t"
                + str((repo_root / "cx-chat-listener").resolve())
            )
            if len(panes) != 1:
                raise TakeoverError("refusing to stop an inexact replacement session")
            parts = panes[0].split("\t", 2)
            if (
                len(parts) != 3
                or not parts[0].isdigit()
                or "\t".join(parts[1:]) != expected
            ):
                raise TakeoverError("refusing to stop an inexact replacement session")
            pane_pid = int(parts[0])
            processes = self._process_table()
            pane_rows = [row for row in processes if row[0] == pane_pid]
            if (
                len(pane_rows) != 1
                or pane_rows[0][2] <= 1
                or not _reviewed_replacement_arguments(
                    self._process_arguments(pane_rows[0][0]),
                    repo_root,
                    workspace_root,
                )
            ):
                raise TakeoverError(
                    "refusing to stop an inexact replacement listener"
                )
            captured_group = pane_rows[0][2]
            if captured_group == os.getpgrp():
                raise TakeoverError("refusing to stop the current process group")
            captured_ids = {
                row[0] for row in self._descendants(processes, pane_pid)
            }
            if pane_pid not in captured_ids:
                raise TakeoverError("replacement process tree could not be captured")

        for component in ("cx-chat-healthcheck", "discord-gateway-client"):
            label = f"{label_prefix}.{component}"
            if self._loaded(label):
                _run([self.launchctl, "bootout", f"gui/{os.getuid()}/{label}"])
            if self._loaded(label):
                raise TakeoverError(f"replacement service remained loaded: {label}")

        if captured_group is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(captured_group, signal.SIGTERM)
            for _ in range(20):
                try:
                    os.killpg(captured_group, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(captured_group, signal.SIGKILL)
        if session_running:
            _run([self.tmux, "kill-session", "-t", f"={session}"])
        if (
            _run(
                [self.tmux, "has-session", "-t", f"={session}"],
                check=False,
            ).returncode
            == 0
        ):
            raise TakeoverError("replacement tmux session remained after shutdown")
        processes = self._process_table()
        remaining_ids = sorted(
            pid for pid, _, _, _ in processes if pid in captured_ids
        )
        if remaining_ids:
            raise TakeoverError(
                "replacement descendants remain after shutdown: "
                + ", ".join(str(pid) for pid in remaining_ids)
            )
        if captured_group is not None:
            try:
                os.killpg(captured_group, 0)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                raise TakeoverError(
                    "replacement process group could not be proven absent"
                ) from exc
            else:
                raise TakeoverError(
                    "replacement process group remains after shutdown"
                )
        suspicious: list[int] = []
        for pid, _, _, command in processes:
            if pid == os.getpid():
                continue
            possible_replacement = (
                listener_contract.RUNTIME_PROMPT_NAME in command
                or str((repo_root / "cx-launcher.sh").resolve()) in command
            )
            if not possible_replacement:
                continue
            try:
                exact = _reviewed_replacement_arguments(
                    self._process_arguments(pid), repo_root, workspace_root
                )
            except TakeoverError:
                exact = False
            if exact or "plugin:discord@claude-plugins-official" in command:
                suspicious.append(pid)
        if suspicious:
            raise TakeoverError(
                "replacement listener processes remain after shutdown: "
                + ", ".join(str(pid) for pid in sorted(suspicious))
            )


class Takeover:
    def __init__(self, host: Host, discord: Discord) -> None:
        self.host = host
        self.discord = discord

    def prepare(
        self,
        *,
        explicit_opt_in: bool,
        quarantine_opt_in: bool,
        maintenance_phrase: str,
        quarantine_acknowledgment: str,
        expected_plan_sha256: str,
        workspace_root: Path,
        conversations_dir: Path,
        queue_db: Path,
        backup_root: Path,
        receipt_path: Path,
        plist_dir: Path,
        legacy_approval_root: Path | None,
        new_gateway_state: Path,
        root_channel: str,
        owner_user_id: str,
        new_label_prefix: str,
        new_session: str,
        repo_root: Path,
    ) -> dict[str, Any]:
        if not explicit_opt_in or not quarantine_opt_in:
            raise TakeoverError("legacy takeover and ambiguity quarantine require opt-in")
        if maintenance_phrase != MAINTENANCE_PHRASE:
            raise TakeoverError("legacy takeover maintenance phrase does not match")
        if not re.fullmatch(r"[a-f0-9]{64}", expected_plan_sha256):
            raise TakeoverError("legacy takeover plan digest is invalid")
        if conversations_dir.resolve() != (
            workspace_root / "x_System/Assistant/conversations"
        ).resolve():
            raise TakeoverError(
                "takeover must preserve x_System/Assistant/conversations exactly"
            )
        _require_owned_real_directory_chain(workspace_root, conversations_dir)
        _require_owned_real_directory_chain(workspace_root, conversations_dir / "state")
        if queue_db.resolve() != (conversations_dir / "state/mq.sqlite3").resolve():
            raise TakeoverError("takeover queue path is not canonical")
        if backup_root.resolve() != (
            conversations_dir / "state/takeover-backups"
        ).resolve():
            raise TakeoverError("takeover backup path is not canonical")
        if receipt_path.parent.resolve() != (
            conversations_dir / "state/takeover"
        ).resolve() or not re.fullmatch(r"[A-Za-z0-9_.-]+\.json", receipt_path.name):
            raise TakeoverError("takeover receipt path is not canonical")
        if new_gateway_state.resolve() != (
            repo_root / "discord-gateway/state/gateway.json"
        ).resolve():
            raise TakeoverError("replacement Gateway state path is not canonical")
        expected_approval_root = workspace_root / "x_System/Assistant/discord-gateway"
        if legacy_approval_root is not None and legacy_approval_root.resolve() != (
            expected_approval_root.resolve()
        ):
            raise TakeoverError("legacy approval state path is not canonical")
        repo_metadata = repo_root.lstat()
        if (
            stat.S_ISLNK(repo_metadata.st_mode)
            or not stat.S_ISDIR(repo_metadata.st_mode)
            or repo_metadata.st_uid != os.getuid()
        ):
            raise TakeoverError("replacement repository path is unsafe")
        _require_owned_real_directory_chain(repo_root, new_gateway_state.parent)
        if receipt_path.exists() or receipt_path.is_symlink():
            raise TakeoverError("takeover receipt already exists")
        _ensure_private_directory(receipt_path.parent)
        for prior_path in sorted(receipt_path.parent.glob("*.json")):
            prior = _read_private_json(prior_path)
            if prior.get("phase") not in {"committed", "rolled-back"}:
                raise TakeoverError(
                    "an unfinished legacy takeover receipt requires manual review"
                )
        lock_path = receipt_path.parent / ".takeover.lock"
        lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        lock_flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            lock_path,
            lock_flags,
            0o600,
        )
        inventory: LegacyInventory | None = None
        takeover_id = f"{int(time.time())}-{os.urandom(8).hex()}"
        backup_dir: Path | None = None
        progress: dict[str, Any] | None = None
        try:
            os.fchmod(descriptor, 0o600)
            lock_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_uid != os.getuid()
                or lock_metadata.st_nlink != 1
            ):
                raise TakeoverError("takeover lock is not a private regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            preflight_connection = _connect_existing_queue(
                queue_db, read_only=True
            )
            try:
                preflight_connection.execute("BEGIN")
                preflight_plan = queue_takeover_plan(preflight_connection)
                preflight_connection.execute("COMMIT")
            finally:
                with contextlib.suppress(sqlite3.Error):
                    preflight_connection.execute("ROLLBACK")
                preflight_connection.close()
            if preflight_plan["snapshot_sha256"] != expected_plan_sha256:
                raise TakeoverError(
                    "legacy queue changed after the count-bound plan was acknowledged"
                )
            if preflight_plan["acknowledgment"] != quarantine_acknowledgment:
                raise TakeoverError(
                    "legacy quarantine acknowledgment does not match exact counts"
                )
            if preflight_plan["hard_blockers"]:
                raise TakeoverError(
                    "legacy queue contains hard blockers that require manual review"
                )
            self.host.prove_replacement_absent(
                label_prefix=new_label_prefix,
                session=new_session,
                repo_root=repo_root,
            )
            inventory = self.host.inspect_legacy(
                plist_dir=plist_dir, workspace_root=workspace_root
            )
            progress = {
                "version": RECEIPT_VERSION,
                "takeover_id": takeover_id,
                "phase": "legacy-validated",
                "workspace_root": str(workspace_root.resolve()),
                "conversations_dir": str(conversations_dir.resolve()),
                "queue_db": str(queue_db.resolve()),
                "backup_dir": "",
                "new_gateway_state": str(new_gateway_state.resolve()),
                "root_channel": root_channel,
                "owner_user_id": owner_user_id,
                "new_label_prefix": new_label_prefix,
                "new_session": new_session,
                "repo_root": str(repo_root.resolve()),
                "legacy_inventory": asdict(inventory),
                "validated_at": time.time(),
            }
            _save_receipt(receipt_path, progress)
            for label in LEGACY_STOP_ORDER:
                self.host.stop_label(label)
            self.host.stop_legacy_session(inventory)
            self.host.prove_legacy_stopped(inventory)
            progress["phase"] = "legacy-quiesced"
            progress["quiesced_at"] = time.time()
            _save_receipt(receipt_path, progress)
            backup_dir = create_backup(
                conversations_dir=conversations_dir,
                queue_db=queue_db,
                backup_root=backup_root,
                inventory=inventory,
                legacy_approval_root=legacy_approval_root,
                new_gateway_state=new_gateway_state,
                takeover_id=takeover_id,
            )
            verify_backup(backup_dir)
            progress["phase"] = "backup-complete"
            progress["backup_dir"] = str(backup_dir.resolve())
            progress["backup_completed_at"] = time.time()
            _save_receipt(receipt_path, progress)
            connection = _connect_existing_queue(queue_db)
            try:
                classification = classify_queue(connection)
                current_plan = queue_takeover_plan(connection)
                if current_plan["snapshot_sha256"] != expected_plan_sha256:
                    raise TakeoverError(
                        "legacy queue changed after the count-bound plan was acknowledged"
                    )
                with _owned_binary_reader(
                    backup_dir / "queue-nonterminal-snapshot.json"
                ) as snapshot_stream:
                    backed_up_plan = json.load(snapshot_stream)
                if backed_up_plan.get("snapshot_sha256") != expected_plan_sha256:
                    raise TakeoverError(
                        "private queue snapshot does not match the acknowledged plan"
                    )
                if current_plan["acknowledgment"] != quarantine_acknowledgment:
                    raise TakeoverError(
                        "legacy quarantine acknowledgment does not match exact counts"
                    )
                progress["phase"] = "quarantine-authorized"
                progress["classification"] = asdict(classification)
                progress["acknowledged_queue_plan"] = current_plan
                progress["quarantine_authorized_at"] = time.time()
                _save_receipt(receipt_path, progress)
                quarantine_ambiguous(
                    connection, classification, takeover_id=takeover_id
                )
                channel_ids = _registry_threads(conversations_dir, root_channel)
                lower = _global_lower(connection, channel_ids)
                upper = self.discord.capture_upper(channel_ids, lower)
                progress["phase"] = "gap-reconciling"
                progress["maintenance_lower"] = lower
                progress["maintenance_upper"] = upper
                _save_receipt(receipt_path, progress)
                inserted = reconcile_window(
                    connection,
                    self.discord,
                    channel_ids=channel_ids,
                    root_channel=root_channel,
                    owner_user_id=owner_user_id,
                    lower=lower,
                    upper=upper,
                    takeover_id=takeover_id,
                )
                baseline = queue_baseline(connection)
            finally:
                connection.close()
            progress["phase"] = "gateway-resetting"
            progress["initial_reconciled"] = list(inserted)
            progress["baseline"] = baseline
            _save_receipt(receipt_path, progress)
            self.host.mark_gateway_session_fresh(new_gateway_state, backup_dir)
            progress["phase"] = "prepared"
            progress["prepared_at"] = time.time()
            _save_receipt(receipt_path, progress)
            return progress
        except Exception:
            if inventory is not None:
                try:
                    if backup_dir is not None and queue_db.exists():
                        connection = _connect_existing_queue(queue_db)
                        try:
                            restore_quarantine(connection, takeover_id)
                        finally:
                            connection.close()
                        self.host.restore_gateway_state(
                            new_gateway_state, backup_dir
                        )
                    self.host.restart_legacy(inventory)
                    if progress is not None and receipt_path.exists():
                        progress["phase"] = "rolled-back"
                        progress["rolled_back_at"] = time.time()
                        _save_receipt(receipt_path, progress)
                except Exception as rollback_error:
                    if progress is not None and receipt_path.exists():
                        progress["phase"] = "manual-recovery-required"
                        progress["rollback_failed_at"] = time.time()
                        with contextlib.suppress(Exception):
                            _save_receipt(receipt_path, progress)
                    raise TakeoverError(
                        "takeover failed and automatic legacy rollback also failed"
                    ) from rollback_error
            raise
        finally:
            with contextlib.suppress(Exception):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def begin_replacement(self, receipt_path: Path) -> dict[str, Any]:
        with _receipt_transaction_lock(receipt_path):
            return self._begin_replacement_unlocked(receipt_path)

    def _begin_replacement_unlocked(self, receipt_path: Path) -> dict[str, Any]:
        receipt = _read_private_json(receipt_path)
        if receipt.get("phase") != "prepared":
            raise TakeoverError("replacement can begin only from prepared phase")
        connection = _connect_existing_queue(Path(receipt["queue_db"]))
        try:
            receipt["baseline"] = queue_baseline(connection)
        finally:
            connection.close()
        receipt["phase"] = "replacement-starting"
        receipt["replacement_started_at"] = time.time()
        _save_receipt(receipt_path, receipt)
        return receipt

    def finalize(self, receipt_path: Path) -> dict[str, Any]:
        with _receipt_transaction_lock(receipt_path):
            return self._finalize_unlocked(receipt_path)

    def _finalize_unlocked(self, receipt_path: Path) -> dict[str, Any]:
        receipt = _read_private_json(receipt_path)
        if receipt.get("phase") != "replacement-starting":
            raise TakeoverError("takeover finalization is out of order")
        repo_root = Path(receipt["repo_root"])
        self.host.verify_replacement(
            label_prefix=receipt["new_label_prefix"],
            session=receipt["new_session"],
            repo_root=repo_root,
            workspace_root=Path(receipt["workspace_root"]),
        )
        connection = _connect_existing_queue(Path(receipt["queue_db"]))
        try:
            channel_ids = _registry_threads(
                Path(receipt["conversations_dir"]), receipt["root_channel"]
            )
            lower = receipt["maintenance_lower"]
            upper = self.discord.capture_upper(channel_ids, lower)
            inserted = reconcile_window(
                connection,
                self.discord,
                channel_ids=channel_ids,
                root_channel=receipt["root_channel"],
                owner_user_id=receipt["owner_user_id"],
                lower=lower,
                upper=upper,
                takeover_id=receipt["takeover_id"],
            )
        finally:
            connection.close()
        receipt["phase"] = "replacement-reconciled"
        receipt["final_upper"] = upper
        receipt["final_reconciled"] = list(inserted)
        receipt["final_reconciled_at"] = time.time()
        _save_receipt(receipt_path, receipt)

        issued_at = time.time()
        challenge = secrets.token_hex(32)
        expires_at = issued_at + TAKEOVER_DRAIN_TTL_SECONDS
        receipt["phase"] = "replacement-draining"
        receipt["drain_handshake"] = {
            "challenge": challenge,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "status": "issued",
        }
        _save_receipt(receipt_path, receipt)
        responded_at = self.host.run_takeover_drain(
            label_prefix=receipt["new_label_prefix"],
            session=receipt["new_session"],
            repo_root=repo_root,
            workspace_root=Path(receipt["workspace_root"]),
            challenge=challenge,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        if responded_at < issued_at or responded_at > expires_at:
            receipt["drain_handshake"]["status"] = "expired-response"
            receipt["drain_handshake"]["responded_at"] = responded_at
            _save_receipt(receipt_path, receipt)
            raise TakeoverError(
                "takeover drain completion was outside its freshness window"
            )
        receipt["drain_handshake"]["status"] = "responded"
        receipt["drain_handshake"]["responded_at"] = responded_at
        _save_receipt(receipt_path, receipt)

        connection = _connect_existing_queue(Path(receipt["queue_db"]))
        try:
            backlog = safe_pre_dispatch_backlog(connection)
        finally:
            connection.close()
        if backlog:
            rendered = ", ".join(
                f"{row['message_id']}:{row['state']}" for row in backlog
            )
            raise TakeoverError(
                "replacement drain left safe pre-dispatch work: " + rendered
            )
        self.host.verify_replacement(
            label_prefix=receipt["new_label_prefix"],
            session=receipt["new_session"],
            repo_root=repo_root,
            workspace_root=Path(receipt["workspace_root"]),
        )
        receipt["drain_handshake"]["status"] = "consumed"
        receipt["drain_handshake"]["consumed_at"] = time.time()
        receipt["phase"] = "committed"
        receipt["committed_at"] = time.time()
        _save_receipt(receipt_path, receipt)
        return receipt

    def abort(self, receipt_path: Path) -> dict[str, Any]:
        with _receipt_transaction_lock(receipt_path):
            return self._abort_unlocked(receipt_path)

    def _abort_unlocked(self, receipt_path: Path) -> dict[str, Any]:
        receipt = _read_private_json(receipt_path)
        phase = receipt.get("phase")
        if phase == "committed":
            raise UnsafeRollback("committed takeover cannot restart the legacy runtime")
        if phase == "rolled-back":
            return receipt
        rollback_phases = {
            "legacy-validated",
            "legacy-quiesced",
            "backup-complete",
            "quarantine-authorized",
            "gap-reconciling",
            "gateway-resetting",
            "prepared",
            "replacement-starting",
            "replacement-reconciled",
            "replacement-draining",
        }
        if phase not in rollback_phases:
            raise TakeoverError("takeover receipt is not rollback eligible")
        queue_db = Path(receipt["queue_db"])
        if phase in {
            "prepared",
            "replacement-starting",
            "replacement-reconciled",
            "replacement-draining",
        }:
            connection = _connect_existing_queue(queue_db)
            try:
                if replacement_accepted_work(connection, receipt["baseline"]):
                    receipt["phase"] = "manual-recovery-required"
                    receipt["rollback_forbidden_at"] = time.time()
                    _save_receipt(receipt_path, receipt)
                    raise UnsafeRollback(
                        "replacement accepted work; automatic legacy restart is forbidden"
                    )
            finally:
                connection.close()
        inventory = LegacyInventory(**receipt["legacy_inventory"])
        if phase in {
            "replacement-starting",
            "replacement-reconciled",
            "replacement-draining",
        }:
            self.host.stop_replacement(
                label_prefix=receipt["new_label_prefix"],
                session=receipt["new_session"],
                repo_root=Path(receipt["repo_root"]),
                workspace_root=Path(receipt["workspace_root"]),
            )
        if queue_db.exists():
            connection = _connect_existing_queue(queue_db)
            try:
                restore_quarantine(connection, receipt["takeover_id"])
            finally:
                connection.close()
        if receipt.get("backup_dir"):
            self.host.restore_gateway_state(
                Path(receipt["new_gateway_state"]), Path(receipt["backup_dir"])
            )
        self.host.restart_legacy(inventory)
        receipt["phase"] = "rolled-back"
        receipt["rolled_back_at"] = time.time()
        _save_receipt(receipt_path, receipt)
        return receipt


def _read_lines(expected: int) -> list[str]:
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        raise TakeoverError("takeover input is too large")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise TakeoverError("takeover input must be UTF-8 text") from exc
    if len(lines) != expected:
        raise TakeoverError(
            f"takeover input must contain exactly {expected} lines"
        )
    return lines


def _read_prepare_stdin() -> tuple[str, str, str, str]:
    phrase, token, acknowledgment, plan_sha256 = _read_lines(4)
    return phrase, token, acknowledgment, plan_sha256


def _read_finalize_stdin() -> tuple[str, str]:
    phrase, token = _read_lines(2)
    if phrase != MAINTENANCE_PHRASE:
        raise TakeoverError("legacy takeover maintenance phrase does not match")
    return phrase, token


def _common_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--receipt", type=Path, required=True)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--queue-db", type=Path, required=True)
    prepare = subparsers.add_parser("prepare")
    _common_parser(prepare)
    prepare.add_argument("--take-over-legacy", action="store_true")
    prepare.add_argument("--quarantine-ambiguous", action="store_true")
    prepare.add_argument("--workspace-root", type=Path, required=True)
    prepare.add_argument("--conversations-dir", type=Path, required=True)
    prepare.add_argument("--queue-db", type=Path, required=True)
    prepare.add_argument("--backup-root", type=Path, required=True)
    prepare.add_argument("--plist-dir", type=Path, required=True)
    prepare.add_argument("--legacy-approval-root", type=Path)
    prepare.add_argument("--new-gateway-state", type=Path, required=True)
    prepare.add_argument("--root-channel", required=True)
    prepare.add_argument("--owner-user-id", required=True)
    prepare.add_argument("--new-label-prefix", required=True)
    prepare.add_argument("--new-session", required=True)
    prepare.add_argument("--repo-root", type=Path, required=True)
    begin = subparsers.add_parser("begin-replacement")
    _common_parser(begin)
    finalize = subparsers.add_parser("finalize")
    _common_parser(finalize)
    abort = subparsers.add_parser("abort")
    _common_parser(abort)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    host = MacHost()
    if arguments.command == "plan":
        connection = _connect_existing_queue(arguments.queue_db, read_only=True)
        try:
            connection.execute("BEGIN")
            plan = queue_takeover_plan(connection)
            connection.execute("COMMIT")
            print(json.dumps(plan, sort_keys=True))
        finally:
            with contextlib.suppress(sqlite3.Error):
                connection.execute("ROLLBACK")
            connection.close()
        return 0
    if arguments.command == "prepare":
        phrase, token, acknowledgment, plan_sha256 = _read_prepare_stdin()
        takeover = Takeover(host, DiscordREST(token))
        takeover.prepare(
            explicit_opt_in=arguments.take_over_legacy,
            quarantine_opt_in=arguments.quarantine_ambiguous,
            maintenance_phrase=phrase,
            quarantine_acknowledgment=acknowledgment,
            expected_plan_sha256=plan_sha256,
            workspace_root=arguments.workspace_root,
            conversations_dir=arguments.conversations_dir,
            queue_db=arguments.queue_db,
            backup_root=arguments.backup_root,
            receipt_path=arguments.receipt,
            plist_dir=arguments.plist_dir,
            legacy_approval_root=arguments.legacy_approval_root,
            new_gateway_state=arguments.new_gateway_state,
            root_channel=arguments.root_channel,
            owner_user_id=arguments.owner_user_id,
            new_label_prefix=arguments.new_label_prefix,
            new_session=arguments.new_session,
            repo_root=arguments.repo_root,
        )
        print(str(arguments.receipt.resolve()))
        return 0
    if arguments.command == "begin-replacement":
        takeover = Takeover(host, DiscordREST.__new__(DiscordREST))
        takeover.begin_replacement(arguments.receipt)
        return 0
    if arguments.command == "finalize":
        _, token = _read_finalize_stdin()
        takeover = Takeover(host, DiscordREST(token))
        takeover.finalize(arguments.receipt)
        return 0
    takeover = Takeover(host, DiscordREST.__new__(DiscordREST))
    takeover.abort(arguments.receipt)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except UnsafeRollback as exc:
        print(f"takeover rollback forbidden: {exc}", file=sys.stderr)
        raise SystemExit(3)
    except Exception as exc:  # noqa: BLE001
        print(f"takeover failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
