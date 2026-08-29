#!/usr/bin/env python3
"""Approval responder.

Invoked by the Discord interaction router when the owner clicks Approve or
Reject on a draft preview. Writes a marker file under the gateway approvals dir
so the in-flight worker (which is polling request_approval.py) sees the result.

Marker file path:
    <repo>/discord-gateway/approvals/<sha-prefix>.json

The marker copies every immutable Discord principal and the frozen request
binding. The polling request rejects missing, substituted, or fallback fields.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APPROVALS_DIR = REPO_ROOT / "discord-gateway" / "approvals"
SHA_PREFIX_RE = re.compile(r"^[a-f0-9]{12,64}$")
FULL_SHA_RE = re.compile(r"^[a-f0-9]{64}$")
SNOWFLAKE_RE = re.compile(r"^[1-9][0-9]{16,19}$")
BINDING_DIGEST_RE = FULL_SHA_RE
MARKER_VERSION = 2
CONFLICT_EXIT_CODE = 4
MAX_MARKER_BYTES = 1_000_000
MAX_RESPONDER_INPUT_BYTES = 16_384
RESPONDER_INPUT_KEYS = frozenset(
    {
        "action",
        "sha",
        "channel_id",
        "message_id",
        "interaction_id",
        "user_id",
        "application_id",
        "guild_id",
        "bot_user_id",
        "full_sha",
        "request_action",
        "request_target",
        "binding_sha256",
    }
)


class ConflictingDecisionError(RuntimeError):
    """A different immutable click already decided this approval request."""


def _require_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError("approvals directory is not a private owned directory")


def _read_existing_marker(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_MARKER_BYTES
    ):
        raise RuntimeError("existing approval marker is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, MAX_MARKER_BYTES + 1)
    finally:
        os.close(descriptor)
    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise RuntimeError("approval marker changed while opening")
    if len(raw) > MAX_MARKER_BYTES:
        raise RuntimeError("approval marker is too large")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("approval marker is not a JSON object")
    return value


def write_marker(
    action: str,
    status: str,
    sha: str,
    full_sha: str,
    channel_id: str,
    message_id: str,
    interaction_id: str,
    user_id: str,
    application_id: str,
    guild_id: str,
    bot_user_id: str,
    request_action: str,
    request_target: str,
    binding_sha256: str,
) -> Path:
    _require_private_directory(APPROVALS_DIR)
    payload = {
        "version": MARKER_VERSION,
        "status": status,
        "action": action,
        "sha_prefix": sha,
        "full_sha": full_sha,
        "channel_id": channel_id,
        "message_id": message_id,
        "interaction_id": interaction_id,
        "user_id": user_id,
        "application_id": application_id,
        "guild_id": guild_id,
        "bot_user_id": bot_user_id,
        "request_action": request_action,
        "request_target": request_target,
        "binding_sha256": binding_sha256,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    path = APPROVALS_DIR / f"{sha}.json"
    try:
        existing = _read_existing_marker(path)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        identity = tuple(key for key in payload if key != "ts")
        if isinstance(existing, dict) and all(
            existing.get(key) == payload.get(key) for key in identity
        ):
            return path
        raise ConflictingDecisionError(
            "a conflicting approval decision already exists for this SHA"
        )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{sha}.", suffix=".tmp", dir=APPROVALS_DIR
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            existing = _read_existing_marker(path)
            identity = tuple(key for key in payload if key != "ts")
            if all(existing.get(key) == payload.get(key) for key in identity):
                temporary.unlink(missing_ok=True)
                return path
            raise ConflictingDecisionError(
                "a conflicting approval decision already exists for this SHA"
            ) from None
        temporary.unlink()
        directory = os.open(APPROVALS_DIR, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-stdin", action="store_true", required=True)
    parser.parse_args()

    raw = sys.stdin.buffer.read(MAX_RESPONDER_INPUT_BYTES + 1)
    if len(raw) > MAX_RESPONDER_INPUT_BYTES:
        print("responder input is too large", file=sys.stderr)
        return 2
    try:
        values = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print("responder input is not valid UTF-8 JSON", file=sys.stderr)
        return 2
    if not isinstance(values, dict) or set(values) != RESPONDER_INPUT_KEYS:
        print("responder input has an unexpected schema", file=sys.stderr)
        return 2
    if any(not isinstance(value, str) for value in values.values()):
        print("responder input fields must be strings", file=sys.stderr)
        return 2

    action = str(values.get("action") or "")
    if action not in {"approve", "reject"}:
        print("action must be approve or reject", file=sys.stderr)
        return 2
    sha = str(values["sha"]).strip().lower()
    if not SHA_PREFIX_RE.fullmatch(sha):
        print("sha prefix must be 12-64 lowercase hex characters", file=sys.stderr)
        return 2
    full_sha = str(values["full_sha"])
    if not FULL_SHA_RE.fullmatch(full_sha) or not full_sha.startswith(sha):
        print("full sha must be a matching lowercase sha256", file=sys.stderr)
        return 2
    identifiers = (
        (str(values["channel_id"]), "channel id"),
        (str(values["message_id"]), "message id"),
        (str(values["interaction_id"]), "interaction id"),
        (str(values["user_id"]), "user id"),
        (str(values["application_id"]), "application id"),
        (str(values["guild_id"]), "guild id"),
        (str(values["bot_user_id"]), "bot user id"),
    )
    for value, label in identifiers:
        if not SNOWFLAKE_RE.fullmatch(value):
            print(f"{label} must be a Discord snowflake", file=sys.stderr)
            return 2
    binding_sha256 = str(values["binding_sha256"])
    if not BINDING_DIGEST_RE.fullmatch(binding_sha256):
        print("binding sha256 must be 64 lowercase hex characters", file=sys.stderr)
        return 2
    if (
        not str(values["request_action"]).strip()
        or len(str(values["request_action"])) > 200
        or "\x00" in str(values["request_action"])
    ):
        print("request action is invalid", file=sys.stderr)
        return 2
    if (
        not str(values["request_target"]).strip()
        or len(str(values["request_target"])) > 2000
        or "\x00" in str(values["request_target"])
    ):
        print("request target is invalid", file=sys.stderr)
        return 2

    status = "approved" if action == "approve" else "rejected"
    try:
        path = write_marker(
            action,
            status,
            sha,
            full_sha,
            str(values["channel_id"]),
            str(values["message_id"]),
            str(values["interaction_id"]),
            str(values["user_id"]),
            str(values["application_id"]),
            str(values["guild_id"]),
            str(values["bot_user_id"]),
            str(values["request_action"]),
            str(values["request_target"]),
            binding_sha256,
        )
    except ConflictingDecisionError:
        print("approval request was already decided", file=sys.stderr)
        return CONFLICT_EXIT_CODE
    print(f"{status}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
