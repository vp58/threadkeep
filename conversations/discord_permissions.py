"""Read-only least-privilege verification for the Claude Discord bot."""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from config import CONFIG


SNOWFLAKE = re.compile(r"[1-9][0-9]{16,19}\Z")
SAFE_SESSION_ID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")

ADMINISTRATOR = 1 << 3
ADD_REACTIONS = 1 << 6
VIEW_CHANNEL = 1 << 10
SEND_MESSAGES = 1 << 11
ATTACH_FILES = 1 << 15
READ_MESSAGE_HISTORY = 1 << 16
MANAGE_THREADS = 1 << 34
CREATE_PUBLIC_THREADS = 1 << 35
CREATE_PRIVATE_THREADS = 1 << 36
SEND_MESSAGES_IN_THREADS = 1 << 38

# Permissions that a dedicated message transport must never receive through a
# guild role. These are copied from the Codex transport's reviewed policy.
FORBIDDEN_GUILD_PERMISSION_BITS = {
    "KICK_MEMBERS": 1 << 1,
    "BAN_MEMBERS": 1 << 2,
    "ADMINISTRATOR": ADMINISTRATOR,
    "MANAGE_CHANNELS": 1 << 4,
    "MANAGE_GUILD": 1 << 5,
    "VIEW_AUDIT_LOG": 1 << 7,
    "MANAGE_MESSAGES": 1 << 13,
    "VIEW_GUILD_INSIGHTS": 1 << 19,
    "MUTE_MEMBERS": 1 << 22,
    "DEAFEN_MEMBERS": 1 << 23,
    "MOVE_MEMBERS": 1 << 24,
    "MANAGE_NICKNAMES": 1 << 27,
    "MANAGE_ROLES": 1 << 28,
    "MANAGE_WEBHOOKS": 1 << 29,
    "MANAGE_GUILD_EXPRESSIONS": 1 << 30,
    "MANAGE_EVENTS": 1 << 33,
    "MANAGE_THREADS": MANAGE_THREADS,
    "MODERATE_MEMBERS": 1 << 40,
    "VIEW_CREATOR_MONETIZATION_ANALYTICS": 1 << 41,
    "CREATE_GUILD_EXPRESSIONS": 1 << 43,
    "CREATE_EVENTS": 1 << 44,
}

FORBIDDEN_CHANNEL_PERMISSION_BITS = {
    **FORBIDDEN_GUILD_PERMISSION_BITS,
    "CREATE_INSTANT_INVITE": 1 << 0,
    "SEND_TTS_MESSAGES": 1 << 12,
    "MENTION_EVERYONE": 1 << 17,
    "CREATE_PRIVATE_THREADS": CREATE_PRIVATE_THREADS,
    "SEND_VOICE_MESSAGES": 1 << 46,
    "SEND_POLLS": 1 << 49,
    "USE_EXTERNAL_APPS": 1 << 50,
    "PIN_MESSAGES": 1 << 51,
}

# Anthropic's official Discord plugin documents the first six permissions.
# Disco Party additionally creates public conversation threads.
CHAT_REQUIRED_PERMISSION_BITS = {
    "ADD_REACTIONS": ADD_REACTIONS,
    "VIEW_CHANNEL": VIEW_CHANNEL,
    "SEND_MESSAGES": SEND_MESSAGES,
    "ATTACH_FILES": ATTACH_FILES,
    "READ_MESSAGE_HISTORY": READ_MESSAGE_HISTORY,
    "CREATE_PUBLIC_THREADS": CREATE_PUBLIC_THREADS,
    "SEND_MESSAGES_IN_THREADS": SEND_MESSAGES_IN_THREADS,
}
CHAT_REQUIRED_PERMISSIONS = sum(CHAT_REQUIRED_PERMISSION_BITS.values())

ERRORS_REQUIRED_PERMISSION_BITS = {
    "VIEW_CHANNEL": VIEW_CHANNEL,
    "SEND_MESSAGES": SEND_MESSAGES,
    "READ_MESSAGE_HISTORY": READ_MESSAGE_HISTORY,
}

# The root remains visible to ordinary guild members, but only the dedicated
# bot may create threads. Otherwise any member could create an unregistered
# public thread, causing the runtime verifier to stop the listener on drift.
PUBLIC_CHAT_FORBIDDEN_PERMISSION_BITS = {
    "MANAGE_THREADS": MANAGE_THREADS,
    "CREATE_PUBLIC_THREADS": CREATE_PUBLIC_THREADS,
    "CREATE_PRIVATE_THREADS": CREATE_PRIVATE_THREADS,
}

GUILD_TEXT = 0
GUILD_VOICE = 2
GUILD_CATEGORY = 4
GUILD_ANNOUNCEMENT = 5
GUILD_STAGE_VOICE = 13
GUILD_DIRECTORY = 14
GUILD_FORUM = 15
GUILD_MEDIA = 16
PUBLIC_THREAD = 11
PRIVATE_THREAD = 12
GUILD_CHANNEL_TYPES = {
    GUILD_TEXT,
    GUILD_VOICE,
    GUILD_CATEGORY,
    GUILD_ANNOUNCEMENT,
    GUILD_STAGE_VOICE,
    GUILD_DIRECTORY,
    GUILD_FORUM,
    GUILD_MEDIA,
}
ROLE_OVERWRITE = 0
MEMBER_OVERWRITE = 1
CHANNEL_OBFUSCATED = 1 << 17
MAX_REGISTRY_BYTES = 16 * 1024 * 1024
MAX_CONVERSATION_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_PAGES = 1000

DiscordRequest = Callable[[str, str, str], Any]


@dataclass(frozen=True)
class PermissionConfig:
    guild_id: str
    chat_channel_id: str
    errors_channel_id: str
    bot_user_id: str
    application_id: str
    conversations_dir: Path


@dataclass(frozen=True)
class _Overwrite:
    target_id: str
    target_type: int
    allow: int
    deny: int


@dataclass(frozen=True)
class _RootChannel:
    channel_id: str
    parent_id: str | None
    overwrites: dict[tuple[int, str], _Overwrite]


def _runtime_config() -> PermissionConfig:
    return PermissionConfig(
        guild_id=CONFIG.discord.guild_id,
        chat_channel_id=CONFIG.discord.chat_channel_id,
        errors_channel_id=CONFIG.discord.errors_channel_id,
        bot_user_id=CONFIG.discord.bot_user_id,
        application_id=CONFIG.discord.application_id,
        conversations_dir=CONFIG.paths.conversations_dir,
    )


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


def _array(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


def _snowflake(value: Any, field: str) -> str:
    if isinstance(value, bool):
        raise RuntimeError(f"Discord returned malformed {field}")
    normalized = str(value or "")
    if not SNOWFLAKE.fullmatch(normalized):
        raise RuntimeError(f"Discord returned malformed {field}")
    return normalized


def _optional_snowflake(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _snowflake(value, field)


def _bitfield(value: Any, field: str) -> int:
    if (
        not isinstance(value, str)
        or not value
        or any(character < "0" or character > "9" for character in value)
    ):
        raise RuntimeError(f"Discord returned malformed {field}")
    return int(value)


def _active_timeout(value: Any) -> bool:
    if value is None:
        return False
    if not isinstance(value, str) or not value:
        raise RuntimeError("Discord returned malformed communication_disabled_until")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        deadline = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RuntimeError(
            "Discord returned malformed communication_disabled_until"
        ) from exc
    if deadline.tzinfo is None or deadline.utcoffset() is None:
        raise RuntimeError("Discord returned malformed communication_disabled_until")
    return deadline.astimezone(timezone.utc) > datetime.now(timezone.utc)


def _default_request(token: str, method: str, path: str) -> Any:
    from discord_http import request as http_request

    _, raw = http_request(method, path, token)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Discord REST response is not valid JSON") from exc


def _parse_roles(guild: dict[str, Any], guild_id: str) -> dict[str, int]:
    roles: dict[str, int] = {}
    for index, raw_role in enumerate(_array(guild.get("roles"), "guild roles")):
        role = _mapping(raw_role, f"guild role {index}")
        role_id = _snowflake(role.get("id"), f"guild role {index} id")
        if role_id in roles:
            raise RuntimeError("Discord returned duplicate guild role IDs")
        roles[role_id] = _bitfield(
            role.get("permissions"), f"guild role {role_id} permissions"
        )
    if guild_id not in roles:
        raise RuntimeError("Discord response omitted the @everyone role")
    return roles


def _parse_member_roles(
    member: dict[str, Any], roles: dict[str, int], guild_id: str
) -> list[str]:
    assigned: list[str] = []
    seen: set[str] = set()
    for index, raw_role_id in enumerate(_array(member.get("roles"), "member roles")):
        role_id = _snowflake(raw_role_id, f"member role {index}")
        if role_id == guild_id or role_id in seen:
            raise RuntimeError("Discord returned malformed member roles")
        if role_id not in roles:
            raise RuntimeError("Discord member references an unknown guild role")
        seen.add(role_id)
        assigned.append(role_id)
    return assigned


def _parse_overwrites(channel: dict[str, Any]) -> dict[tuple[int, str], _Overwrite]:
    overwrites: dict[tuple[int, str], _Overwrite] = {}
    for index, raw_overwrite in enumerate(
        _array(channel.get("permission_overwrites"), "channel permission_overwrites")
    ):
        overwrite = _mapping(raw_overwrite, f"permission overwrite {index}")
        target_id = _snowflake(
            overwrite.get("id"), f"permission overwrite {index} id"
        )
        target_type = _integer(
            overwrite.get("type"), f"permission overwrite {index} type"
        )
        if target_type not in {ROLE_OVERWRITE, MEMBER_OVERWRITE}:
            raise RuntimeError("Discord returned an unknown permission overwrite type")
        key = (target_type, target_id)
        if key in overwrites:
            raise RuntimeError("Discord returned duplicate permission overwrites")
        overwrites[key] = _Overwrite(
            target_id=target_id,
            target_type=target_type,
            allow=_bitfield(overwrite.get("allow"), "permission overwrite allow"),
            deny=_bitfield(overwrite.get("deny"), "permission overwrite deny"),
        )
    return overwrites


def _validate_overwrite_roles(
    overwrites: dict[tuple[int, str], _Overwrite], roles: dict[str, int]
) -> None:
    if any(
        target_type == ROLE_OVERWRITE and target_id not in roles
        for target_type, target_id in overwrites
    ):
        raise RuntimeError("Discord channel overwrite references an unknown guild role")


def _apply(permissions: int, overwrite: _Overwrite | None) -> int:
    if overwrite is None:
        return permissions
    return (permissions & ~overwrite.deny) | overwrite.allow


def _public_everyone_permissions(
    roles: dict[str, int],
    guild_id: str,
    overwrites: dict[tuple[int, str], _Overwrite],
) -> int:
    permissions = roles[guild_id]
    if permissions & ADMINISTRATOR:
        return permissions | VIEW_CHANNEL
    return _apply(permissions, overwrites.get((ROLE_OVERWRITE, guild_id)))


def _bot_permissions(
    *,
    bot_id: str,
    guild_id: str,
    roles: dict[str, int],
    assigned_roles: list[str],
    overwrites: dict[tuple[int, str], _Overwrite],
) -> int:
    permissions = roles[guild_id]
    for role_id in assigned_roles:
        permissions |= roles[role_id]
    permissions = _apply(permissions, overwrites.get((ROLE_OVERWRITE, guild_id)))

    deny = 0
    allow = 0
    for role_id in assigned_roles:
        overwrite = overwrites.get((ROLE_OVERWRITE, role_id))
        if overwrite is not None:
            deny |= overwrite.deny
            allow |= overwrite.allow
    permissions = (permissions & ~deny) | allow
    return _apply(permissions, overwrites.get((MEMBER_OVERWRITE, bot_id)))


def _forbidden_names(permissions: int, policy: dict[str, int]) -> list[str]:
    return [name for name, bit in policy.items() if permissions & bit]


def _missing_names(permissions: int, policy: dict[str, int]) -> list[str]:
    return [name for name, bit in policy.items() if not permissions & bit]


def _root_channel(
    payload: Any, expected_id: str, expected_guild_id: str, label: str
) -> _RootChannel:
    channel = _mapping(payload, label)
    if _snowflake(channel.get("id"), f"{label} id") != expected_id:
        raise RuntimeError(f"Discord returned a different {label}")
    if _snowflake(channel.get("guild_id"), f"{label} guild_id") != expected_guild_id:
        raise RuntimeError(f"Configured {label} belongs to a different guild")
    if _integer(channel.get("type"), f"{label} type") != GUILD_TEXT:
        raise RuntimeError(f"Configured {label} must be a GUILD_TEXT channel")
    flags = 0 if "flags" not in channel else _integer(channel["flags"], f"{label} flags")
    if flags < 0 or flags & CHANNEL_OBFUSCATED:
        raise RuntimeError(f"Configured {label} is obfuscated")
    return _RootChannel(
        channel_id=expected_id,
        parent_id=_optional_snowflake(channel.get("parent_id"), f"{label} parent_id"),
        overwrites=_parse_overwrites(channel),
    )


def _unquote_scalar(value: str) -> str | None:
    normalized = value.strip()
    if normalized in {"", "null", "~"}:
        return None
    if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in {"'", '"'}:
        normalized = normalized[1:-1]
    return normalized


def _conversation_binding(
    path: Path, *, allow_legacy_readonly: bool = False
) -> tuple[str | None, str | None, str | None]:
    raw = _stable_private_read(
        path,
        MAX_CONVERSATION_BYTES,
        "Disco Party conversation registration",
        allow_legacy_readonly=allow_legacy_readonly,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise RuntimeError("Disco Party conversation registration is not valid UTF-8") from exc
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise RuntimeError("Disco Party conversation registration lacks frontmatter")
    values: dict[str, str | None] = {}
    for line in lines[1:257]:
        if line == "---":
            return (
                values.get("claude_session_id"),
                values.get("discord_thread_id"),
                values.get("discord_channel_id"),
            )
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        if key in {"claude_session_id", "discord_thread_id", "discord_channel_id"}:
            values[key] = _unquote_scalar(raw)
    raise RuntimeError("Disco Party conversation frontmatter is not bounded")


def _stable_private_read(
    path: Path,
    maximum: int,
    label: str,
    *,
    allow_legacy_readonly: bool = False,
) -> bytes:
    """Read one current-owner 0600 regular file without following symlinks."""

    absolute = Path(os.path.abspath(path.expanduser()))
    try:
        before = os.lstat(absolute)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(before.st_mode):
        raise RuntimeError(f"{label} must not use symlinks")
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"{label} is not a regular file")
    if before.st_uid != os.getuid():
        raise RuntimeError(f"{label} is not owned by the current user")
    before_mode = stat.S_IMODE(before.st_mode)
    if before_mode != 0o600 and not (
        allow_legacy_readonly and not before_mode & 0o022 and before_mode & 0o400
    ):
        raise RuntimeError(f"{label} must have mode 0600")
    if before.st_size > maximum:
        raise RuntimeError(f"{label} exceeds its size limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != before_mode
            or opened.st_size > maximum
        ):
            raise RuntimeError(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > maximum:
            raise RuntimeError(f"{label} exceeds its size limit")
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or len(raw) != opened.st_size
        ):
            raise RuntimeError(f"{label} changed while it was read")
        return raw
    finally:
        os.close(descriptor)


def _harden_private_file(path: Path, label: str) -> bool:
    """Safely migrate one current-owner, nonwritable legacy file to 0600."""

    try:
        before = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(before.st_mode):
        raise RuntimeError(f"{label} must not use symlinks")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError(f"{label} must be a single-link regular file")
    if before.st_uid != os.getuid():
        raise RuntimeError(f"{label} is not owned by the current user")
    mode = stat.S_IMODE(before.st_mode)
    if mode & 0o022 or not mode & 0o400:
        raise RuntimeError(f"{label} has an unsafe legacy mode")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != mode
        ):
            raise RuntimeError(f"{label} changed before mode migration")
        if mode == 0o600:
            return False
        os.fchmod(descriptor, 0o600)
        after = os.fstat(descriptor)
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_uid != os.getuid()
            or stat.S_IMODE(after.st_mode) != 0o600
        ):
            raise RuntimeError(f"{label} mode migration did not bind to the same file")
        return True
    finally:
        os.close(descriptor)


def _harden_private_directory(path: Path, label: str) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"{label} must be a real directory")
    if metadata.st_uid != os.getuid():
        raise RuntimeError(f"{label} is not owned by the current user")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o022:
        raise RuntimeError(f"{label} is writable by another user")
    if mode == 0o700:
        return False
    os.chmod(path, 0o700, follow_symlinks=False)
    return True


def harden_registered_state(conversations_dir: Path) -> dict[str, int]:
    """Migrate reviewed legacy transcript, registry, and queue modes safely."""

    requested = conversations_dir.expanduser()
    requested.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = requested.resolve(strict=True)
    changed_directories = int(
        _harden_private_directory(root, "Disco Party conversations directory")
    )
    changed_files = 0
    candidates: list[tuple[Path, str]] = []
    for name in ("_registry.json", "INDEX.md"):
        path = root / name
        if path.exists() or path.is_symlink():
            candidates.append((path, f"Disco Party {name}"))
    for folder_name in ("active", "archived", "state"):
        folder = root / folder_name
        if not folder.exists() and not folder.is_symlink():
            continue
        changed_directories += int(
            _harden_private_directory(folder, f"Disco Party {folder_name} directory")
        )
        pattern = "*.md" if folder_name != "state" else "*"
        for path in sorted(folder.glob(pattern)):
            candidates.append((path, f"Disco Party {folder_name} state file"))
    for path, label in candidates:
        changed_files += int(_harden_private_file(path, label))
    return {"directories": changed_directories, "files": changed_files}


def load_registered_threads(
    conversations_dir: Path,
    chat_channel_id: str,
    *,
    allow_legacy_readonly: bool = False,
) -> set[str]:
    """Read the exact registry and verify it against canonical conversation files."""

    chat_channel_id = _snowflake(chat_channel_id, "configured chat channel id")
    # Canonicalize the configured root once. This accepts macOS's normal
    # /var -> /private/var alias, then rejects symlinks beneath that boundary.
    root = conversations_dir.expanduser().resolve(strict=False)
    registry_path = root / "_registry.json"
    file_bindings: dict[str, str] = {}
    for folder_name in ("active", "archived"):
        folder = root / folder_name
        if not folder.exists() and not folder.is_symlink():
            continue
        try:
            folder_metadata = os.lstat(folder)
        except OSError as exc:
            raise RuntimeError("Disco Party conversation directory cannot be inspected") from exc
        if stat.S_ISLNK(folder_metadata.st_mode) or not stat.S_ISDIR(folder_metadata.st_mode):
            raise RuntimeError("Disco Party conversation directory is malformed")
        for path in sorted(folder.glob("*.md")):
            session_id, thread_id, channel_id = _conversation_binding(
                path, allow_legacy_readonly=allow_legacy_readonly
            )
            if thread_id is None:
                continue
            session_id = session_id or path.stem
            if not SAFE_SESSION_ID.fullmatch(session_id) or session_id != path.stem:
                raise RuntimeError("Disco Party conversation session binding is malformed")
            thread_id = _snowflake(thread_id, "registered Discord thread id")
            if _snowflake(channel_id, "registered Discord channel id") != chat_channel_id:
                raise RuntimeError("Registered Discord thread belongs to a different root")
            if thread_id in file_bindings:
                raise RuntimeError("Disco Party conversation files duplicate a Discord thread")
            file_bindings[thread_id] = session_id

    if not registry_path.exists() and not registry_path.is_symlink():
        if file_bindings:
            raise RuntimeError("Disco Party registry is missing registered conversations")
        return set()
    raw = _stable_private_read(
        registry_path,
        MAX_REGISTRY_BYTES,
        "Disco Party registry",
        allow_legacy_readonly=allow_legacy_readonly,
    )
    try:
        registry = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Disco Party registry is not valid JSON") from exc
    registry = _mapping(registry, "Disco Party registry")
    if registry.get("schema_version") != 1:
        raise RuntimeError("Disco Party registry schema is not supported")
    by_thread = _mapping(registry.get("by_thread"), "Disco Party thread registry")
    conversations = _mapping(
        registry.get("conversations"), "Disco Party conversation registry"
    )

    registered: dict[str, str] = {}
    for raw_thread_id, raw_session_id in by_thread.items():
        thread_id = _snowflake(raw_thread_id, "registered Discord thread id")
        if not isinstance(raw_session_id, str) or not SAFE_SESSION_ID.fullmatch(raw_session_id):
            raise RuntimeError("Disco Party thread registry has an invalid session id")
        if thread_id in registered:
            raise RuntimeError("Disco Party thread registry has a duplicate thread")
        entry = _mapping(
            conversations.get(raw_session_id), "Disco Party registered conversation"
        )
        if _snowflake(entry.get("thread_id"), "conversation thread id") != thread_id:
            raise RuntimeError("Disco Party registry thread binding is inconsistent")
        if _snowflake(entry.get("channel_id"), "conversation channel id") != chat_channel_id:
            raise RuntimeError("Disco Party registry conversation has a foreign channel")
        registered[thread_id] = raw_session_id

    for raw_session_id, raw_entry in conversations.items():
        if not isinstance(raw_session_id, str) or not SAFE_SESSION_ID.fullmatch(raw_session_id):
            raise RuntimeError("Disco Party conversation registry has an invalid session id")
        entry = _mapping(raw_entry, "Disco Party conversation registry entry")
        if entry.get("thread_id") is None:
            continue
        thread_id = _snowflake(entry.get("thread_id"), "conversation thread id")
        if registered.get(thread_id) != raw_session_id:
            raise RuntimeError("Disco Party conversation is missing its thread index")
        if _snowflake(entry.get("channel_id"), "conversation channel id") != chat_channel_id:
            raise RuntimeError("Disco Party registry conversation has a foreign channel")

    if registered != file_bindings:
        raise RuntimeError("Disco Party registry and conversation files disagree")
    return set(registered)


def _validate_thread(
    raw_thread: Any,
    *,
    guild_id: str,
    parent_id: str,
    registered_threads: set[str],
    seen_threads: set[str],
    field: str,
    archived: bool,
) -> str:
    thread = _mapping(raw_thread, field)
    thread_id = _snowflake(thread.get("id"), f"{field} id")
    if thread_id in seen_threads:
        raise RuntimeError("Discord returned a duplicate visible thread")
    if _snowflake(thread.get("guild_id"), f"{field} guild_id") != guild_id:
        raise RuntimeError("Discord returned a visible thread from another guild")
    if _integer(thread.get("type"), f"{field} type") != PUBLIC_THREAD:
        raise RuntimeError("Claude Discord bot can access a non-public thread")
    if _snowflake(thread.get("parent_id"), f"{field} parent_id") != parent_id:
        raise RuntimeError("Claude Discord bot can access a thread under another channel")
    if thread_id not in registered_threads:
        raise RuntimeError("Claude Discord bot can access an unregistered public thread")
    metadata = _mapping(thread.get("thread_metadata"), f"{field} metadata")
    if _boolean(metadata.get("archived"), f"{field} archived") is not archived:
        raise RuntimeError("Discord returned a thread with inconsistent archive state")
    seen_threads.add(thread_id)
    return thread_id


def _verify_archived_public_threads(
    *,
    token: str,
    guild_id: str,
    parent_id: str,
    registered_threads: set[str],
    seen_threads: set[str],
    request: DiscordRequest,
) -> None:
    before: str | None = None
    for page in range(MAX_ARCHIVE_PAGES):
        path = f"/channels/{parent_id}/threads/archived/public?limit=100"
        if before is not None:
            path += "&before=" + quote(before, safe="")
        payload = _mapping(request(token, "GET", path), "archived public threads")
        _array(payload.get("members"), "archived public thread members")
        threads = _array(payload.get("threads"), "archived public thread list")
        for index, thread in enumerate(threads):
            _validate_thread(
                thread,
                guild_id=guild_id,
                parent_id=parent_id,
                registered_threads=registered_threads,
                seen_threads=seen_threads,
                field=f"archived public thread {index}",
                archived=True,
            )
        has_more = _boolean(payload.get("has_more"), "archived public has_more")
        if not has_more:
            return
        if not threads:
            raise RuntimeError("Discord archived thread pagination made no progress")
        last = _mapping(threads[-1], "last archived public thread")
        metadata = _mapping(
            last.get("thread_metadata"), "last archived public thread metadata"
        )
        cursor = metadata.get("archive_timestamp")
        if not isinstance(cursor, str) or not cursor or cursor == before:
            raise RuntimeError("Discord archived thread pagination cursor is malformed")
        before = cursor
    raise RuntimeError("Discord archived thread inventory exceeded the verification limit")


def _verify_no_private_archived_threads(
    token: str, parent_id: str, request: DiscordRequest
) -> None:
    payload = _mapping(
        request(
            token,
            "GET",
            f"/channels/{parent_id}/users/@me/threads/archived/private?limit=1",
        ),
        "joined private archived threads",
    )
    _array(payload.get("members"), "joined private archived thread members")
    threads = _array(payload.get("threads"), "joined private archived thread list")
    if threads:
        raise RuntimeError("Claude Discord bot can access a private archived thread")
    if _boolean(payload.get("has_more"), "joined private archived has_more"):
        raise RuntimeError("Discord private archived thread inventory is inconsistent")


def verify_discord_permissions(
    token: str,
    config: PermissionConfig,
    *,
    request: DiscordRequest | None = None,
    registered_threads: set[str] | None = None,
    allow_legacy_state_modes: bool = False,
) -> dict[str, Any]:
    """Fail closed unless the Claude bot has only its reviewed Discord access."""

    if not token or len(token) > 4096 or any(character.isspace() for character in token):
        raise RuntimeError("Discord bot credential is empty or malformed")
    request = request or _default_request
    guild_id = _snowflake(config.guild_id, "configured guild_id")
    chat_id = _snowflake(config.chat_channel_id, "configured chat_channel_id")
    errors_id = _snowflake(config.errors_channel_id, "configured errors_channel_id")
    bot_id = _snowflake(config.bot_user_id, "configured bot_user_id")
    application_id = _snowflake(config.application_id, "configured application_id")
    if registered_threads is None:
        registered_threads = load_registered_threads(
            config.conversations_dir,
            chat_id,
            allow_legacy_readonly=allow_legacy_state_modes,
        )
    else:
        registered_threads = {
            _snowflake(value, "registered Discord thread id")
            for value in registered_threads
        }

    identity = _mapping(request(token, "GET", "/users/@me"), "current bot user")
    if identity.get("bot") is not True or _snowflake(
        identity.get("id"), "current bot user id"
    ) != bot_id:
        raise RuntimeError("Discord credential does not match the configured bot identity")

    application = _mapping(
        request(token, "GET", "/oauth2/applications/@me"), "current application"
    )
    if _snowflake(application.get("id"), "current application id") != application_id:
        raise RuntimeError(
            "Discord credential does not match the configured application identity"
        )
    application_bot = _mapping(application.get("bot"), "current application bot")
    if _snowflake(application_bot.get("id"), "current application bot id") != bot_id:
        raise RuntimeError("Discord application is associated with a different bot")

    guilds = _array(
        request(token, "GET", "/users/@me/guilds?limit=2"), "current bot guilds"
    )
    if len(guilds) != 1 or _snowflake(
        _mapping(guilds[0], "current bot guild").get("id"), "current bot guild id"
    ) != guild_id:
        raise RuntimeError("Claude Discord bot must belong to exactly the configured guild")

    roots: dict[str, _RootChannel] = {}
    roots[chat_id] = _root_channel(
        request(token, "GET", f"/channels/{chat_id}"), chat_id, guild_id, "chat channel"
    )
    if errors_id == chat_id:
        roots[errors_id] = roots[chat_id]
    else:
        roots[errors_id] = _root_channel(
            request(token, "GET", f"/channels/{errors_id}"),
            errors_id,
            guild_id,
            "errors channel",
        )

    guild = _mapping(
        request(token, "GET", f"/guilds/{guild_id}"), "configured guild"
    )
    if _snowflake(guild.get("id"), "guild id") != guild_id:
        raise RuntimeError("Discord returned a different guild than configured")
    guild_owner_id = _snowflake(guild.get("owner_id"), "guild owner_id")
    roles = _parse_roles(guild, guild_id)
    for root in roots.values():
        _validate_overwrite_roles(root.overwrites, roles)

    member = _mapping(
        request(token, "GET", f"/guilds/{guild_id}/members/{bot_id}"),
        "bot guild member",
    )
    member_user = _mapping(member.get("user"), "bot guild member user")
    if _snowflake(member_user.get("id"), "bot guild member user id") != bot_id:
        raise RuntimeError("Discord returned a guild member for a different bot")
    assigned_roles = _parse_member_roles(member, roles, guild_id)
    if member.get("pending", False) is not False:
        if member.get("pending") is not True:
            raise RuntimeError("Discord returned malformed pending membership state")
        raise RuntimeError("Discord bot guild membership is pending")
    if _active_timeout(member.get("communication_disabled_until")):
        raise RuntimeError("Discord bot guild member has an active timeout")
    if guild_owner_id == bot_id:
        raise RuntimeError("Discord bot must not own the configured guild")

    guild_permissions = roles[guild_id]
    for role_id in assigned_roles:
        guild_permissions |= roles[role_id]
    forbidden_guild = _forbidden_names(
        guild_permissions, FORBIDDEN_GUILD_PERMISSION_BITS
    )
    if forbidden_guild:
        raise RuntimeError(
            "Discord bot has forbidden guild permissions: "
            + ", ".join(forbidden_guild)
        )

    guild_channels = _array(
        request(token, "GET", f"/guilds/{guild_id}/channels"), "guild channels"
    )
    allowed_parent_ids = {
        root.parent_id for root in roots.values() if root.parent_id is not None
    }
    inventory_roots: dict[str, _RootChannel] = {}
    seen_channel_ids: set[str] = set()
    seen_parent_ids: set[str] = set()
    for index, raw_channel in enumerate(guild_channels):
        channel = _mapping(raw_channel, f"guild channel {index}")
        channel_id = _snowflake(channel.get("id"), f"guild channel {index} id")
        if channel_id in seen_channel_ids:
            raise RuntimeError("Discord returned duplicate guild channel IDs")
        seen_channel_ids.add(channel_id)
        channel_type = _integer(channel.get("type"), f"guild channel {channel_id} type")
        if channel_type not in GUILD_CHANNEL_TYPES:
            raise RuntimeError("Discord returned an unexpected guild channel type")
        if "guild_id" in channel and _snowflake(
            channel.get("guild_id"), f"guild channel {channel_id} guild_id"
        ) != guild_id:
            raise RuntimeError("Discord guild inventory contains a foreign channel")
        overwrites = _parse_overwrites(channel)
        _validate_overwrite_roles(overwrites, roles)
        effective = _bot_permissions(
            bot_id=bot_id,
            guild_id=guild_id,
            roles=roles,
            assigned_roles=assigned_roles,
            overwrites=overwrites,
        )

        if channel_id in roots:
            root = roots[channel_id]
            if channel_type != GUILD_TEXT:
                raise RuntimeError("Configured Discord root must be a GUILD_TEXT channel")
            inventory_parent = _optional_snowflake(
                channel.get("parent_id"), "configured root parent_id"
            )
            if inventory_parent != root.parent_id or overwrites != root.overwrites:
                raise RuntimeError(
                    "Configured Discord root changed during permission verification"
                )
            flags = 0 if "flags" not in channel else _integer(
                channel.get("flags"), "configured root flags"
            )
            if flags < 0 or flags & CHANNEL_OBFUSCATED:
                raise RuntimeError("Configured Discord root is obfuscated")
            inventory_roots[channel_id] = root
        elif channel_id in allowed_parent_ids:
            if channel_type != GUILD_CATEGORY:
                raise RuntimeError("Configured Discord root parent must be a category")
            seen_parent_ids.add(channel_id)
        elif effective & VIEW_CHANNEL:
            raise RuntimeError("Claude Discord bot can view an unrelated guild channel")

        if (channel_id in roots or channel_id in allowed_parent_ids) and effective & VIEW_CHANNEL:
            forbidden_channel = _forbidden_names(
                effective, FORBIDDEN_CHANNEL_PERMISSION_BITS
            )
            if forbidden_channel:
                raise RuntimeError(
                    "Discord bot has forbidden effective channel permissions: "
                    + ", ".join(forbidden_channel)
                )

    if set(inventory_roots) != set(roots):
        raise RuntimeError("Discord guild inventory omitted a configured root channel")
    if seen_parent_ids != allowed_parent_ids:
        raise RuntimeError("Discord guild inventory omitted a configured parent category")

    chat_effective = _bot_permissions(
        bot_id=bot_id,
        guild_id=guild_id,
        roles=roles,
        assigned_roles=assigned_roles,
        overwrites=roots[chat_id].overwrites,
    )
    public_chat_effective = _public_everyone_permissions(
        roles, guild_id, roots[chat_id].overwrites
    )
    if not public_chat_effective & VIEW_CHANNEL:
        raise RuntimeError("Configured Discord chat channel is not public to @everyone")
    public_thread_permissions = _forbidden_names(
        public_chat_effective, PUBLIC_CHAT_FORBIDDEN_PERMISSION_BITS
    )
    if public_thread_permissions:
        raise RuntimeError(
            "Configured Discord chat channel lets @everyone create or manage threads: "
            + ", ".join(public_thread_permissions)
        )
    missing_chat = _missing_names(chat_effective, CHAT_REQUIRED_PERMISSION_BITS)
    if missing_chat:
        raise RuntimeError(
            "Discord bot lacks required chat channel permissions: "
            + ", ".join(missing_chat)
        )

    errors_effective = _bot_permissions(
        bot_id=bot_id,
        guild_id=guild_id,
        roles=roles,
        assigned_roles=assigned_roles,
        overwrites=roots[errors_id].overwrites,
    )
    missing_errors = _missing_names(
        errors_effective, ERRORS_REQUIRED_PERMISSION_BITS
    )
    if missing_errors:
        raise RuntimeError(
            "Discord bot lacks required errors channel permissions: "
            + ", ".join(missing_errors)
        )

    active = _mapping(
        request(token, "GET", f"/guilds/{guild_id}/threads/active"),
        "active guild threads",
    )
    _array(active.get("members"), "active guild thread members")
    seen_threads: set[str] = set()
    for index, thread in enumerate(_array(active.get("threads"), "active guild threads list")):
        payload = _mapping(thread, f"active guild thread {index}")
        parent_id = _snowflake(
            payload.get("parent_id"), f"active guild thread {index} parent_id"
        )
        if parent_id != chat_id:
            raise RuntimeError("Claude Discord bot can access a thread under another channel")
        _validate_thread(
            payload,
            guild_id=guild_id,
            parent_id=chat_id,
            registered_threads=registered_threads,
            seen_threads=seen_threads,
            field=f"active guild thread {index}",
            archived=False,
        )

    for parent_id in roots:
        _verify_archived_public_threads(
            token=token,
            guild_id=guild_id,
            parent_id=parent_id,
            registered_threads=registered_threads,
            seen_threads=seen_threads,
            request=request,
        )
        _verify_no_private_archived_threads(token, parent_id, request)

    return {
        "application_id": application_id,
        "bot_user_id": bot_id,
        "guild_id": guild_id,
        "registered_thread_count": len(registered_threads),
        "visible_thread_count": len(seen_threads),
    }


def _override_config(args: argparse.Namespace) -> PermissionConfig:
    override_names = (
        "guild_id",
        "chat_channel_id",
        "errors_channel_id",
        "bot_user_id",
        "application_id",
        "conversations_dir",
    )
    supplied = [getattr(args, name) is not None for name in override_names]
    if any(supplied) and not all(supplied):
        raise RuntimeError("all Discord permission configuration overrides are required")
    if not any(supplied):
        return _runtime_config()
    return PermissionConfig(
        guild_id=args.guild_id,
        chat_channel_id=args.chat_channel_id,
        errors_channel_id=args.errors_channel_id,
        bot_user_id=args.bot_user_id,
        application_id=args.application_id,
        conversations_dir=Path(args.conversations_dir),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--token-stdin", action="store_true")
    verify_parser.add_argument("--guild-id")
    verify_parser.add_argument("--chat-channel-id")
    verify_parser.add_argument("--errors-channel-id")
    verify_parser.add_argument("--bot-user-id")
    verify_parser.add_argument("--application-id")
    verify_parser.add_argument("--conversations-dir")
    verify_parser.add_argument("--allow-legacy-readonly-state", action="store_true")
    harden_parser = subparsers.add_parser("harden-state")
    harden_parser.add_argument("--conversations-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "harden-state":
        print(json.dumps(harden_registered_state(args.conversations_dir), sort_keys=True))
        return 0
    if args.command != "verify":
        raise RuntimeError("unsupported Discord permission command")
    config = _override_config(args)
    if args.token_stdin:
        token = sys.stdin.read().strip()
    else:
        from discord_secret import load_discord_token

        token = load_discord_token(allow_environment=False)
    result = verify_discord_permissions(
        token,
        config,
        allow_legacy_state_modes=args.allow_legacy_readonly_state,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if CHAT_REQUIRED_PERMISSIONS != 0x0000004800018C40:
    raise RuntimeError("reviewed Claude Discord permission constant is inconsistent")


if __name__ == "__main__":
    raise SystemExit(main())
