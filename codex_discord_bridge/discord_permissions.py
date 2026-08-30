from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .config import Config


ADMINISTRATOR = 1 << 3
ADD_REACTIONS = 1 << 6
VIEW_CHANNEL = 1 << 10
SEND_MESSAGES = 1 << 11
READ_MESSAGE_HISTORY = 1 << 16
CREATE_PUBLIC_THREADS = 1 << 35
CREATE_PRIVATE_THREADS = 1 << 36
SEND_MESSAGES_IN_THREADS = 1 << 38
MANAGE_THREADS = 1 << 34
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
    "MANAGE_THREADS": 1 << 34,
    "MODERATE_MEMBERS": 1 << 40,
    "VIEW_CREATOR_MONETIZATION_ANALYTICS": 1 << 41,
    "CREATE_GUILD_EXPRESSIONS": 1 << 43,
    "CREATE_EVENTS": 1 << 44,
}

FORBIDDEN_TARGET_PERMISSION_BITS = {
    **FORBIDDEN_GUILD_PERMISSION_BITS,
    "CREATE_INSTANT_INVITE": 1 << 0,
    "SEND_TTS_MESSAGES": 1 << 12,
    "ATTACH_FILES": 1 << 15,
    "MENTION_EVERYONE": 1 << 17,
    "CREATE_PRIVATE_THREADS": 1 << 36,
    "SEND_VOICE_MESSAGES": 1 << 46,
    "SEND_POLLS": 1 << 49,
    "USE_EXTERNAL_APPS": 1 << 50,
    "PIN_MESSAGES": 1 << 51,
}

FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS = {
    "MANAGE_THREADS": MANAGE_THREADS,
    "CREATE_PUBLIC_THREADS": CREATE_PUBLIC_THREADS,
    "CREATE_PRIVATE_THREADS": CREATE_PRIVATE_THREADS,
}
PUBLIC_MEMBER_THREAD_GUARD_MASK = sum(FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.values())

REQUIRED_PERMISSION_BITS = {
    "ADD_REACTIONS": ADD_REACTIONS,
    "VIEW_CHANNEL": VIEW_CHANNEL,
    "SEND_MESSAGES": SEND_MESSAGES,
    "READ_MESSAGE_HISTORY": READ_MESSAGE_HISTORY,
    "CREATE_PUBLIC_THREADS": CREATE_PUBLIC_THREADS,
    "SEND_MESSAGES_IN_THREADS": SEND_MESSAGES_IN_THREADS,
}
REQUIRED_PERMISSIONS = 0x0000004800010C40

GUILD_TEXT = 0
GUILD_VOICE = 2
GUILD_CATEGORY = 4
GUILD_ANNOUNCEMENT = 5
GUILD_STAGE_VOICE = 13
GUILD_DIRECTORY = 14
GUILD_FORUM = 15
GUILD_MEDIA = 16
PUBLIC_THREAD = 11
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

DiscordRequest = Callable[..., Awaitable[Any]]


@dataclass(frozen=True)
class _Overwrite:
    target_id: str
    target_type: int
    allow: int
    deny: int


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


def _array(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


def _snowflake(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(character < "0" or character > "9" for character in value)
        or int(value) <= 0
    ):
        raise RuntimeError(f"Discord returned malformed {field}")
    number = int(value)
    if str(number) != value or number >= 1 << 64:
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


def _bitfield(value: Any, field: str) -> int:
    if (
        not isinstance(value, str)
        or not value
        or any(character < "0" or character > "9" for character in value)
    ):
        raise RuntimeError(f"Discord returned malformed {field}")
    return int(value)


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


def _optional_snowflake(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _snowflake(value, field)


def _optional_boolean(payload: dict[str, Any], field: str) -> bool:
    if field not in payload:
        return False
    value = payload[field]
    if not isinstance(value, bool):
        raise RuntimeError(f"Discord returned malformed {field}")
    return value


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
    raw_overwrites = _array(
        channel.get("permission_overwrites"), "channel permission_overwrites"
    )
    for index, raw_overwrite in enumerate(raw_overwrites):
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
            allow=_bitfield(
                overwrite.get("allow"), f"permission overwrite {index} allow"
            ),
            deny=_bitfield(
                overwrite.get("deny"), f"permission overwrite {index} deny"
            ),
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
    permissions &= ~overwrite.deny
    permissions |= overwrite.allow
    return permissions


def _public_everyone_permissions(
    roles: dict[str, int],
    guild_id: str,
    overwrites: dict[tuple[int, str], _Overwrite],
) -> int:
    permissions = roles[guild_id]
    if permissions & ADMINISTRATOR:
        return permissions | VIEW_CHANNEL
    return _apply(permissions, overwrites.get((ROLE_OVERWRITE, guild_id)))


def _validate_public_thread_overwrite_topology(
    *,
    overwrites: dict[tuple[int, str], _Overwrite],
    guild_id: str,
    bot_id: str,
) -> None:
    """Require a channel-local deny with one narrowly scoped bot exception.

    Discord applies role and member overwrite allows after the ``@everyone``
    overwrite. Checking only the effective ``@everyone`` permissions therefore
    misses a role or member allow that can restore thread-management powers for
    another public member.
    """

    everyone = overwrites.get((ROLE_OVERWRITE, guild_id))
    missing_denies = [
        name
        for name, permission in FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.items()
        if everyone is None or not everyone.deny & permission
    ]
    if missing_denies:
        raise RuntimeError(
            "The @everyone channel overwrite must explicitly deny thread permissions: "
            + ", ".join(missing_denies)
        )

    bot_member = overwrites.get((MEMBER_OVERWRITE, bot_id))
    if (
        bot_member is None
        or not bot_member.allow & CREATE_PUBLIC_THREADS
        or bot_member.deny & CREATE_PUBLIC_THREADS
    ):
        raise RuntimeError(
            "The configured bot member overwrite must exclusively restore "
            "CREATE_PUBLIC_THREADS"
        )

    for key, overwrite in overwrites.items():
        allowed_thread_bits = overwrite.allow & PUBLIC_MEMBER_THREAD_GUARD_MASK
        permitted = (
            CREATE_PUBLIC_THREADS
            if key == (MEMBER_OVERWRITE, bot_id)
            else 0
        )
        forbidden_allowed = allowed_thread_bits & ~permitted
        if forbidden_allowed:
            names = [
                name
                for name, permission in FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.items()
                if forbidden_allowed & permission
            ]
            raise RuntimeError(
                "Discord channel overwrite can restore forbidden public thread "
                f"permissions for {key[1]}: " + ", ".join(names)
            )


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

    permissions = _apply(
        permissions, overwrites.get((ROLE_OVERWRITE, guild_id))
    )

    deny = 0
    allow = 0
    for role_id in assigned_roles:
        overwrite = overwrites.get((ROLE_OVERWRITE, role_id))
        if overwrite is not None:
            deny |= overwrite.deny
            allow |= overwrite.allow
    permissions &= ~deny
    permissions |= allow

    return _apply(
        permissions, overwrites.get((MEMBER_OVERWRITE, bot_id))
    )


async def verify_discord_permissions(
    token: str,
    config: Config,
    request: DiscordRequest | None = None,
) -> None:
    """Fail closed unless the dedicated bot can operate in the public channel."""

    if request is None:
        from .discord_io import discord_request

        request = discord_request

    expected_bot_id = _snowflake(config.bot_user_id, "configured bot_user_id")
    expected_application_id = _snowflake(
        config.application_id, "configured application_id"
    )
    expected_channel_id = _snowflake(config.channel_id, "configured channel_id")
    expected_guild_id = _snowflake(config.guild_id, "configured guild_id")

    identity = _mapping(
        await request(token, "GET", "/users/@me"), "current bot user"
    )
    bot_id = _snowflake(identity.get("id"), "current bot user id")
    if bot_id != expected_bot_id or identity.get("bot") is not True:
        raise RuntimeError("Discord credential does not match the configured bot identity")

    application = _mapping(
        await request(token, "GET", "/oauth2/applications/@me"),
        "current application",
    )
    if (
        _snowflake(application.get("id"), "current application id")
        != expected_application_id
    ):
        raise RuntimeError(
            "Discord credential does not match the configured application identity"
        )
    if "bot" in application:
        application_bot = _mapping(application["bot"], "current application bot")
        if _snowflake(application_bot.get("id"), "current application bot id") != bot_id:
            raise RuntimeError("Discord application is associated with a different bot")

    channel = _mapping(
        await request(token, "GET", f"/channels/{expected_channel_id}"),
        "configured channel",
    )
    if _snowflake(channel.get("id"), "channel id") != expected_channel_id:
        raise RuntimeError("Discord returned a different channel than configured")
    channel_guild_id = _snowflake(channel.get("guild_id"), "channel guild_id")
    if channel_guild_id != expected_guild_id:
        raise RuntimeError("Configured Discord channel belongs to a different guild")
    if _integer(channel.get("type"), "channel type") != GUILD_TEXT:
        raise RuntimeError("Configured Discord channel must be a GUILD_TEXT channel")
    flags = 0 if "flags" not in channel else _integer(channel["flags"], "channel flags")
    if flags < 0:
        raise RuntimeError("Discord returned malformed channel flags")
    if flags & CHANNEL_OBFUSCATED:
        raise RuntimeError("Configured Discord channel is obfuscated")
    target_parent_id = _optional_snowflake(channel.get("parent_id"), "channel parent_id")
    overwrites = _parse_overwrites(channel)

    guild = _mapping(
        await request(token, "GET", f"/guilds/{expected_guild_id}"),
        "configured guild",
    )
    if _snowflake(guild.get("id"), "guild id") != expected_guild_id:
        raise RuntimeError("Discord returned a different guild than configured")
    owner_id = _snowflake(guild.get("owner_id"), "guild owner_id")
    roles = _parse_roles(guild, expected_guild_id)
    _validate_overwrite_roles(overwrites, roles)

    member = _mapping(
        await request(
            token,
            "GET",
            f"/guilds/{expected_guild_id}/members/{bot_id}",
        ),
        "bot guild member",
    )
    member_user = _mapping(member.get("user"), "bot guild member user")
    if _snowflake(member_user.get("id"), "bot guild member user id") != bot_id:
        raise RuntimeError("Discord returned a guild member for a different bot")
    assigned_roles = _parse_member_roles(member, roles, expected_guild_id)
    if _optional_boolean(member, "pending"):
        raise RuntimeError("Discord bot guild membership is pending")
    if _active_timeout(member.get("communication_disabled_until")):
        raise RuntimeError("Discord bot guild member has an active timeout")
    guild_permissions = roles[expected_guild_id]
    for role_id in assigned_roles:
        guild_permissions |= roles[role_id]
    if bot_id == owner_id:
        raise RuntimeError("Discord bot must not own the configured guild")
    forbidden = [
        name
        for name, permission in FORBIDDEN_GUILD_PERMISSION_BITS.items()
        if guild_permissions & permission
    ]
    if forbidden:
        raise RuntimeError(
            "Discord bot has forbidden guild permissions: " + ", ".join(forbidden)
        )

    guild_channels = _array(
        await request(token, "GET", f"/guilds/{expected_guild_id}/channels"),
        "guild channels",
    )
    seen_channel_ids: set[str] = set()
    inventory_target: dict[str, Any] | None = None
    inventory_target_overwrites: dict[tuple[int, str], _Overwrite] | None = None
    target_parent_seen = target_parent_id is None
    for index, raw_guild_channel in enumerate(guild_channels):
        guild_channel = _mapping(raw_guild_channel, f"guild channel {index}")
        guild_channel_id = _snowflake(
            guild_channel.get("id"), f"guild channel {index} id"
        )
        if guild_channel_id in seen_channel_ids:
            raise RuntimeError("Discord returned duplicate guild channel IDs")
        seen_channel_ids.add(guild_channel_id)
        channel_type = _integer(
            guild_channel.get("type"), f"guild channel {guild_channel_id} type"
        )
        if channel_type not in GUILD_CHANNEL_TYPES:
            raise RuntimeError("Discord returned an unexpected guild channel type")
        if "guild_id" in guild_channel and _snowflake(
            guild_channel["guild_id"], f"guild channel {guild_channel_id} guild_id"
        ) != expected_guild_id:
            raise RuntimeError("Discord guild inventory contains a foreign channel")
        guild_channel_overwrites = _parse_overwrites(guild_channel)
        _validate_overwrite_roles(guild_channel_overwrites, roles)
        channel_effective = _bot_permissions(
            bot_id=bot_id,
            guild_id=expected_guild_id,
            roles=roles,
            assigned_roles=assigned_roles,
            overwrites=guild_channel_overwrites,
        )
        if target_parent_id is not None and guild_channel_id == target_parent_id:
            if channel_type != GUILD_CATEGORY:
                raise RuntimeError(
                    "Configured Discord channel parent must be a GUILD_CATEGORY"
                )
            target_parent_seen = True
        if guild_channel_id == expected_channel_id:
            if channel_type != GUILD_TEXT:
                raise RuntimeError(
                    "Configured Discord channel must be a GUILD_TEXT channel"
                )
            inventory_parent_id = _optional_snowflake(
                guild_channel.get("parent_id"),
                "configured guild channel parent_id",
            )
            if inventory_parent_id != target_parent_id:
                raise RuntimeError(
                    "Configured Discord channel parent changed during verification"
                )
            inventory_flags = (
                0
                if "flags" not in guild_channel
                else _integer(guild_channel["flags"], "configured guild channel flags")
            )
            if inventory_flags < 0 or inventory_flags & CHANNEL_OBFUSCATED:
                raise RuntimeError("Configured Discord channel is obfuscated")
            inventory_target = guild_channel
            inventory_target_overwrites = guild_channel_overwrites
            continue
        if (
            channel_effective & VIEW_CHANNEL
            and not (
                channel_type == GUILD_CATEGORY
                and target_parent_id is not None
                and guild_channel_id == target_parent_id
            )
        ):
            raise RuntimeError(
                "Dedicated Discord bot can view an unrelated guild channel"
            )
    if inventory_target is None or inventory_target_overwrites is None:
        raise RuntimeError("Discord guild inventory omitted the configured channel")
    if not target_parent_seen:
        raise RuntimeError("Discord guild inventory omitted the configured parent category")
    if inventory_target_overwrites != overwrites:
        raise RuntimeError(
            "Configured Discord channel permissions changed during verification"
        )
    active_threads = _mapping(
        await request(
            token,
            "GET",
            f"/guilds/{expected_guild_id}/threads/active",
        ),
        "active guild threads",
    )
    _array(active_threads.get("members"), "active guild thread members")
    seen_thread_ids: set[str] = set()
    for index, raw_thread in enumerate(
        _array(active_threads.get("threads"), "active guild threads list")
    ):
        thread = _mapping(raw_thread, f"active guild thread {index}")
        thread_id = _snowflake(thread.get("id"), f"active guild thread {index} id")
        if thread_id in seen_thread_ids or thread_id in seen_channel_ids:
            raise RuntimeError("Discord returned duplicate active thread IDs")
        seen_thread_ids.add(thread_id)
        if "guild_id" in thread and _snowflake(
            thread["guild_id"], f"active guild thread {thread_id} guild_id"
        ) != expected_guild_id:
            raise RuntimeError("Discord active thread inventory contains a foreign thread")
        thread_type = _integer(
            thread.get("type"), f"active guild thread {thread_id} type"
        )
        parent_id = _optional_snowflake(
            thread.get("parent_id"), f"active guild thread {thread_id} parent_id"
        )
        if thread_type != PUBLIC_THREAD or parent_id != expected_channel_id:
            raise RuntimeError(
                "Dedicated Discord bot can access an unrelated active thread"
            )

    everyone_permissions = _public_everyone_permissions(
        roles, expected_guild_id, inventory_target_overwrites
    )
    if config.channel_trust == "public":
        if not everyone_permissions & VIEW_CHANNEL:
            raise RuntimeError(
                "Configured public Discord channel is not visible to the @everyone baseline"
            )
    elif everyone_permissions & VIEW_CHANNEL:
        raise RuntimeError(
            "Configured owner_private Discord channel is visible to the @everyone baseline"
        )
    public_thread_permissions = [
        name
        for name, permission in FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.items()
        if everyone_permissions & permission
    ]
    if public_thread_permissions:
        raise RuntimeError(
            "Public @everyone baseline has forbidden thread permissions: "
            + ", ".join(public_thread_permissions)
        )

    effective = _bot_permissions(
        bot_id=bot_id,
        guild_id=expected_guild_id,
        roles=roles,
        assigned_roles=assigned_roles,
        overwrites=inventory_target_overwrites,
    )
    forbidden_effective = [
        name
        for name, permission in FORBIDDEN_TARGET_PERMISSION_BITS.items()
        if effective & permission
    ]
    if forbidden_effective:
        raise RuntimeError(
            "Discord bot has forbidden effective channel permissions: "
            + ", ".join(forbidden_effective)
        )
    missing = [
        name
        for name, permission in REQUIRED_PERMISSION_BITS.items()
        if not effective & permission
    ]
    if missing:
        raise RuntimeError(
            "Discord bot lacks required channel permissions: " + ", ".join(missing)
        )
    _validate_public_thread_overwrite_topology(
        overwrites=inventory_target_overwrites,
        guild_id=expected_guild_id,
        bot_id=bot_id,
    )


if sum(REQUIRED_PERMISSION_BITS.values()) != REQUIRED_PERMISSIONS:
    raise RuntimeError("reviewed Discord permission constant is inconsistent")
