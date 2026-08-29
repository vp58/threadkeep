from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import pwd
import random
import re
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path

from websockets.asyncio.client import connect as _WebSocketConnect
from websockets.exceptions import ConnectionClosed

from conversations.public_output import (
    SECRET_PATTERNS,
    SENSITIVE_DATA_PATTERNS,
    contains_secret_data,
    contains_sensitive_data,
    redact_credentials,
    public_safe_output as _shared_public_safe_output,
    withheld_notice,
)

from .config import Config
from .discord_permissions import ADMINISTRATOR, VIEW_CHANNEL
from .identify_budget import IdentifyBudget
from .ingress import MessageEvent, RejectedEvent, authorize
from .store import IngressLimitExceeded, JobStore


GATEWAY = "wss://gateway.discord.gg/?v=10&encoding=json"
BASE_INTENTS = (1 << 0) | (1 << 9) | (1 << 15)  # GUILDS + GUILD_MESSAGES + MESSAGE_CONTENT
GUILD_MEMBERS_INTENT = 1 << 1
DISCORD_LIMIT = 2000
CHUNK_LIMIT = 1980
# Discord documents enforce_nonce as de-duplicating only messages sent in the
# past few minutes. Stay well inside that vague server window; older attempts
# require one bounded history reconciliation or are quarantined.
NONCE_RETRY_WINDOW_SECONDS = 60
DELIVERY_HISTORY_MAX_PAGES = 50
DELIVERY_RATE_LIMIT_MAX_RETRIES = 4
log = logging.getLogger("codex_discord_bridge.discord")
RESET_SESSION_CLOSE_CODES = {1000, 4007, 4009}
FATAL_GATEWAY_CLOSE_CODES = {4004, 4010, 4011, 4012, 4013, 4014}
SECURITY_RECHECK_EVENTS = {
    "CHANNEL_CREATE",
    "CHANNEL_UPDATE",
    "CHANNEL_DELETE",
    "THREAD_CREATE",
    "THREAD_UPDATE",
    "THREAD_DELETE",
    "THREAD_LIST_SYNC",
    "GUILD_CREATE",
    "GUILD_UPDATE",
    "GUILD_DELETE",
    "GUILD_ROLE_CREATE",
    "GUILD_ROLE_UPDATE",
    "GUILD_ROLE_DELETE",
    "GUILD_MEMBER_UPDATE",
    "GUILD_MEMBER_ADD",
    "GUILD_MEMBER_REMOVE",
}


def _require_direct_discord_transport() -> None:
    proxies = urllib.request.getproxies()
    configured = sorted(
        str(name)
        for name, value in proxies.items()
        if str(name).lower() in {"http", "https", "all"} and value
    )
    if configured:
        raise RuntimeError(
            "Discord transport refuses ambient proxy configuration: "
            + ", ".join(configured)
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail closed before urllib can forward a Discord credential."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class _NoRedirectWebSocketConnect(_WebSocketConnect):
    """Refuse Gateway redirects before a bot token can cross origins."""

    def process_redirect(self, exc: Exception) -> Exception | str:
        return exc


def _direct_urlopen(request: urllib.request.Request, *, timeout: float):
    """Open one Discord request without proxies or credentialed redirects."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    return opener.open(request, timeout=timeout)


class DiscordHTTPError(RuntimeError):
    def __init__(
        self,
        status: int,
        operation: str,
        *,
        retry_after: float | None = None,
    ):
        super().__init__(f"Discord HTTP {status} during {operation}")
        self.status = status
        self.retry_after = retry_after


class DeliveryAmbiguousError(RuntimeError):
    """Discord may have accepted a message whose response was never recorded."""


class AudienceViolation(RuntimeError):
    """The declared owner-only response audience could not be proven."""


class DiscordSecurityVerificationError(RuntimeError):
    """Runtime Discord permissions or audience posture could not be proven."""


def gateway_intents(config: Config) -> int:
    return (
        BASE_INTENTS | GUILD_MEMBERS_INTENT
        if config.channel_trust == "owner_private"
        else BASE_INTENTS
    )


def _gateway_snowflake(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or not value.isdecimal()
        or str(int(value)) != value
        or int(value) <= 0
        or int(value) >= 1 << 64
    ):
        raise RuntimeError(f"Discord Gateway returned malformed {field}")
    return value


def _gateway_resume_url(value: object) -> str:
    """Return a reviewed Discord WSS URL without trusting READY as a host oracle."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or not value.isascii()
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        raise RuntimeError("Discord Gateway returned a malformed resume URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("Discord Gateway returned a malformed resume URL") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "wss"
        or not hostname
        or not hostname.isascii()
        or not (hostname == "gateway.discord.gg" or hostname.endswith(".discord.gg"))
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.netloc not in {hostname, f"{hostname}:443"}
    ):
        raise RuntimeError("Discord Gateway returned an untrusted resume URL")
    authority = hostname if port is None else f"{hostname}:443"
    return f"wss://{authority}/?v=10&encoding=json"


def _validate_ready_guilds(ready: object, configured_guild_id: str) -> None:
    try:
        if not isinstance(ready, dict) or not isinstance(ready.get("guilds"), list):
            raise ValueError("Discord Gateway READY guild inventory is unavailable")
        seen: set[str] = set()
        for index, raw_guild in enumerate(ready["guilds"]):
            if not isinstance(raw_guild, dict):
                raise ValueError("Discord Gateway READY contains a malformed guild")
            guild_id = _gateway_snowflake(raw_guild.get("id"), f"READY guild {index} id")
            if guild_id in seen:
                raise ValueError("Discord Gateway READY contains duplicate guild IDs")
            seen.add(guild_id)
        if seen != {configured_guild_id}:
            raise ValueError(
                "Dedicated Discord bot must belong only to the configured guild"
            )
    except DiscordSecurityVerificationError:
        raise
    except Exception as exc:
        raise DiscordSecurityVerificationError(str(exc)) from exc


def _validate_security_event_guild(
    event_type: str, data: object, configured_guild_id: str
) -> None:
    try:
        if not isinstance(data, dict):
            raise ValueError(f"Discord Gateway {event_type} payload is malformed")
        field = "id" if event_type in {"GUILD_CREATE", "GUILD_UPDATE", "GUILD_DELETE"} else "guild_id"
        guild_id = _gateway_snowflake(data.get(field), f"{event_type} {field}")
        if guild_id != configured_guild_id:
            raise ValueError("Dedicated Discord bot received a foreign guild event")
    except DiscordSecurityVerificationError:
        raise
    except Exception as exc:
        raise DiscordSecurityVerificationError(str(exc)) from exc


def dedicated_token(config: Config | None = None) -> str:
    config = config or Config.from_threadkeep()
    for label, value in (
        ("service", config.keychain_service),
        ("account", config.keychain_account),
    ):
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 256
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise RuntimeError(f"dedicated Codex Discord Keychain {label} is invalid")
    security = Path("/usr/bin/security")
    try:
        security_metadata = security.lstat()
    except OSError as exc:
        raise RuntimeError("macOS Keychain client is unavailable") from exc
    if (
        stat.S_ISLNK(security_metadata.st_mode)
        or not stat.S_ISREG(security_metadata.st_mode)
        or security_metadata.st_uid != 0
        or stat.S_IMODE(security_metadata.st_mode) & 0o022
    ):
        raise RuntimeError("macOS Keychain client is unsafe")
    account = pwd.getpwuid(os.getuid())
    configured_home = Path(account.pw_dir)
    try:
        canonical_home = configured_home.resolve(strict=True)
        home_metadata = canonical_home.stat()
    except OSError as exc:
        raise RuntimeError("canonical user HOME is unavailable") from exc
    if (
        not configured_home.is_absolute()
        or ".." in configured_home.parts
        or canonical_home != Path(os.path.normpath(os.fspath(configured_home)))
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.getuid()
        or stat.S_IMODE(home_metadata.st_mode) & 0o022
    ):
        raise RuntimeError("canonical user HOME is unsafe")
    result = subprocess.run(
        [
            "/usr/bin/security",
            "find-generic-password",
            "-s",
            config.keychain_service,
            "-a",
            config.keychain_account,
            "-w",
        ],
        text=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=15,
        check=False,
        env={
            "HOME": str(canonical_home),
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
        },
        start_new_session=True,
    )
    token = result.stdout.strip()
    parts = token.split(".")
    if (
        result.returncode
        or not 50 <= len(token) <= 256
        or len(parts) != 3
        or len(parts[0]) < 10
        or len(parts[1]) < 4
        or len(parts[2]) < 20
        or any(re.fullmatch(r"[A-Za-z0-9_-]+", part, re.ASCII) is None for part in parts)
    ):
        raise RuntimeError("dedicated Codex Discord token is unavailable")
    return token


async def discord_request(
    token: str, method: str, path: str, body: dict | None = None, max_attempts: int = 4
):
    _require_direct_discord_transport()

    def call_once():
        request = urllib.request.Request(
            "https://discord.com/api/v10" + path,
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={
                "Authorization": f"Bot {token}",
                "Content-Type": "application/json",
                "User-Agent": "Threadkeep-Codex-Bridge/0.2",
            },
        )
        try:
            with _direct_urlopen(request, timeout=20) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = {}
            return exc.code, payload

    for attempt in range(max_attempts):
        try:
            status, payload = await asyncio.to_thread(call_once)
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt + 1 >= max_attempts:
                raise RuntimeError(f"Discord transport failed during {method} {path.split('?')[0]}")
            await asyncio.sleep(min(2**attempt, 8) + random.random() / 4)
            continue
        if 200 <= status < 300:
            return payload
        if status == 429:
            raw_retry_after = (
                payload.get("retry_after") if isinstance(payload, dict) else None
            )
            try:
                retry_after = float(raw_retry_after)
            except (TypeError, ValueError):
                retry_after = None
            if (
                retry_after is None
                or not math.isfinite(retry_after)
                or retry_after < 0
            ):
                raise DiscordHTTPError(
                    status,
                    f"{method} {path.split('?')[0]}",
                )
            if attempt + 1 >= max_attempts:
                raise DiscordHTTPError(
                    status,
                    f"{method} {path.split('?')[0]}",
                    retry_after=retry_after,
                )
            # Discord requires clients to honor the complete retry_after value;
            # it can legitimately exceed a minute for shared resource limits.
            await asyncio.sleep(retry_after + random.random() / 4)
            continue
        if status >= 500 and attempt + 1 < max_attempts:
            await asyncio.sleep(min(2**attempt, 8) + random.random() / 4)
            continue
        raise DiscordHTTPError(status, f"{method} {path.split('?')[0]}")
    raise DiscordHTTPError(429, f"{method} {path.split('?')[0]}")


async def verify_bot(token: str, config: Config) -> None:
    identity = await discord_request(token, "GET", "/users/@me")
    if identity.get("id") != config.bot_user_id or not identity.get("bot"):
        raise RuntimeError("Discord credential does not match configured dedicated bot identity")


def _verify_member_is_allowed(member: dict, config: Config) -> bool:
    user = member.get("user")
    if not isinstance(user, dict):
        raise AudienceViolation("Discord returned a malformed guild member")
    user_id = str(user.get("id", ""))
    if not user_id:
        raise AudienceViolation("Discord returned a guild member without an ID")
    return user_id == config.owner_user_id


def _permission_bits(value: object, label: str) -> int:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise AudienceViolation(f"Discord returned malformed {label}")
    return int(value)


def _effective_view_channel(
    *,
    user_id: str,
    assigned_roles: list[str],
    guild_owner_id: str,
    guild_id: str,
    roles: dict[str, int],
    role_overwrites: dict[str, tuple[int, int]],
    member_overwrites: dict[str, tuple[int, int]],
) -> bool:
    """Resolve VIEW_CHANNEL using Discord's documented overwrite order."""

    if user_id == guild_owner_id:
        return True
    permissions = roles[guild_id]
    for role_id in assigned_roles:
        permissions |= roles[role_id]
    if permissions & ADMINISTRATOR:
        return True

    allow, deny = role_overwrites.get(guild_id, (0, 0))
    permissions &= ~deny
    permissions |= allow
    role_allow = 0
    role_deny = 0
    for role_id in assigned_roles:
        allow, deny = role_overwrites.get(role_id, (0, 0))
        role_allow |= allow
        role_deny |= deny
    permissions &= ~role_deny
    permissions |= role_allow
    allow, deny = member_overwrites.get(user_id, (0, 0))
    permissions &= ~deny
    permissions |= allow
    return bool(permissions & VIEW_CHANNEL)


def _verify_private_channel_audience(
    guild: object,
    channel: object,
    members: list[dict],
    config: Config,
) -> None:
    """Prove a private parent channel has exactly the owner and bridge as readers.

    A currently single-human public guild is not a private audience: a newly
    invited member can immediately read retained history. ``owner_private``
    therefore requires a channel-level @everyone VIEW_CHANNEL deny, exact
    member allows for the owner and bridge, and no other allow path.
    """

    if not isinstance(guild, dict) or not isinstance(channel, dict):
        raise AudienceViolation("Discord returned malformed audience metadata")
    if _gateway_snowflake(guild.get("id"), "audience guild id") != config.guild_id:
        raise AudienceViolation("Discord returned the wrong audience guild")
    if _gateway_snowflake(channel.get("id"), "audience channel id") != config.channel_id:
        raise AudienceViolation("Discord returned the wrong audience channel")
    if _gateway_snowflake(channel.get("guild_id"), "audience channel guild_id") != config.guild_id:
        raise AudienceViolation("Discord audience channel belongs to the wrong guild")

    raw_roles = guild.get("roles")
    raw_overwrites = channel.get("permission_overwrites")
    if not isinstance(raw_roles, list) or not isinstance(raw_overwrites, list):
        raise AudienceViolation("Discord audience permissions are unavailable")
    roles: dict[str, int] = {}
    for index, raw_role in enumerate(raw_roles):
        if not isinstance(raw_role, dict):
            raise AudienceViolation("Discord returned a malformed audience role")
        role_id = _gateway_snowflake(raw_role.get("id"), f"audience role {index} id")
        if role_id in roles:
            raise AudienceViolation("Discord returned duplicate audience roles")
        roles[role_id] = _permission_bits(
            raw_role.get("permissions"), f"audience role {role_id} permissions"
        )
    if config.guild_id not in roles:
        raise AudienceViolation("Discord audience roles omit @everyone")

    role_overwrites: dict[str, tuple[int, int]] = {}
    member_overwrites: dict[str, tuple[int, int]] = {}
    for index, raw_overwrite in enumerate(raw_overwrites):
        if not isinstance(raw_overwrite, dict):
            raise AudienceViolation("Discord returned a malformed audience overwrite")
        target_type = raw_overwrite.get("type")
        if isinstance(target_type, bool) or not isinstance(target_type, int):
            raise AudienceViolation("Discord returned a malformed audience overwrite type")
        target_id = _gateway_snowflake(
            raw_overwrite.get("id"), f"audience overwrite {index} id"
        )
        destination = role_overwrites if target_type == 0 else member_overwrites
        if target_type not in {0, 1}:
            raise AudienceViolation("Discord returned an unknown audience overwrite type")
        if target_id in destination:
            raise AudienceViolation("Discord returned duplicate audience overwrites")
        destination[target_id] = (
            _permission_bits(
                raw_overwrite.get("allow"),
                f"audience overwrite {target_id} allow",
            ),
            _permission_bits(
                raw_overwrite.get("deny"),
                f"audience overwrite {target_id} deny",
            ),
        )

    everyone_allow, everyone_deny = role_overwrites.get(config.guild_id, (0, 0))
    if everyone_allow & VIEW_CHANNEL or not everyone_deny & VIEW_CHANNEL:
        raise AudienceViolation(
            "owner_private requires @everyone View Channel to be explicitly denied"
        )
    for role_id, (allow, _deny) in role_overwrites.items():
        if role_id != config.guild_id and allow & VIEW_CHANNEL:
            raise AudienceViolation(
                "owner_private forbids role-based View Channel allows"
            )
    for user_id, (allow, deny) in member_overwrites.items():
        if user_id in {config.owner_user_id, config.bot_user_id}:
            if not allow & VIEW_CHANNEL or deny & VIEW_CHANNEL:
                raise AudienceViolation(
                    "owner_private requires exact owner and bridge View Channel allows"
                )
        elif allow & VIEW_CHANNEL:
            raise AudienceViolation(
                "owner_private forbids View Channel allows for any other member"
            )
    for required_id in (config.owner_user_id, config.bot_user_id):
        allow, deny = member_overwrites.get(required_id, (0, 0))
        if not allow & VIEW_CHANNEL or deny & VIEW_CHANNEL:
            raise AudienceViolation(
                "owner_private requires exact owner and bridge View Channel allows"
            )

    guild_owner_id = _gateway_snowflake(guild.get("owner_id"), "audience guild owner_id")
    if guild_owner_id != config.owner_user_id:
        raise AudienceViolation(
            "owner_private requires the configured owner to own the Discord guild"
        )
    seen_users: set[str] = set()
    for member in members:
        user = member.get("user")
        if not isinstance(user, dict):
            raise AudienceViolation("Discord returned a malformed audience member")
        user_id = _gateway_snowflake(user.get("id"), "audience member id")
        if user_id in seen_users:
            raise AudienceViolation("Discord returned duplicate audience members")
        seen_users.add(user_id)
        raw_member_roles = member.get("roles")
        if not isinstance(raw_member_roles, list):
            raise AudienceViolation("Discord returned malformed audience member roles")
        seen_roles: set[str] = set()
        assigned_roles: list[str] = []
        for index, raw_role_id in enumerate(raw_member_roles):
            role_id = _gateway_snowflake(
                raw_role_id, f"audience member role {index} id"
            )
            if role_id == config.guild_id or role_id in seen_roles or role_id not in roles:
                raise AudienceViolation("Discord returned invalid audience member roles")
            seen_roles.add(role_id)
            assigned_roles.append(role_id)
        can_view = _effective_view_channel(
            user_id=user_id,
            assigned_roles=assigned_roles,
            guild_owner_id=guild_owner_id,
            guild_id=config.guild_id,
            roles=roles,
            role_overwrites=role_overwrites,
            member_overwrites=member_overwrites,
        )
        if user_id in {config.owner_user_id, config.bot_user_id}:
            if not can_view:
                raise AudienceViolation(
                    "owner_private owner or bridge cannot read the Discord channel"
                )
        elif can_view:
            raise AudienceViolation(
                "owner_private is invalid because another guild member can read the channel"
            )

    if config.owner_user_id not in seen_users or config.bot_user_id not in seen_users:
        raise AudienceViolation("owner_private owner or bridge is absent from the guild")


async def verify_owner_private_audience(token: str, config: Config) -> None:
    """Prove the configured channel is private to the owner and bridge."""

    if config.channel_trust != "owner_private":
        return
    try:
        guild, channel = await asyncio.gather(
            discord_request(token, "GET", f"/guilds/{config.guild_id}"),
            discord_request(token, "GET", f"/channels/{config.channel_id}"),
        )
    except Exception as exc:
        raise AudienceViolation(
            "owner_private audience permissions could not be verified"
        ) from exc
    owner_seen = False
    all_members: list[dict] = []
    after: str | None = None
    for _page in range(1000):
        suffix = f"&after={urllib.parse.quote(after)}" if after else ""
        try:
            members = await discord_request(
                token,
                "GET",
                f"/guilds/{config.guild_id}/members?limit=1000{suffix}",
            )
        except Exception as exc:
            raise AudienceViolation(
                "owner_private audience membership could not be verified"
            ) from exc
        if not isinstance(members, list) or any(
            not isinstance(member, dict) for member in members
        ):
            raise AudienceViolation("Discord returned a malformed guild member list")
        for member in members:
            owner_seen = _verify_member_is_allowed(member, config) or owner_seen
            all_members.append(member)
        if len(members) < 1000:
            break
        next_after = str(members[-1].get("user", {}).get("id", ""))
        if not next_after or next_after == after:
            raise AudienceViolation("Discord guild member pagination did not advance")
        after = next_after
    else:
        raise AudienceViolation("Discord guild member pagination exceeded its limit")
    if not owner_seen:
        raise AudienceViolation(
            "owner_private is invalid because the owner is not in the guild"
        )
    _verify_private_channel_audience(guild, channel, all_members, config)


async def verify_runtime_security_posture(token: str, config: Config) -> None:
    """Make every runtime permission or audience proof failure terminal."""

    from .discord_permissions import verify_discord_permissions

    try:
        await verify_discord_permissions(token, config)
        await verify_owner_private_audience(token, config)
    except asyncio.CancelledError:
        raise
    except (AudienceViolation, DiscordSecurityVerificationError):
        raise
    except Exception as exc:
        raise DiscordSecurityVerificationError(
            "Discord permission or audience verification failed"
        ) from exc


async def bootstrap_root_cursor(token: str, config: Config, store: JobStore) -> None:
    """Create a first-run boundary without executing historical channel messages."""

    if store.cursor_for(config.channel_id) is not None:
        return
    rows = await discord_request(
        token,
        "GET",
        f"/channels/{config.channel_id}/messages?limit=1",
    )
    newest = str(rows[0].get("id", "")) if rows else "0"
    if not newest.isdecimal():
        raise RuntimeError("Discord returned an invalid bootstrap cursor")
    store.save_cursor(config.channel_id, newest)
    log.info("root_cursor_bootstrapped channel_id=%s", config.channel_id)


async def acknowledge(token: str, config: Config, event_id: str) -> None:
    emoji = urllib.parse.quote("👀")
    await discord_request(
        token,
        "PUT",
        f"/channels/{config.channel_id}/messages/{event_id}/reactions/{emoji}/@me",
    )


async def acknowledge_sensitive_rejection(
    token: str, config: Config, event_id: str
) -> None:
    """Mark an owner message that was rejected before durable persistence."""

    emoji = urllib.parse.quote("🚫")
    await discord_request(
        token,
        "PUT",
        f"/channels/{config.channel_id}/messages/{event_id}/reactions/{emoji}/@me",
    )


async def ensure_response_thread(
    token: str, config: Config, event_id: str, content: str
) -> str:
    def validate(thread: object) -> str:
        if not isinstance(thread, dict):
            raise RuntimeError("Discord returned a malformed response thread")
        if thread.get("id") != event_id:
            raise RuntimeError("Discord response thread has the wrong immutable ID")
        if thread.get("guild_id") != config.guild_id:
            raise RuntimeError("Discord response thread belongs to the wrong guild")
        if thread.get("parent_id") != config.channel_id:
            raise RuntimeError("Discord response thread has the wrong parent")
        if thread.get("type") != 11:
            raise RuntimeError("Discord response thread is not public")
        if thread.get("owner_id") != config.bot_user_id:
            raise RuntimeError("Discord response thread is not owned by the dedicated bot")
        return event_id

    try:
        existing = await discord_request(token, "GET", f"/channels/{event_id}", max_attempts=1)
        return validate(existing)
    except DiscordHTTPError as exc:
        if exc.status != 404:
            raise
    title = " ".join(content.split()).strip()[:90] or "Codex task"
    result = await discord_request(
        token,
        "POST",
        f"/channels/{config.channel_id}/messages/{event_id}/threads",
        {"name": title, "auto_archive_duration": 1440},
    )
    return validate(result)


async def create_response_thread(token: str, config: Config, event_id: str, content: str) -> str:
    return await ensure_response_thread(token, config, event_id, content)


def _hard_split(text: str, limit: int) -> list[str]:
    parts = []
    while len(text) > limit:
        cut = text.rfind(" ", 0, limit)
        if cut <= limit // 2:
            cut = limit
        parts.append(text[:cut])
        text = text[cut:].lstrip() if cut != limit else text[cut:]
    if text:
        parts.append(text)
    return parts


def split_message(content: str) -> list[str]:
    if len(content) <= DISCORD_LIMIT:
        return [content]
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    fence: str | None = None

    def flush() -> None:
        nonlocal current, current_len
        if not current:
            return
        body = "\n".join(current)
        if fence is not None:
            body += "\n```"
        chunks.append(body)
        current = [fence] if fence is not None else []
        current_len = len(fence) + 1 if fence is not None else 0

    for raw_line in content.split("\n"):
        for line in ([raw_line] if len(raw_line) <= CHUNK_LIMIT else _hard_split(raw_line, CHUNK_LIMIT)):
            if current and current_len + len(line) + 1 > CHUNK_LIMIT:
                flush()
            current.append(line)
            current_len += len(line) + 1
            if line.strip().startswith("```"):
                fence = None if fence is not None else line
    flush()
    return [chunk for chunk in chunks if chunk.strip()]


def _nonce(event_id: str, index: int, total: int) -> str:
    if total == 1 and len(f"codex-{event_id}") <= 25:
        return f"codex-{event_id}"
    digest = hashlib.sha256(f"{event_id}:{index}".encode()).hexdigest()[:24]
    return f"c{digest}"


WITHHELD_NOTICE = withheld_notice("Codex")


def public_safe_output(text: str, channel_trust: str = "public") -> str:
    return _shared_public_safe_output(
        text,
        agent_name="Codex",
        channel_trust=channel_trust,
    )


async def _find_deliveries_by_nonce(
    token: str,
    destination_id: str,
    expected_content_hashes: dict[str, str],
    bot_user_id: str,
) -> dict[str, str]:
    """Bound one channel-history scan for all uncertain manifest chunks.

    This slow path is used only after Discord's documented short nonce
    de-duplication window has expired. A complete bounded scan can confirm
    exact bot-authored nonce/content pairs. Hitting the bound is ambiguous and
    therefore never authorizes another POST.
    """

    if not expected_content_hashes:
        return {}
    if not bot_user_id:
        raise DeliveryAmbiguousError(
            "bot identity is required to reconcile an aged Discord delivery"
        )
    before: str | None = None
    matched: dict[str, str] = {}
    seen_ids: set[str] = set()
    for _page_number in range(DELIVERY_HISTORY_MAX_PAGES):
        suffix = f"&before={before}" if before else ""
        rows = await discord_request(
            token,
            "GET",
            f"/channels/{destination_id}/messages?limit=100{suffix}",
        )
        if not isinstance(rows, list):
            raise DeliveryAmbiguousError(
                "Discord history reconciliation returned a malformed page"
            )
        if len(rows) > 100:
            raise DeliveryAmbiguousError(
                "Discord history reconciliation exceeded its requested page size"
            )
        if not rows:
            return matched
        page_ids: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                raise DeliveryAmbiguousError(
                    "Discord history reconciliation returned a malformed message"
                )
            message_id = _gateway_snowflake(row.get("id"), "history message id")
            if message_id in seen_ids:
                raise DeliveryAmbiguousError(
                    "Discord history pagination repeated a message"
                )
            seen_ids.add(message_id)
            page_ids.append(message_id)
            nonce = str(row.get("nonce", ""))
            content_hash = expected_content_hashes.get(nonce)
            if content_hash is None:
                continue
            author = row.get("author")
            if not isinstance(author, dict) or str(author.get("id", "")) != bot_user_id:
                # Nonces are client-selected and therefore not authenticators.
                # A public-channel participant must not be able to quarantine
                # the bridge merely by copying a predictable nonce.
                continue
            actual_hash = hashlib.sha256(str(row.get("content", "")).encode()).hexdigest()
            if actual_hash != content_hash:
                raise DeliveryAmbiguousError(
                    "Discord delivery nonce matched different content"
                )
            if nonce in matched:
                raise DeliveryAmbiguousError(
                    "Discord already contains duplicate messages for one delivery nonce"
                )
            matched[nonce] = message_id
        oldest = str(min(int(message_id) for message_id in page_ids))
        if before is not None and int(oldest) >= int(before):
            raise DeliveryAmbiguousError(
                "Discord history pagination did not move backwards"
            )
        if len(rows) < 100:
            return matched
        before = oldest
    raise DeliveryAmbiguousError(
        "Discord history reconciliation exceeded its bounded page limit"
    )


async def _find_delivery_by_nonce(
    token: str,
    destination_id: str,
    nonce: str,
    content_hash: str,
    bot_user_id: str,
) -> str | None:
    """Compatibility wrapper for a single uncertain delivery chunk."""

    matched = await _find_deliveries_by_nonce(
        token,
        destination_id,
        {nonce: content_hash},
        bot_user_id,
    )
    return matched.get(nonce)


async def reconcile_delivery(
    token: str,
    store: JobStore,
    event_id: str,
    bot_user_id: str | None = None,
) -> str:
    manifest = store.delivery_manifest(event_id)
    if not manifest:
        raise RuntimeError("delivery manifest is unavailable")
    target, response_hash, chunk_count, _manifest_state, rows = manifest
    if len(rows) != chunk_count or [row[0] for row in rows] != list(range(chunk_count)):
        raise RuntimeError("delivery manifest is incomplete")
    canonical = "\0".join(str(row[2]) for row in rows)
    if hashlib.sha256(canonical.encode()).hexdigest() != response_hash:
        raise RuntimeError("delivery manifest response hash mismatch")
    history_candidates: dict[str, tuple[int, str]] = {}
    for row in rows:
        index, nonce, _content, content_hash, state, _message_id, attempted_at, ambiguous_at = row
        if hashlib.sha256(str(row[2]).encode()).hexdigest() != content_hash:
            raise RuntimeError("delivery chunk hash mismatch")
        if ambiguous_at is not None:
            raise DeliveryAmbiguousError(
                "Discord delivery is quarantined after an aged ambiguous POST"
            )
        if state == "prepared" and attempted_at is not None:
            nonce_text = str(nonce)
            if nonce_text in history_candidates:
                raise RuntimeError("delivery manifest contains duplicate nonces")
            history_candidates[nonce_text] = (int(index), str(content_hash))

    history_scanned = False
    history_matches: dict[str, str] = {}

    async def scan_history_once() -> dict[str, str]:
        nonlocal history_scanned, history_matches
        if not history_scanned:
            history_matches = await _find_deliveries_by_nonce(
                token,
                target,
                {
                    nonce: content_hash
                    for nonce, (_index, content_hash) in history_candidates.items()
                },
                bot_user_id or "",
            )
            history_scanned = True
        return history_matches

    last_id = ""
    for (
        index,
        nonce,
        content,
        content_hash,
        state,
        message_id,
        attempted_at,
        ambiguous_at,
    ) in rows:
        if state == "sent" and message_id:
            existing = await discord_request(
                token, "GET", f"/channels/{target}/messages/{message_id}"
            )
            if not isinstance(existing, dict):
                raise RuntimeError("Discord delivery readback is malformed")
            if hashlib.sha256(str(existing.get("content", "")).encode()).hexdigest() != content_hash:
                store.mark_delivery_ambiguous(event_id, index)
                raise DeliveryAmbiguousError(
                    "Discord delivery readback content mismatch; delivery quarantined"
                )
            last_id = str(message_id)
            continue
        rate_limit_retries = 0
        while True:
            first_attempt, attempted_at = store.begin_delivery_attempt(event_id, index)
            attempt_age = int(time.time()) - attempted_at
            if not first_attempt and history_scanned:
                existing_id = history_matches.get(str(nonce))
                if existing_id:
                    store.confirm_delivery(event_id, index, existing_id)
                    last_id = existing_id
                    break
            if not first_attempt and (
                attempt_age < 0 or attempt_age > NONCE_RETRY_WINDOW_SECONDS
            ):
                try:
                    matches = await scan_history_once()
                except DeliveryAmbiguousError:
                    store.mark_delivery_ambiguous(event_id, index)
                    raise
                existing_id = matches.get(str(nonce))
                if not existing_id:
                    store.mark_delivery_ambiguous(event_id, index)
                    raise DeliveryAmbiguousError(
                        "aged Discord POST has no provable history match; delivery quarantined"
                    )
                store.confirm_delivery(event_id, index, existing_id)
                last_id = existing_id
                break
            try:
                result = await discord_request(
                    token,
                    "POST",
                    f"/channels/{target}/messages",
                    {
                        "content": content,
                        "nonce": nonce,
                        "enforce_nonce": True,
                        "allowed_mentions": {"parse": []},
                    },
                    # A transport retry crosses the same unknown-commit boundary.
                    # The outer durable reconciliation owns every POST retry.
                    max_attempts=1,
                )
            except DiscordHTTPError as exc:
                if exc.status != 429:
                    raise
                # A 429 definitively rejected this request. It is safe to erase
                # only an attempt created by this call; an older unknown POST
                # must retain its original timestamp.
                if first_attempt:
                    store.clear_delivery_attempt(event_id, index, attempted_at)
                if exc.retry_after is None:
                    raise
                rate_limit_retries += 1
                await asyncio.sleep(exc.retry_after + random.random() / 4)
                if rate_limit_retries >= DELIVERY_RATE_LIMIT_MAX_RETRIES:
                    raise
                continue
            if not isinstance(result, dict) or not str(result.get("id", "")):
                raise RuntimeError("Discord delivery POST returned a malformed message")
            last_id = str(result["id"])
            readback = await discord_request(
                token, "GET", f"/channels/{target}/messages/{last_id}"
            )
            if not isinstance(readback, dict):
                raise RuntimeError("Discord delivery readback is malformed")
            if hashlib.sha256(str(readback.get("content", "")).encode()).hexdigest() != content_hash:
                store.mark_delivery_ambiguous(event_id, index)
                raise DeliveryAmbiguousError(
                    "Discord delivery readback content mismatch; delivery quarantined"
                )
            # Confirmation follows readback so normalized or corrupted content
            # can never become a permanently poisoned `sent` row.
            store.confirm_delivery(event_id, index, last_id)
            break
    if not last_id:
        raise RuntimeError("delivery manifest produced no Discord message")
    store.confirm_manifest(event_id)
    return last_id


async def send_result(
    token: str,
    config: Config,
    event_id: str,
    text: str,
    destination_id: str | None = None,
    store: JobStore | None = None,
) -> str:
    safe = public_safe_output(text, config.channel_trust)
    chunks = split_message(safe)
    target = destination_id or config.channel_id
    records = [
        (_nonce(event_id, index, len(chunks)), chunk, hashlib.sha256(chunk.encode()).hexdigest())
        for index, chunk in enumerate(chunks)
    ]
    if store:
        canonical = "\0".join(chunks)
        store.prepare_delivery_manifest(
            event_id,
            target,
            hashlib.sha256(canonical.encode()).hexdigest(),
            records,
        )
        return await reconcile_delivery(
            token, store, event_id, bot_user_id=config.bot_user_id
        )

    last_id = ""
    for nonce, chunk, _content_hash in records:
        result = await discord_request(
            token,
            "POST",
            f"/channels/{target}/messages",
            {
                "content": chunk,
                "nonce": nonce,
                "enforce_nonce": True,
                "allowed_mentions": {"parse": []},
            },
        )
        last_id = str(result["id"])
    return last_id


def _event_from_data(data: dict, bot_id: str, application_id: str) -> MessageEvent:
    attachments = []
    for item in data.get("attachments", [])[:10]:
        url = str(item.get("url", ""))
        name = str(item.get("filename", "attachment"))[:200]
        if url.startswith("https://cdn.discordapp.com/") or url.startswith("https://media.discordapp.net/"):
            attachments.append(f"- {name}: {url}")
    content = str(data.get("content", ""))
    if attachments:
        content += "\n\nDiscord attachments (untrusted):\n" + "\n".join(attachments)
    return MessageEvent(
        event_id=str(data.get("id", "")),
        guild_id=data.get("guild_id"),
        channel_id=str(data.get("channel_id", "")),
        author_id=str(data.get("author", {}).get("id", "")),
        author_is_bot=bool(data.get("author", {}).get("bot")),
        webhook_id=data.get("webhook_id"),
        content=content,
        event_type="MESSAGE_CREATE",
        receiving_bot_id=bot_id,
        application_id=application_id,
        policy_version=1,
        message_type=int(data.get("type", 0)),
    )


async def handle_message_data(
    token: str,
    config: Config,
    store: JobStore,
    data: dict,
    bot_id: str,
    application_id: str,
) -> bool:
    event = _event_from_data(data, bot_id, application_id)
    is_root = event.channel_id == config.channel_id
    managed_root = store.managed_root(event.channel_id)
    is_managed_thread = managed_root is not None
    if not is_root and not is_managed_thread:
        return False
    if managed_root is not None:
        root = store.job_status(managed_root)
        if root is None or store.job_policy_binding(managed_root) != store.policy_binding:
            log.error("stale_managed_thread_rejected thread_id=%s", event.channel_id)
            return False
        _state, _ready, root_thread, guild, channel, author, _content = root
        if (
            guild != config.guild_id
            or channel != config.channel_id
            or author != config.owner_user_id
            or root_thread != event.channel_id
        ):
            log.error("invalid_managed_thread_binding thread_id=%s", event.channel_id)
            return False
    try:
        authorize(event, config if is_root else replace(config, channel_id=event.channel_id))
    except RejectedEvent:
        return False
    reject_sensitive_ingress = (
        contains_secret_data(event.content)
        if config.channel_trust == "owner_private"
        else contains_sensitive_data(event.content)
    )
    if reject_sensitive_ingress:
        log.warning(
            "sensitive_message_rejected_before_persistence event_id=%s",
            event.event_id,
        )
        await acknowledge_sensitive_rejection(
            token,
            config if is_root else replace(config, channel_id=event.channel_id),
            event.event_id,
        )
        return False
    reservation = {
        "max_messages_per_minute": config.max_messages_per_minute,
        "max_messages_per_hour": config.max_messages_per_hour,
        "max_pending_jobs": config.max_pending_jobs,
    }
    if is_managed_thread:
        try:
            inserted = store.enqueue_limited(
                **reservation,
                event_id=event.event_id,
                guild_id=event.guild_id or "",
                channel_id=event.channel_id,
                author_id=event.author_id,
                content=event.content,
            )
        except IngressLimitExceeded as exc:
            log.warning(
                "message_event_limited event_id=%s reason=%s",
                event.event_id,
                exc.reason,
            )
            return False
        status = store.job_status(event.event_id)
        if not status:
            raise RuntimeError("follow-up Discord event reservation disappeared")
        _state, _ready, _thread, guild, channel, author, stored_content = status
        if (guild, channel, author, stored_content) != (
            event.guild_id or "",
            event.channel_id,
            event.author_id,
            event.content,
        ):
            raise RuntimeError(
                "follow-up Discord event ID replayed with different immutable content"
            )
        await acknowledge(token, replace(config, channel_id=event.channel_id), event.event_id)
        return inserted

    try:
        inserted = store.enqueue_limited(
            **reservation,
            event_id=event.event_id,
            guild_id=event.guild_id or "",
            channel_id=event.channel_id,
            author_id=event.author_id,
            content=event.content,
            ready=False,
        )
    except IngressLimitExceeded as exc:
        log.warning(
            "message_event_limited event_id=%s reason=%s",
            event.event_id,
            exc.reason,
        )
        return False
    status = store.job_status(event.event_id)
    if not status:
        raise RuntimeError("root Discord event reservation disappeared")
    state, ready, stored_thread, guild, channel, author, stored_content = status
    if (guild, channel, author, stored_content) != (
        event.guild_id or "",
        event.channel_id,
        event.author_id,
        event.content,
    ):
        raise RuntimeError("Discord event ID replayed with different immutable content")
    if not inserted and (state != "queued" or ready):
        return False
    await acknowledge(token, config, event.event_id)
    thread_id = stored_thread or store.thread_for(f"discord:{event.event_id}")
    if not thread_id:
        thread_id = await ensure_response_thread(token, config, event.event_id, event.content)
    store.save_thread(f"discord:{event.event_id}", thread_id)
    store.save_managed_thread(thread_id, event.event_id)
    if store.cursor_for(thread_id) is None:
        store.save_cursor(thread_id, event.event_id)
    if not store.make_ready(event.event_id, thread_id):
        raise RuntimeError("failed to transition root Discord event to ready")
    return True


async def reconcile_recent(
    token: str, config: Config, store: JobStore, bot_id: str, application_id: str
) -> None:
    for event_id in store.unready_root_ids(config.channel_id):
        try:
            data = await discord_request(
                token, "GET", f"/channels/{config.channel_id}/messages/{event_id}"
            )
        except DiscordHTTPError as exc:
            if exc.status == 404:
                if not store.cancel_unready_root(event_id, config.channel_id):
                    raise RuntimeError(
                        "vanished root reservation changed during cancellation"
                    )
                log.error(
                    "reserved_root_message_missing_cancelled event_id=%s",
                    event_id,
                )
                continue
            raise
        await handle_message_data(token, config, store, data, bot_id, application_id)

    channels = [config.channel_id, *store.managed_threads()]
    for channel_id in dict.fromkeys(channels):
        cursor = store.cursor_for(channel_id)
        while True:
            suffix = f"&after={cursor}" if cursor else ""
            try:
                rows = await discord_request(
                    token, "GET", f"/channels/{channel_id}/messages?limit=100{suffix}"
                )
            except DiscordHTTPError as exc:
                if exc.status in {403, 404} and channel_id != config.channel_id:
                    break
                raise
            ordered = sorted(rows or [], key=lambda row: int(row.get("id", "0")))
            for data in ordered:
                await handle_message_data(token, config, store, data, bot_id, application_id)
                cursor = str(data["id"])
                store.save_cursor(channel_id, cursor)
            if len(ordered) < 100:
                break


async def _abort_gateway(socket) -> None:
    transport = getattr(socket, "transport", None)
    if transport is not None:
        transport.abort()
    else:
        await socket.close(code=4000, reason="reconnect")


async def receive_forever(
    token: str,
    config: Config,
    store: JobStore,
    ready_event: asyncio.Event | None = None,
) -> None:
    received_sequence: int | None = None
    resume_sequence: int | None = None
    session_id: str | None = None
    resume_url = GATEWAY
    bot_id: str | None = None
    application_id: str | None = None
    backoff = 1.0
    identify_budget = IdentifyBudget(config.state_dir / "identify-ledger.json")
    while True:
        if ready_event is not None:
            ready_event.clear()
        try:
            _require_direct_discord_transport()
            async with _NoRedirectWebSocketConnect(
                resume_url,
                max_size=1_000_000,
                open_timeout=20,
                close_timeout=2,
                proxy=None,
            ) as socket:
                hello = json.loads(await asyncio.wait_for(socket.recv(), 20))
                if hello.get("op") != 10:
                    raise RuntimeError("Discord Gateway did not send HELLO")
                interval = hello["d"]["heartbeat_interval"] / 1000
                heartbeat_ack = asyncio.Event()
                heartbeat_ack.set()
                if session_id and resume_sequence is not None:
                    await socket.send(
                        json.dumps(
                            {
                                "op": 6,
                                "d": {
                                    "token": token,
                                    "session_id": session_id,
                                    "seq": resume_sequence,
                                },
                            }
                        )
                    )
                else:
                    await identify_budget.acquire()
                    await socket.send(
                        json.dumps(
                            {
                                "op": 2,
                                "d": {
                                    "token": token,
                                    "intents": gateway_intents(config),
                                    "properties": {
                                        "os": "macos",
                                        "browser": "codex-discord-bridge",
                                        "device": "codex-discord-bridge",
                                    },
                                },
                            }
                        )
                    )

                async def heartbeat() -> None:
                    await asyncio.sleep(random.random() * interval)
                    while True:
                        if not heartbeat_ack.is_set():
                            await _abort_gateway(socket)
                            raise RuntimeError("Discord heartbeat ACK timeout")
                        heartbeat_ack.clear()
                        await socket.send(
                            json.dumps({"op": 1, "d": received_sequence})
                        )
                        await asyncio.sleep(interval)

                heart = asyncio.create_task(heartbeat(), name="discord-heartbeat")
                permission_watch: asyncio.Task | None = None
                dispatch_queue: asyncio.Queue[
                    tuple[str, dict, str | None, str | None, int | None]
                ] = asyncio.Queue(maxsize=1000)

                async def watch_permissions() -> None:
                    while True:
                        await asyncio.sleep(300)
                        try:
                            await verify_runtime_security_posture(token, config)
                        except Exception:
                            await _abort_gateway(socket)
                            raise

                async def process_dispatches() -> None:
                    nonlocal backoff, resume_sequence
                    while True:
                        (
                            event_type,
                            data,
                            event_bot_id,
                            event_application_id,
                            event_sequence,
                        ) = (
                            await dispatch_queue.get()
                        )
                        try:
                            if event_type == "READY":
                                if not event_bot_id or not event_application_id:
                                    raise RuntimeError("Gateway READY identity is unavailable")
                                await verify_runtime_security_posture(token, config)
                                await reconcile_recent(
                                    token,
                                    config,
                                    store,
                                    event_bot_id,
                                    event_application_id,
                                )
                                backoff = 1.0
                                if ready_event is not None:
                                    ready_event.set()
                                log.info("gateway_ready bot_id=%s", event_bot_id)
                            elif event_type == "RESUMED":
                                await verify_runtime_security_posture(token, config)
                                backoff = 1.0
                                if ready_event is not None:
                                    ready_event.set()
                                log.info("gateway_resumed")
                            elif event_type == "VERIFY_PERMISSIONS":
                                await verify_runtime_security_posture(token, config)
                            elif event_type == "MESSAGE_CREATE":
                                if not event_bot_id or not event_application_id:
                                    raise RuntimeError(
                                        "Gateway message arrived before verified READY identity"
                                    )
                                await handle_message_data(
                                    token,
                                    config,
                                    store,
                                    data,
                                    event_bot_id,
                                    event_application_id,
                                )
                                channel_id = str(data.get("channel_id", ""))
                                if channel_id == config.channel_id or store.managed_root(
                                    channel_id
                                ):
                                    store.save_cursor(
                                        channel_id, str(data.get("id", ""))
                                    )
                                    log.info(
                                        "message_event_processed event_id=%s channel_id=%s",
                                        data.get("id", ""),
                                        channel_id,
                                    )
                            if event_sequence is not None:
                                resume_sequence = event_sequence
                        except Exception:
                            await _abort_gateway(socket)
                            raise
                        finally:
                            dispatch_queue.task_done()

                dispatcher = asyncio.create_task(
                    process_dispatches(), name="discord-dispatch-worker"
                )

                try:
                    async for raw in socket:
                        payload = json.loads(raw)
                        dispatch_sequence = (
                            int(payload["s"]) if payload.get("s") is not None else None
                        )
                        if dispatch_sequence is not None:
                            received_sequence = dispatch_sequence
                        opcode = payload.get("op")
                        if opcode == 11:
                            heartbeat_ack.set()
                            continue
                        if opcode == 1:
                            await socket.send(
                                json.dumps({"op": 1, "d": received_sequence})
                            )
                            continue
                        if opcode == 7:
                            await _abort_gateway(socket)
                            break
                        if opcode == 9:
                            if not payload.get("d"):
                                received_sequence = None
                                resume_sequence = None
                                session_id = None
                                bot_id = None
                                application_id = None
                                resume_url = GATEWAY
                            await asyncio.sleep(random.uniform(1, 5))
                            await _abort_gateway(socket)
                            break
                        event_type = payload.get("t")
                        if event_type == "READY":
                            ready = payload.get("d", {})
                            bot_id = str(ready.get("user", {}).get("id", ""))
                            application_id = str(ready.get("application", {}).get("id", ""))
                            if bot_id != config.bot_user_id or application_id != config.application_id:
                                raise DiscordSecurityVerificationError(
                                    "Gateway READY identity does not match configured bot application"
                                )
                            _validate_ready_guilds(ready, config.guild_id)
                            session_id = str(ready.get("session_id", ""))
                            resume_url = _gateway_resume_url(
                                ready.get("resume_gateway_url")
                                or "wss://gateway.discord.gg"
                            )
                            dispatch_queue.put_nowait(
                                (
                                    "READY",
                                    ready,
                                    bot_id,
                                    application_id,
                                    dispatch_sequence,
                                )
                            )
                            if permission_watch is None or permission_watch.done():
                                permission_watch = asyncio.create_task(
                                    watch_permissions(), name="discord-permission-watch"
                                )
                            continue
                        if event_type == "RESUMED":
                            dispatch_queue.put_nowait(
                                (
                                    "RESUMED",
                                    payload.get("d", {}),
                                    bot_id,
                                    application_id,
                                    dispatch_sequence,
                                )
                            )
                            continue
                        if event_type in SECURITY_RECHECK_EVENTS:
                            event_data = payload.get("d", {})
                            _validate_security_event_guild(
                                event_type, event_data, config.guild_id
                            )
                            dispatch_queue.put_nowait(
                                (
                                    "VERIFY_PERMISSIONS",
                                    event_data,
                                    bot_id,
                                    application_id,
                                    dispatch_sequence,
                                )
                            )
                            continue
                        if event_type == "MESSAGE_CREATE" and bot_id and application_id:
                            dispatch_queue.put_nowait(
                                (
                                    "MESSAGE_CREATE",
                                    payload.get("d", {}),
                                    bot_id,
                                    application_id,
                                    dispatch_sequence,
                                )
                            )
                            continue
                        if opcode == 0:
                            dispatch_queue.put_nowait(
                                (
                                    "IGNORED",
                                    payload.get("d", {}),
                                    bot_id,
                                    application_id,
                                    dispatch_sequence,
                                )
                            )
                finally:
                    if ready_event is not None:
                        ready_event.clear()
                    heart.cancel()
                    dispatcher.cancel()
                    if permission_watch is not None:
                        permission_watch.cancel()
                    task_results = await asyncio.gather(
                        heart,
                        dispatcher,
                        *(tuple([permission_watch]) if permission_watch is not None else ()),
                        return_exceptions=True,
                    )
                    for task_result in task_results:
                        if isinstance(
                            task_result,
                            (AudienceViolation, DiscordSecurityVerificationError),
                        ):
                            raise task_result
                    for task_result in task_results:
                        if isinstance(task_result, Exception):
                            raise task_result
        except asyncio.CancelledError:
            raise
        except (AudienceViolation, DiscordSecurityVerificationError):
            raise
        except ConnectionClosed as exc:
            if exc.code in FATAL_GATEWAY_CLOSE_CODES:
                raise RuntimeError(f"Discord Gateway rejected the session with code {exc.code}") from exc
            if exc.code in RESET_SESSION_CLOSE_CODES:
                received_sequence = None
                resume_sequence = None
                session_id = None
                bot_id = None
                application_id = None
                resume_url = GATEWAY
            log.error("gateway_disconnected code=%s", exc.code)
            await asyncio.sleep(backoff + random.random())
            backoff = min(backoff * 2, 60)
        except Exception as exc:
            log.error("gateway_cycle_failed type=%s", type(exc).__name__)
            await asyncio.sleep(backoff + random.random())
            backoff = min(backoff * 2, 60)
