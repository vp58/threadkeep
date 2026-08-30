"""Principal and destination checks for Claude Discord helper egress."""
from __future__ import annotations

import re
from typing import Any

from config import CONFIG
from discord_http import json_request
import lib


SNOWFLAKE = re.compile(r"[1-9][0-9]{16,19}\Z")
PUBLIC_THREAD_TYPES = {10, 11}


def _snowflake(value: Any, label: str) -> str:
    normalized = str(value or "")
    if not SNOWFLAKE.fullmatch(normalized):
        raise RuntimeError(f"invalid Discord {label}")
    return normalized


def validate_principal(token: str) -> None:
    user = json_request("GET", "/users/@me", token)
    if user.get("bot") is not True or _snowflake(user.get("id"), "bot ID") != CONFIG.discord.bot_user_id:
        raise RuntimeError("Discord credential does not match the configured Claude bot")
    application = json_request("GET", "/oauth2/applications/@me", token)
    if _snowflake(application.get("id"), "application ID") != CONFIG.discord.application_id:
        raise RuntimeError("Discord credential does not match the configured Claude application")


def validate_destination(
    token: str,
    channel_id: str,
    *,
    allow_chat_root: bool = False,
    allow_errors: bool = False,
) -> dict[str, Any]:
    channel_id = _snowflake(channel_id, "destination channel ID")
    allowed_root = (
        (allow_chat_root and channel_id == CONFIG.discord.chat_channel_id)
        or (allow_errors and channel_id == CONFIG.discord.errors_channel_id)
    )
    if not allowed_root and lib.thread_to_session(channel_id) is None:
        raise RuntimeError("Discord destination is not a registered Threadkeep thread")

    channel = json_request("GET", f"/channels/{channel_id}", token)
    if _snowflake(channel.get("id"), "returned channel ID") != channel_id:
        raise RuntimeError("Discord returned a different destination channel")
    if _snowflake(channel.get("guild_id"), "destination guild ID") != CONFIG.discord.guild_id:
        raise RuntimeError("Discord destination is outside the configured guild")
    if allowed_root:
        if channel.get("type") != 0:
            raise RuntimeError("configured Discord root must be a guild text channel")
        return channel
    if (
        channel.get("type") not in PUBLIC_THREAD_TYPES
        or _snowflake(channel.get("parent_id"), "thread parent ID")
        != CONFIG.discord.chat_channel_id
    ):
        raise RuntimeError("Discord destination is not a public child of the Claude channel")
    return channel


def validate_owner_anchor(token: str, channel_id: str, message_id: str) -> None:
    if _snowflake(channel_id, "anchor channel ID") != CONFIG.discord.chat_channel_id:
        raise RuntimeError("Threadkeep threads can only be created in the Claude channel")
    message_id = _snowflake(message_id, "anchor message ID")
    message = json_request(
        "GET", f"/channels/{channel_id}/messages/{message_id}", token
    )
    author = message.get("author")
    if not isinstance(author, dict) or _snowflake(author.get("id"), "anchor author ID") != CONFIG.discord.owner_user_id:
        raise RuntimeError("Threadkeep thread anchor was not posted by the configured owner")
