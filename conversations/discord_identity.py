"""Read-only Discord credential and channel identity preflight for installation."""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

from discord_http import json_request


SNOWFLAKE = re.compile(r"[1-9][0-9]{16,19}\Z")


def _snowflake(value: Any, label: str) -> str:
    normalized = str(value or "")
    if not SNOWFLAKE.fullmatch(normalized):
        raise RuntimeError(f"Discord returned an invalid {label}")
    return normalized


def inspect(token: str, chat_channel_id: str, errors_channel_id: str) -> dict[str, str]:
    if not token or any(character.isspace() for character in token):
        raise RuntimeError("Discord token is empty or malformed")
    chat_channel_id = _snowflake(chat_channel_id, "configured chat channel ID")
    errors_channel_id = _snowflake(errors_channel_id, "configured errors channel ID")

    user = json_request("GET", "/users/@me", token)
    bot_user_id = _snowflake(user.get("id"), "bot user ID")
    if user.get("bot") is not True:
        raise RuntimeError("Discord credential does not belong to a bot")

    application = json_request("GET", "/oauth2/applications/@me", token)
    application_id = _snowflake(application.get("id"), "application ID")
    if isinstance(application.get("bot"), dict):
        if _snowflake(application["bot"].get("id"), "application bot ID") != bot_user_id:
            raise RuntimeError("Discord application and bot identity do not match")

    chat = json_request("GET", f"/channels/{chat_channel_id}", token)
    if _snowflake(chat.get("id"), "chat channel ID") != chat_channel_id:
        raise RuntimeError("Discord returned a different chat channel")
    if chat.get("type") != 0:
        raise RuntimeError("Claude listen channel must be a GUILD_TEXT channel")
    guild_id = _snowflake(chat.get("guild_id"), "chat guild ID")

    errors = json_request("GET", f"/channels/{errors_channel_id}", token)
    if _snowflake(errors.get("id"), "errors channel ID") != errors_channel_id:
        raise RuntimeError("Discord returned a different errors channel")
    if _snowflake(errors.get("guild_id"), "errors guild ID") != guild_id:
        raise RuntimeError("Claude chat and errors channels must be in the same guild")

    return {
        "guild_id": guild_id,
        "bot_user_id": bot_user_id,
        "application_id": application_id,
        "chat_channel_id": chat_channel_id,
        "errors_channel_id": errors_channel_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chat-channel-id", required=True)
    parser.add_argument("--errors-channel-id", required=True)
    parser.add_argument("--token-stdin", action="store_true")
    args = parser.parse_args()
    if not args.token_stdin:
        raise SystemExit("--token-stdin is required")
    token = sys.stdin.readline().rstrip("\r\n")
    result = inspect(token, args.chat_channel_id, args.errors_channel_id)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
