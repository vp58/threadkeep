#!/usr/bin/env python3
"""Send a message to a Discord channel via the configured bot token.

The token is loaded through Threadkeep's narrow Keychain resolver and is never
placed in a curl command line.
"""

import argparse
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "conversations"))
from config import CONFIG  # noqa: E402
from discord_destination import validate_destination, validate_principal  # noqa: E402
from discord_http import DiscordPOSTAmbiguousError, json_request  # noqa: E402
from discord_secret import load_discord_token  # noqa: E402
from public_output import public_safe_output  # noqa: E402
import safe_files  # noqa: E402

CHANNEL_ALIASES = {
    "chat": CONFIG.discord.chat_channel_id,
    "errors": CONFIG.discord.errors_channel_id,
}
OWNER_MENTION = f"<@{CONFIG.discord.owner_user_id}>" if CONFIG.discord.owner_user_id else ""
SNOWFLAKE_RE = re.compile(r"^[1-9][0-9]{16,19}$")


def load_token():
    return load_discord_token()


def send_message(channel_id, content, token, max_retries=0, *, mention_owner=False):
    if max_retries != 0:
        raise ValueError(
            "Discord message POST retries are disabled because an unsuccessful "
            "response can have an ambiguous delivery outcome"
        )
    allowed_mentions = {"parse": []}
    if mention_owner:
        allowed_mentions["users"] = [CONFIG.discord.owner_user_id]
    payload_obj = {"content": content, "allowed_mentions": allowed_mentions}
    path = f"/channels/{channel_id}/messages"
    result = json_request(
        "POST", path, token, payload_obj, timeout=45, max_attempts=1
    )
    author = result.get("author")
    if (
        not SNOWFLAKE_RE.fullmatch(str(result.get("id") or ""))
        or str(result.get("channel_id") or "") != str(channel_id)
        or not isinstance(author, dict)
        or str(author.get("id") or "") != CONFIG.discord.bot_user_id
    ):
        raise DiscordPOSTAmbiguousError(
            "Discord message POST response could not be bound; do not retry automatically"
        )
    return result


def main():
    parser = argparse.ArgumentParser(description="Send a Discord message")
    parser.add_argument(
        "--channel-id",
        required=True,
        help="Discord channel id or configured alias (chat, errors)",
    )
    parser.add_argument("--message", default="", help="Message content")
    parser.add_argument(
        "--message-exchange-id",
        default="",
        help="Private response exchange ID allocated by conversations/safe_files.py",
    )
    parser.add_argument(
        "--mention-owner",
        action="store_true",
        help="Prepend the configured owner mention",
    )
    args = parser.parse_args()

    channel_id = CHANNEL_ALIASES.get(args.channel_id, args.channel_id)
    if args.message and args.message_exchange_id:
        raise RuntimeError("choose either --message or --message-exchange-id")
    message = (
        safe_files.read("response", args.message_exchange_id, consume=False)
        if args.message_exchange_id
        else args.message
    )
    if not message:
        raise RuntimeError("Discord message must not be empty")
    message = public_safe_output(message, agent_name="Claude")
    if len(message) > 1900:
        raise RuntimeError("Discord message must contain 1 to 1900 characters")
    if args.mention_owner:
        if not OWNER_MENTION:
            raise RuntimeError("owner_user_id is missing in config.toml")
        message = f"{OWNER_MENTION} {message}"

    token = load_token()
    validate_principal(token)
    validate_destination(
        token,
        channel_id,
        allow_chat_root=channel_id == CONFIG.discord.chat_channel_id,
        allow_errors=channel_id == CONFIG.discord.errors_channel_id,
    )
    result = send_message(  # gitleaks:allow - variables are loaded at runtime; no literal credential.
        channel_id, message, token, mention_owner=args.mention_owner  # gitleaks:allow
    )

    msg_id = result.get("id", "unknown")
    print(f"Sent to channel {channel_id}: {result.get('content', '')} (id: {msg_id})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
