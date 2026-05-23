#!/usr/bin/env python3
"""Send a message to a Discord channel via the configured bot token.

Token resolution order:
  1. Environment variable named by config.discord.token_env_var (default DISCORD_BOT_TOKEN)
  2. Optional token file at config.discord.token_file

No platform-specific keyring fallback. Use a process manager or your shell
profile to populate the env var.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "conversations"))
from config import CONFIG  # noqa: E402

CHANNEL_ALIASES = {
    "chat": CONFIG.discord.chat_channel_id,
    "errors": CONFIG.discord.errors_channel_id,
}
OWNER_MENTION = f"<@{CONFIG.discord.owner_user_id}>" if CONFIG.discord.owner_user_id else ""


def load_token():
    token = os.environ.get(CONFIG.discord.token_env_var, "")
    if token:
        return token
    if CONFIG.discord.token_file and CONFIG.discord.token_file.exists():
        return CONFIG.discord.token_file.read_text().strip()
    raise RuntimeError(
        f"No Discord bot token found. Set {CONFIG.discord.token_env_var} "
        "or configure discord.token_file in config.toml."
    )


def send_message(channel_id, content, token, max_retries=3, files=None, components_json=""):
    url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
    files = files or []
    payload_obj = {"content": content}
    if components_json:
        try:
            payload_obj["components"] = json.loads(components_json)
        except json.JSONDecodeError:
            raise RuntimeError("invalid components_json")
    payload = json.dumps(payload_obj)
    import time
    for attempt in range(max_retries):
        if files:
            cmd = [
                "curl", "-s", "--retry", "3", "--retry-delay", "5",
                "--retry-connrefused", "--connect-timeout", "10",
                "-X", "POST",
                "-H", f"Authorization: Bot {token}",
                "-F", f"payload_json={payload}",
            ]
            for idx, file_path in enumerate(files):
                cmd.extend(["-F", f"files[{idx}]=@{file_path}"])
            cmd.append(url)
        else:
            cmd = [
                "curl", "-s", "--retry", "3", "--retry-delay", "5",
                "--retry-connrefused", "--connect-timeout", "10",
                "-X", "POST",
                "-H", f"Authorization: Bot {token}",
                "-H", "Content-Type: application/json",
                "-d", payload,
                url,
            ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            if attempt < max_retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            raise RuntimeError(f"curl failed after {max_retries} attempts: {result.stderr}")
        try:
            resp = json.loads(result.stdout)
            if "id" in resp:
                return resp
            if attempt < max_retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            return resp
        except json.JSONDecodeError:
            if attempt < max_retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            raise RuntimeError(f"Non-JSON response after {max_retries} attempts: {result.stdout[:200]}")


def main():
    parser = argparse.ArgumentParser(description="Send a Discord message")
    parser.add_argument(
        "--channel-id",
        required=True,
        help="Discord channel id or configured alias (chat, errors)",
    )
    parser.add_argument("--message", default="", help="Message content")
    parser.add_argument(
        "--files",
        default="",
        help="Comma-separated local file paths to attach",
    )
    parser.add_argument(
        "--components-json",
        default="",
        help="JSON array of Discord message components (for buttons)",
    )
    parser.add_argument(
        "--mention-owner",
        action="store_true",
        help="Prepend the configured owner mention",
    )
    args = parser.parse_args()

    channel_id = CHANNEL_ALIASES.get(args.channel_id, args.channel_id)
    message = args.message
    if args.mention_owner:
        if not OWNER_MENTION:
            raise RuntimeError("owner_user_id is missing in config.toml")
        message = f"{OWNER_MENTION} {message}"

    token = load_token()
    files = [f.strip() for f in args.files.split(",") if f.strip()]
    result = send_message(
        channel_id, message, token,
        files=files,
        components_json=args.components_json,
    )

    msg_id = result.get("id", "unknown")
    print(f"Sent to channel {channel_id}: {result.get('content', '')} (id: {msg_id})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
