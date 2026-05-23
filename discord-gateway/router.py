#!/usr/bin/env python3
"""Discord interaction router.

Receives an INTERACTION_CREATE payload (Discord button press) and dispatches it
to the right backend by `custom_id` prefix:

    approve:<sha-prefix>      -> request_approval_responder.py approve --sha <prefix>
    reject:<sha-prefix>       -> request_approval_responder.py reject --sha <prefix>

Auth: only interactions where `user.id == config.discord.owner_user_id` are
honored. Everything else is silently rejected with an ephemeral message.

The router ALWAYS sends an immediate ACK to Discord within the 3-second
interaction window. The ACK is a deferred update so Discord keeps the message
visible. The router then PATCHes the message to reflect the final state.
"""
from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "conversations"))
from config import CONFIG  # noqa: E402

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"
LOG_PATH = LOG_DIR / "router.log"

APPROVER_USER_ID = CONFIG.discord.owner_user_id
DISCORD_API = "https://discord.com/api/v10"

REQUEST_APPROVAL_RESPONDER = REPO_ROOT / "approval" / "request_approval_responder.py"

INTERACTION_RESPONSE_DEFERRED_UPDATE = 6
INTERACTION_RESPONSE_UPDATE_MESSAGE = 7
INTERACTION_RESPONSE_CHANNEL_MESSAGE_WITH_SOURCE = 4

EPHEMERAL = 1 << 6


def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("disclawd-router")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=2_000_000, backupCount=5
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    return logger


def load_token() -> str:
    token = os.environ.get(CONFIG.discord.token_env_var, "")
    if token:
        return token
    if CONFIG.discord.token_file and CONFIG.discord.token_file.exists():
        return CONFIG.discord.token_file.read_text().strip()
    raise RuntimeError(
        f"No Discord bot token found. Set {CONFIG.discord.token_env_var} "
        "or configure discord.token_file in config.toml."
    )


def discord_post(path: str, body: dict[str, Any], token: str) -> tuple[int, str]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{DISCORD_API}{path}",
        data=data,
        headers={
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": "ClaudeDisclawdRouter/0.1",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def discord_patch(path: str, body: dict[str, Any], token: str) -> tuple[int, str]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{DISCORD_API}{path}",
        data=data,
        headers={
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": "ClaudeDisclawdRouter/0.1",
        },
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def ack_interaction(interaction_id: str, token_str: str, token: str,
                    response_type: int = INTERACTION_RESPONSE_DEFERRED_UPDATE,
                    payload: dict[str, Any] | None = None) -> tuple[int, str]:
    body: dict[str, Any] = {"type": response_type}
    if payload is not None:
        body["data"] = payload
    return discord_post(
        f"/interactions/{interaction_id}/{token_str}/callback",
        body,
        token,
    )


def send_followup_ephemeral(application_id: str, interaction_token: str,
                            content: str, token: str) -> tuple[int, str]:
    return discord_post(
        f"/webhooks/{application_id}/{interaction_token}",
        {"content": content, "flags": EPHEMERAL},
        token,
    )


def edit_message(channel_id: str, message_id: str, content: str,
                 token: str, clear_components: bool = True) -> tuple[int, str]:
    body: dict[str, Any] = {"content": content}
    if clear_components:
        body["components"] = []
    return discord_patch(
        f"/channels/{channel_id}/messages/{message_id}",
        body,
        token,
    )


def extract_user_id(interaction: dict[str, Any]) -> str:
    member = interaction.get("member") or {}
    user = member.get("user") or interaction.get("user") or {}
    return str(user.get("id", ""))


def parse_custom_id(custom_id: str) -> tuple[str, list[str]]:
    parts = custom_id.split(":")
    if not parts:
        return "", []
    return parts[0], parts[1:]


def run_responder(action: str, sha_prefix: str, channel_id: str, message_id: str,
                  logger: logging.Logger) -> tuple[int, str]:
    """Invoke the approval responder script."""
    if not REQUEST_APPROVAL_RESPONDER.exists():
        return 2, "responder script not found"
    cmd = [
        sys.executable,
        str(REQUEST_APPROVAL_RESPONDER),
        action,
        "--sha", sha_prefix,
        "--channel-id", channel_id,
        "--message-id", message_id,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    logger.info("responder rc=%s stdout=%s stderr=%s", proc.returncode,
                proc.stdout.strip()[:300], proc.stderr.strip()[:300])
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def reject_with_message(application_id: str, interaction_token: str, token: str,
                        reason: str, logger: logging.Logger) -> int:
    logger.warning("reject: %s", reason)
    send_followup_ephemeral(application_id, interaction_token, reason, token)
    return 1


def handle_interaction(interaction: dict[str, Any], logger: logging.Logger) -> int:
    """Route one interaction. Returns exit code (0 ok, non-zero error)."""
    interaction_id = str(interaction.get("id", ""))
    interaction_token = str(interaction.get("token", ""))
    application_id = str(interaction.get("application_id", ""))
    data = interaction.get("data") or {}
    custom_id = str(data.get("custom_id") or "")
    user_id = extract_user_id(interaction)
    message = interaction.get("message") or {}
    channel_id = str(interaction.get("channel_id") or message.get("channel_id") or "")
    message_id = str(message.get("id") or "")
    original_content = str(message.get("content") or "")

    logger.info(
        "interaction id=%s custom_id=%s user_id=%s channel_id=%s message_id=%s",
        interaction_id, custom_id, user_id, channel_id, message_id,
    )

    if not interaction_id or not interaction_token or not application_id:
        logger.error("missing interaction identifiers; cannot ACK")
        return 2

    try:
        token = load_token()
    except Exception as exc:  # noqa: BLE001
        logger.exception("token load failed: %s", exc)
        return 3

    # AUTH: only the configured owner.
    if user_id != APPROVER_USER_ID:
        logger.warning("rejecting interaction from non-owner user_id=%s", user_id)
        ack_interaction(
            interaction_id, interaction_token, token,
            response_type=INTERACTION_RESPONSE_CHANNEL_MESSAGE_WITH_SOURCE,
            payload={"content": "Not authorized.", "flags": EPHEMERAL},
        )
        return 1

    prefix, args = parse_custom_id(custom_id)
    timestamp = datetime.now(timezone.utc).strftime("%H:%M UTC")

    ack_status, ack_body = ack_interaction(
        interaction_id, interaction_token, token,
        response_type=INTERACTION_RESPONSE_DEFERRED_UPDATE,
    )
    logger.info("ack status=%s body=%s", ack_status, ack_body[:200])

    if prefix == "approve":
        if not args:
            return reject_with_message(application_id, interaction_token, token,
                                       "approve: missing sha prefix", logger)
        sha_prefix = args[0]
        rc, out = run_responder("approve", sha_prefix, channel_id, message_id, logger)
        if rc == 0:
            new_content = f"[APPROVED {timestamp}] {original_content}"
            edit_message(channel_id, message_id, new_content, token)
            send_followup_ephemeral(application_id, interaction_token,
                                    f"Approved sha:{sha_prefix}", token)
            return 0
        return reject_with_message(application_id, interaction_token, token,
                                   f"approve failed: {out[:200]}", logger)

    if prefix == "reject":
        if not args:
            return reject_with_message(application_id, interaction_token, token,
                                       "reject: missing sha prefix", logger)
        sha_prefix = args[0]
        rc, out = run_responder("reject", sha_prefix, channel_id, message_id, logger)
        if rc == 0:
            new_content = f"[REJECTED {timestamp}] {original_content}"
            edit_message(channel_id, message_id, new_content, token)
            send_followup_ephemeral(application_id, interaction_token,
                                    f"Rejected sha:{sha_prefix}", token)
            return 0
        return reject_with_message(application_id, interaction_token, token,
                                   f"reject failed: {out[:200]}", logger)

    return reject_with_message(application_id, interaction_token, token,
                               f"unknown custom_id prefix: {prefix}", logger)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-stdin", action="store_true",
                        help="Read interaction JSON from stdin (gateway dispatch mode)")
    parser.add_argument("--interaction-file", default="",
                        help="Read interaction JSON from a file (test mode)")
    args = parser.parse_args()

    logger = setup_logging()

    if args.from_stdin:
        raw = sys.stdin.read()
        if not raw.strip():
            print("no stdin input", file=sys.stderr)
            return 2
        interaction = json.loads(raw)
    elif args.interaction_file:
        interaction = json.loads(Path(args.interaction_file).read_text())
    else:
        print("usage: router.py --from-stdin OR --interaction-file <path>", file=sys.stderr)
        return 2

    try:
        return handle_interaction(interaction, logger)
    except Exception as exc:  # noqa: BLE001
        logger.exception("router error: %s", exc)
        return 3


if __name__ == "__main__":
    sys.exit(main())
