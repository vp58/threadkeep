#!/usr/bin/env python3
"""Discord interaction router.

Receives an INTERACTION_CREATE payload (Discord button press) and dispatches it
to the right backend by `custom_id` prefix:

    approve:<sha-prefix>      -> request_approval_responder.py --from-stdin
    reject:<sha-prefix>       -> request_approval_responder.py --from-stdin

Auth: only interactions where `user.id == config.discord.owner_user_id` are
honored. Everything else is silently rejected with an ephemeral message.

After local validation, the router first sends a deferred-update callback to
meet Discord's interaction deadline. It then records the decision through the
responder and PATCHes the authenticated source message. A row is complete only
when that PATCH succeeds; callback or update failures remain retryable in the
Gateway client's durable inbox.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import logging.handlers
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "conversations"))
from config import CONFIG  # noqa: E402
from discord_http import direct_urlopen  # noqa: E402
from discord_secret import load_discord_token, sanitized_child_environment  # noqa: E402

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"
LOG_PATH = LOG_DIR / "router.log"

APPROVER_USER_ID = CONFIG.discord.owner_user_id
DISCORD_API = "https://discord.com/api/v10"


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

REQUEST_APPROVAL_RESPONDER = REPO_ROOT / "approval" / "request_approval_responder.py"
APPROVAL_BINDINGS_DIR = HERE / "approval-bindings"

INTERACTION_RESPONSE_DEFERRED_UPDATE = 6
INTERACTION_RESPONSE_CHANNEL_MESSAGE_WITH_SOURCE = 4

EPHEMERAL = 1 << 6
SNOWFLAKE_RE = re.compile(r"^[1-9][0-9]{16,19}$")
SHA_PREFIX_RE = re.compile(r"^[a-f0-9]{12,64}$")
FULL_SHA_RE = re.compile(r"^[a-f0-9]{64}$")
BINDING_VERSION = 1
MAX_CONTROL_FILE_BYTES = 1_000_000
MAX_ROUTER_INPUT_BYTES = 1_100_000
ROUTER_ENVELOPE_KEYS = frozenset(
    {
        "interaction",
        "expected_application_id",
        "expected_bot_user_id",
        "expected_guild_id",
        "interaction_preacknowledged",
    }
)
BINDING_KEYS = frozenset(
    {
        "version",
        "sha_prefix",
        "full_sha",
        "approver_user_id",
        "expected_application_id",
        "expected_guild_id",
        "expected_bot_user_id",
        "discord_prompt_channel_id",
        "discord_prompt_message_id",
        "request_action",
        "request_target",
        "created_at",
        "expires_at",
        "binding_sha256",
    }
)

ROUTER_OK = 0
ROUTER_REJECTED = 1
ROUTER_RETRY = 2
RESPONDER_ALREADY_DECIDED = 4


@dataclass(frozen=True)
class ApprovalBinding:
    full_sha: str
    request_action: str
    request_target: str
    binding_sha256: str


def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("threadkeep-router")
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
    return load_discord_token()


def discord_request(
    method: str,
    path: str,
    body: dict[str, Any],
    token: str,
    *,
    timeout: float,
) -> tuple[int, str]:
    _require_direct_discord_transport()
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{DISCORD_API}{path}",
        data=data,
        headers={
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": "ThreadkeepRouter/0.1",
        },
        method=method,
    )
    try:
        with direct_urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        finally:
            exc.close()
        return exc.code, body
    except (TimeoutError, urllib.error.URLError, OSError):
        # Direct-mode interaction tokens live in callback URLs. Keep request
        # details out of exceptions because the caller persists router logs.
        raise RuntimeError("Discord REST transport failed") from None


def discord_post(path: str, body: dict[str, Any], token: str) -> tuple[int, str]:
    return discord_request("POST", path, body, token, timeout=2.5)


def discord_patch(path: str, body: dict[str, Any], token: str) -> tuple[int, str]:
    return discord_request("PATCH", path, body, token, timeout=10)


def status_ok(status: int) -> bool:
    return 200 <= status < 300


def status_retryable(status: int) -> bool:
    return status in {408, 409, 425, 429} or status >= 500


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


def extract_user_id(interaction: dict[str, Any]) -> str:
    member = interaction.get("member") or {}
    user = member.get("user") or interaction.get("user") or {}
    return str(user.get("id", ""))


def parse_custom_id(custom_id: str) -> tuple[str, list[str]]:
    parts = custom_id.split(":")
    if not parts:
        return "", []
    return parts[0], parts[1:]


def run_responder(
    action: str,
    sha_prefix: str,
    channel_id: str,
    message_id: str,
    interaction_id: str,
    user_id: str,
    application_id: str,
    guild_id: str,
    bot_user_id: str,
    binding: ApprovalBinding,
    logger: logging.Logger,
) -> tuple[int, str]:
    """Invoke the approval responder script."""
    if not REQUEST_APPROVAL_RESPONDER.exists():
        return 2, "responder script not found"
    cmd = [
        sys.executable,
        str(REQUEST_APPROVAL_RESPONDER),
        "--from-stdin",
    ]
    responder_input = {
        "action": action,
        "sha": sha_prefix,
        "channel_id": channel_id,
        "message_id": message_id,
        "interaction_id": interaction_id,
        "user_id": user_id,
        "application_id": application_id,
        "guild_id": guild_id,
        "bot_user_id": bot_user_id,
        "full_sha": binding.full_sha,
        "request_action": binding.request_action,
        "request_target": binding.request_target,
        "binding_sha256": binding.binding_sha256,
    }
    proc = subprocess.run(
        cmd,
        input=json.dumps(responder_input, separators=(",", ":")),
        capture_output=True,
        text=True,
        timeout=60,
        env=sanitized_child_environment(),
    )
    # Responder output contains a private marker path. Do not copy child output
    # into router logs or higher-level retry errors.
    logger.info("responder rc=%s", proc.returncode)
    return proc.returncode, ""


def patch_message(
    channel_id: str,
    message_id: str,
    token: str,
    new_content: str,
    logger: logging.Logger,
) -> int:
    status, body = discord_patch(
        f"/channels/{channel_id}/messages/{message_id}",
        {
            "content": new_content[:1900],
            "components": [],
            "allowed_mentions": {"parse": []},
        },
        token,
    )
    logger.info("patch(message) status=%s", status)
    return status


def clear_message_components(
    channel_id: str,
    message_id: str,
    token: str,
    logger: logging.Logger,
) -> int:
    status, _body = discord_patch(
        f"/channels/{channel_id}/messages/{message_id}",
        {"components": [], "allowed_mentions": {"parse": []}},
        token,
    )
    logger.info("patch(clear-components) status=%s", status)
    return status


def reject_with_message(interaction_id: str, interaction_token: str, token: str,
                        reason: str, logger: logging.Logger) -> int:
    """Failure ACK: ephemeral error reply, no message update."""
    logger.warning("reject: %s", reason)
    status, body = ack_interaction(
        interaction_id, interaction_token, token,
        response_type=INTERACTION_RESPONSE_CHANNEL_MESSAGE_WITH_SOURCE,
        payload={"content": reason[:1900], "flags": EPHEMERAL},
    )
    logger.info("ack(rejection) status=%s", status)
    return ROUTER_REJECTED if status_ok(status) else ROUTER_RETRY


def reject_terminally(
    interaction_id: str,
    interaction_token: str,
    token: str,
    reason: str,
    logger: logging.Logger,
    *,
    interaction_preacknowledged: bool,
) -> int:
    if interaction_preacknowledged:
        logger.warning("terminal rejection after Gateway ACK: %s", reason)
        return ROUTER_REJECTED
    return reject_with_message(
        interaction_id, interaction_token, token, reason, logger
    )


def _require_snowflake(value: Any, label: str) -> str:
    normalized = str(value or "")
    if not SNOWFLAKE_RE.fullmatch(normalized):
        raise ValueError(f"invalid {label}")
    return normalized


def _message_has_custom_id(message: dict[str, Any], custom_id: str) -> bool:
    for row in message.get("components") or []:
        if not isinstance(row, dict):
            continue
        for component in row.get("components") or []:
            if isinstance(component, dict) and component.get("custom_id") == custom_id:
                return True
    return False


def _interaction_timestamp(interaction_id: str) -> str:
    discord_epoch_ms = 1_420_070_400_000
    created_ms = (int(interaction_id) >> 22) + discord_epoch_ms
    created = datetime.fromtimestamp(created_ms / 1000, tz=timezone.utc)
    return created.strftime("%H:%M UTC")


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _read_private_control(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_CONTROL_FILE_BYTES
    ):
        raise ValueError("approval binding file is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_CONTROL_FILE_BYTES:
            chunk = os.read(
                descriptor, min(65536, MAX_CONTROL_FILE_BYTES + 1 - len(raw))
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable = (before.st_dev, before.st_ino, before.st_uid, before.st_mode, before.st_nlink)
    if stable != (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_nlink):
        raise ValueError("approval binding changed while reading")
    if (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise ValueError("approval binding was replaced while opening")
    if len(raw) > MAX_CONTROL_FILE_BYTES:
        raise ValueError("approval binding is too large")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("approval binding is not a JSON object")
    return value


def _require_binding_text(value: Any, label: str, maximum: int) -> str:
    text = str(value or "")
    if not text.strip() or len(text) > maximum or "\x00" in text:
        raise ValueError(f"invalid approval binding {label}")
    return text


def _validate_request_binding(
    sha_prefix: str,
    channel_id: str,
    message_id: str,
    user_id: str,
    application_id: str,
    guild_id: str,
    bot_user_id: str,
) -> ApprovalBinding | None:
    path = APPROVAL_BINDINGS_DIR / f"{sha_prefix}.json"
    try:
        binding = _read_private_control(path)
    except FileNotFoundError:
        return None
    if set(binding) != BINDING_KEYS or binding.get("version") != BINDING_VERSION:
        raise ValueError("approval request binding has an unexpected schema")
    digest = str(binding.get("binding_sha256") or "")
    unsigned = dict(binding)
    unsigned.pop("binding_sha256", None)
    if not FULL_SHA_RE.fullmatch(digest) or hashlib.sha256(
        _canonical_json(unsigned)
    ).hexdigest() != digest:
        raise ValueError("approval request binding digest does not match")
    full_sha = str(binding.get("full_sha") or "")
    expected = (
        ("sha_prefix", sha_prefix),
        ("discord_prompt_channel_id", channel_id),
        ("discord_prompt_message_id", message_id),
        ("approver_user_id", user_id),
        ("expected_application_id", application_id),
        ("expected_guild_id", guild_id),
        ("expected_bot_user_id", bot_user_id),
    )
    for key, actual in expected:
        if binding.get(key) != actual:
            raise ValueError(f"approval request {key} binding does not match")
    if not FULL_SHA_RE.fullmatch(full_sha) or not full_sha.startswith(sha_prefix):
        raise ValueError("approval request full SHA does not match")
    expiry = binding.get("expires_at")
    if not isinstance(expiry, int) or expiry < int(datetime.now(timezone.utc).timestamp()):
        raise ValueError("approval request binding is expired")
    return ApprovalBinding(
        full_sha=full_sha,
        request_action=_require_binding_text(
            binding.get("request_action"), "request action", 200
        ),
        request_target=_require_binding_text(
            binding.get("request_target"), "request target", 2000
        ),
        binding_sha256=digest,
    )


def _load_approval_binding(
    sha_prefix: str,
    channel_id: str,
    message_id: str,
    user_id: str,
    application_id: str,
    guild_id: str,
    bot_user_id: str,
) -> ApprovalBinding:
    request_binding = _validate_request_binding(
        sha_prefix,
        channel_id,
        message_id,
        user_id,
        application_id,
        guild_id,
        bot_user_id,
    )
    if request_binding is not None:
        return request_binding
    raise ValueError("no frozen approval binding exists")


def handle_interaction(
    interaction: dict[str, Any],
    logger: logging.Logger,
    *,
    expected_application_id: str = "",
    expected_bot_user_id: str = "",
    expected_guild_id: str = "",
    interaction_preacknowledged: bool = False,
) -> int:
    """Route one interaction. Returns exit code (0 ok, non-zero error)."""
    interaction_id = str(interaction.get("id", ""))
    interaction_token = str(interaction.get("token", ""))
    application_id = str(interaction.get("application_id", ""))
    data = interaction.get("data") or {}
    if not isinstance(data, dict):
        logger.error("interaction data is not an object")
        return ROUTER_RETRY
    custom_id = str(data.get("custom_id") or "")
    user_id = extract_user_id(interaction)
    message = interaction.get("message") or {}
    if not isinstance(message, dict):
        logger.error("interaction message is not an object")
        return ROUTER_RETRY
    channel_id = str(interaction.get("channel_id") or message.get("channel_id") or "")
    message_id = str(message.get("id") or "")
    original_content = str(message.get("content") or "")

    try:
        interaction_id = _require_snowflake(interaction_id, "interaction ID")
        application_id = _require_snowflake(application_id, "application ID")
        channel_id = _require_snowflake(channel_id, "channel ID")
        message_id = _require_snowflake(message_id, "message ID")
        guild_id = _require_snowflake(interaction.get("guild_id"), "guild ID")
        expected_application_id = _require_snowflake(
            expected_application_id, "expected application ID"
        )
        expected_bot_user_id = _require_snowflake(
            expected_bot_user_id, "expected bot user ID"
        )
        expected_guild_id = _require_snowflake(
            expected_guild_id, "expected guild ID"
        )
        configured_application_id = _require_snowflake(
            CONFIG.discord.application_id, "configured application ID"
        )
        configured_bot_user_id = _require_snowflake(
            CONFIG.discord.bot_user_id, "configured bot user ID"
        )
        configured_guild_id = _require_snowflake(
            CONFIG.discord.guild_id, "configured guild ID"
        )
        if expected_application_id != configured_application_id:
            raise ValueError("durable application binding is no longer configured")
        if expected_bot_user_id != configured_bot_user_id:
            raise ValueError("durable bot binding is no longer configured")
        if expected_guild_id != configured_guild_id:
            raise ValueError("durable guild binding is no longer configured")
        author_id = _require_snowflake(
            (message.get("author") or {}).get("id"), "message author ID"
        )
        user_id = _require_snowflake(user_id, "actor user ID")
        if application_id != expected_application_id:
            raise ValueError("application binding does not match")
        if guild_id != expected_guild_id:
            raise ValueError("guild binding does not match")
        if author_id != expected_bot_user_id:
            raise ValueError("source message is not owned by the token bot")
        if (
            interaction.get("type") != 3
            or data.get("component_type") != 2
            or not _message_has_custom_id(message, custom_id)
        ):
            raise ValueError("clicked component is not bound to the source message")
        if interaction_preacknowledged and interaction_token:
            raise ValueError("durable interaction retained its callback token")
        if not interaction_preacknowledged and not interaction_token:
            raise ValueError("interaction token is missing")
    except (AttributeError, TypeError, ValueError) as exc:
        logger.error("interaction principal binding failed: %s", exc)
        # A pre-ACKed inbox row cannot become valid on retry: its payload and
        # frozen READY/config bindings are immutable. Complete it as denied so
        # malformed or stale rows cannot consume the inbox forever.
        return ROUTER_REJECTED if interaction_preacknowledged else ROUTER_RETRY

    try:
        token = load_token()
    except Exception as exc:  # noqa: BLE001
        logger.error("Discord credential resolution failed: %s", type(exc).__name__)
        return 3

    # AUTH: only the configured owner.
    if user_id != APPROVER_USER_ID:
        logger.warning("rejecting interaction from non-owner")
        if interaction_preacknowledged:
            return ROUTER_REJECTED
        status, body = ack_interaction(
            interaction_id, interaction_token, token,
            response_type=INTERACTION_RESPONSE_CHANNEL_MESSAGE_WITH_SOURCE,
            payload={"content": "Not authorized.", "flags": EPHEMERAL},
        )
        logger.info("ack(unauthorized) status=%s", status)
        return ROUTER_REJECTED if status_ok(status) else ROUTER_RETRY

    prefix, args = parse_custom_id(custom_id)
    timestamp = _interaction_timestamp(interaction_id)

    if prefix not in {"approve", "reject"}:
        return reject_terminally(
            interaction_id,
            interaction_token,
            token,
            "Unsupported approval action.",
            logger,
            interaction_preacknowledged=interaction_preacknowledged,
        )
    if len(args) != 1 or not SHA_PREFIX_RE.fullmatch(args[0]):
        return reject_terminally(
            interaction_id,
            interaction_token,
            token,
            "Approval identifier is invalid.",
            logger,
            interaction_preacknowledged=interaction_preacknowledged,
        )
    sha_prefix = args[0]
    try:
        binding = _load_approval_binding(
            sha_prefix,
            channel_id,
            message_id,
            user_id,
            application_id,
            guild_id,
            expected_bot_user_id,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        logger.error("approval binding failed: %s", exc)
        return reject_terminally(
            interaction_id,
            interaction_token,
            token,
            "Approval binding could not be verified.",
            logger,
            interaction_preacknowledged=interaction_preacknowledged,
        )

    # Close the interaction deadline before backend work. The durable inbox
    # retries any rc>=2 row. On replay an expired/already-used callback may
    # fail, but a successful authenticated message PATCH remains a safe
    # fallback completion signal.
    if interaction_preacknowledged:
        acked = True
        logger.info("initial interaction ACK was committed by Gateway client")
    else:
        ack_status, ack_body = ack_interaction(
            interaction_id,
            interaction_token,
            token,
            response_type=INTERACTION_RESPONSE_DEFERRED_UPDATE,
        )
        acked = status_ok(ack_status)
        logger.info("ack(deferred_update) status=%s", ack_status)

    if prefix == "approve":
        rc, out = run_responder(
            "approve",
            sha_prefix,
            channel_id,
            message_id,
            interaction_id,
            user_id,
            application_id,
            guild_id,
            expected_bot_user_id,
            binding,
            logger,
        )
        if rc == 0:
            new_content = f"[APPROVED {timestamp}] {original_content}"
            patch_status = patch_message(
                channel_id, message_id, token, new_content, logger
            )
            if status_ok(patch_status):
                return ROUTER_OK
            if not status_retryable(patch_status):
                logger.error("approve PATCH failed permanently with HTTP %s", patch_status)
                return ROUTER_REJECTED
        elif rc == RESPONDER_ALREADY_DECIDED:
            patch_status = clear_message_components(
                channel_id, message_id, token, logger
            )
            if status_ok(patch_status) or not status_retryable(patch_status):
                logger.warning("approval request already had an immutable decision")
                return ROUTER_REJECTED
        logger.error(
            "approve completion failed responder_rc=%s acked=%s",
            rc,
            acked,
        )
        return ROUTER_RETRY

    if prefix == "reject":
        rc, out = run_responder(
            "reject",
            sha_prefix,
            channel_id,
            message_id,
            interaction_id,
            user_id,
            application_id,
            guild_id,
            expected_bot_user_id,
            binding,
            logger,
        )
        if rc == 0:
            new_content = f"[REJECTED {timestamp}] {original_content}"
            patch_status = patch_message(
                channel_id, message_id, token, new_content, logger
            )
            if status_ok(patch_status):
                return ROUTER_OK
            if not status_retryable(patch_status):
                logger.error("reject PATCH failed permanently with HTTP %s", patch_status)
                return ROUTER_REJECTED
        elif rc == RESPONDER_ALREADY_DECIDED:
            patch_status = clear_message_components(
                channel_id, message_id, token, logger
            )
            if status_ok(patch_status) or not status_retryable(patch_status):
                logger.warning("approval request already had an immutable decision")
                return ROUTER_REJECTED
        logger.error(
            "reject completion failed responder_rc=%s acked=%s",
            rc,
            acked,
        )
        return ROUTER_RETRY

    return ROUTER_RETRY


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-stdin", action="store_true", required=True,
                        help="Read interaction JSON from stdin (gateway dispatch mode)")
    parser.parse_args()

    logger = setup_logging()

    raw = sys.stdin.read(MAX_ROUTER_INPUT_BYTES + 1)
    if not raw.strip():
        print("no stdin input", file=sys.stderr)
        return 2
    if len(raw.encode("utf-8")) > MAX_ROUTER_INPUT_BYTES:
        print("router input is too large", file=sys.stderr)
        return 2
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != ROUTER_ENVELOPE_KEYS:
        print("router stdin requires a complete dispatch envelope", file=sys.stderr)
        return 2
    interaction = value.get("interaction")
    expected_application_id = value.get("expected_application_id")
    expected_bot_user_id = value.get("expected_bot_user_id")
    expected_guild_id = value.get("expected_guild_id")
    interaction_preacknowledged = value.get("interaction_preacknowledged")
    if (
        not isinstance(interaction, dict)
        or not isinstance(expected_application_id, str)
        or not isinstance(expected_bot_user_id, str)
        or not isinstance(expected_guild_id, str)
        or interaction_preacknowledged is not True
    ):
        print("router envelope has invalid field types", file=sys.stderr)
        return 2

    try:
        return handle_interaction(
            interaction,
            logger,
            expected_application_id=expected_application_id,
            expected_bot_user_id=expected_bot_user_id,
            expected_guild_id=expected_guild_id,
            interaction_preacknowledged=interaction_preacknowledged,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("router error: %s", exc)
        return 3


if __name__ == "__main__":
    sys.exit(main())
