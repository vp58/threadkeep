#!/usr/bin/env python3
"""Request a Discord approval for an outbound draft.

Posts the exact draft as a Discord attachment with native Approve and Reject
buttons. The configured owner must click one of those buttons. The gateway
interaction router writes an immutable approval marker at
`<repo>/discord-gateway/approvals/<full-sha>.json`.

The returned review reference records which Discord prompt the owner reviewed.
It is not a durable one-time authorization capability and must not be used by
itself to authorize an outbound side effect.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "conversations"))
from config import CONFIG  # noqa: E402
from discord_http import (  # noqa: E402
    DiscordPOSTAmbiguousError,
    json_request,
    multipart_message,
    request,
)
from discord_secret import load_discord_token  # noqa: E402
from discord_destination import validate_destination, validate_principal  # noqa: E402
from public_output import public_safe_output  # noqa: E402
import safe_files  # noqa: E402

APPROVALS_DIR = REPO_ROOT / "discord-gateway" / "approvals"
APPROVAL_BINDINGS_DIR = REPO_ROOT / "discord-gateway" / "approval-bindings"
DEFAULT_APPROVER = CONFIG.discord.owner_user_id

BINDING_VERSION = 1
MARKER_VERSION = 2
MAX_CONTROL_FILE_BYTES = 1_000_000
SNOWFLAKE_RE = re.compile(r"^[1-9][0-9]{16,19}$")
SHA_PREFIX_RE = re.compile(r"^[a-f0-9]{12,64}$")
FULL_SHA_RE = re.compile(r"^[a-f0-9]{64}$")
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
MARKER_KEYS = frozenset(
    {
        "version",
        "status",
        "action",
        "sha_prefix",
        "full_sha",
        "interaction_id",
        "user_id",
        "application_id",
        "guild_id",
        "bot_user_id",
        "channel_id",
        "message_id",
        "request_action",
        "request_target",
        "binding_sha256",
        "ts",
    }
)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _binding_digest(binding_without_digest: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(binding_without_digest)).hexdigest()


def _require_text(value: Any, label: str, maximum: int) -> str:
    text = str(value or "")
    if (
        not text.strip()
        or len(text) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise ValueError(f"invalid {label}")
    return text


def _ensure_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError(f"unsafe control directory: {path}")


def _read_private_json(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_CONTROL_FILE_BYTES
    ):
        raise RuntimeError(f"unsafe control file: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
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
        raise RuntimeError(f"control file changed while reading: {path}")
    if (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise RuntimeError(f"control file was replaced while opening: {path}")
    if len(raw) > MAX_CONTROL_FILE_BYTES:
        raise RuntimeError(f"control file is too large: {path}")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"control file is not a JSON object: {path}")
    return value


def _atomic_create_private_json(path: Path, payload: dict[str, Any]) -> None:
    _ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(_canonical_json(payload) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            raise RuntimeError(
                f"an approval for sha:{payload['sha_prefix']} is already active"
            ) from None
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_approval_binding(
    *,
    sha_prefix: str,
    full_sha: str,
    approver_user_id: str,
    expected_application_id: str,
    expected_guild_id: str,
    expected_bot_user_id: str,
    channel_id: str,
    message_id: str,
    request_action: str,
    request_target: str,
    expires_at: int,
) -> dict[str, Any]:
    if not SHA_PREFIX_RE.fullmatch(sha_prefix) or not full_sha.startswith(sha_prefix):
        raise ValueError("invalid approval SHA binding")
    if not FULL_SHA_RE.fullmatch(full_sha):
        raise ValueError("invalid full draft SHA")
    for value, label in (
        (approver_user_id, "approver user ID"),
        (expected_application_id, "expected application ID"),
        (expected_guild_id, "expected guild ID"),
        (expected_bot_user_id, "expected bot user ID"),
        (channel_id, "prompt channel ID"),
        (message_id, "prompt message ID"),
    ):
        if not SNOWFLAKE_RE.fullmatch(str(value)):
            raise ValueError(f"invalid {label}")
    action = _require_text(request_action, "request action", 200)
    target = _require_text(request_target, "request target", 2000)
    if not isinstance(expires_at, int) or expires_at <= int(time.time()):
        raise ValueError("approval expiry must be in the future")
    binding: dict[str, Any] = {
        "version": BINDING_VERSION,
        "sha_prefix": sha_prefix,
        "full_sha": full_sha,
        "approver_user_id": approver_user_id,
        "expected_application_id": expected_application_id,
        "expected_guild_id": expected_guild_id,
        "expected_bot_user_id": expected_bot_user_id,
        "discord_prompt_channel_id": channel_id,
        "discord_prompt_message_id": message_id,
        "request_action": action,
        "request_target": target,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
    }
    binding["binding_sha256"] = _binding_digest(binding)
    return binding


def validate_approval_binding(binding: dict[str, Any], *, now: int | None = None) -> None:
    if set(binding) != BINDING_KEYS or binding.get("version") != BINDING_VERSION:
        raise ValueError("approval binding has an unexpected schema")
    digest = str(binding.get("binding_sha256") or "")
    unsigned = dict(binding)
    unsigned.pop("binding_sha256", None)
    if not FULL_SHA_RE.fullmatch(digest) or _binding_digest(unsigned) != digest:
        raise ValueError("approval binding digest does not match")
    prefix = str(binding.get("sha_prefix") or "")
    full_sha = str(binding.get("full_sha") or "")
    identifiers = (
        binding.get("approver_user_id"),
        binding.get("expected_application_id"),
        binding.get("expected_guild_id"),
        binding.get("expected_bot_user_id"),
        binding.get("discord_prompt_channel_id"),
        binding.get("discord_prompt_message_id"),
    )
    if (
        not SHA_PREFIX_RE.fullmatch(prefix)
        or not FULL_SHA_RE.fullmatch(full_sha)
        or not full_sha.startswith(prefix)
        or not all(SNOWFLAKE_RE.fullmatch(str(value or "")) for value in identifiers)
    ):
        raise ValueError("approval binding contains invalid identifiers")
    _require_text(binding.get("request_action"), "request action", 200)
    _require_text(binding.get("request_target"), "request target", 2000)
    expiry = binding.get("expires_at")
    current = int(time.time()) if now is None else now
    if not isinstance(expiry, int) or expiry < current:
        raise ValueError("approval binding is expired")


def write_approval_binding(binding: dict[str, Any]) -> Path:
    validate_approval_binding(binding)
    path = APPROVAL_BINDINGS_DIR / f"{binding['sha_prefix']}.json"
    _atomic_create_private_json(path, binding)
    return path


def clear_approval_binding(sha_prefix: str, binding_sha256: str) -> None:
    path = APPROVAL_BINDINGS_DIR / f"{sha_prefix}.json"
    try:
        binding = _read_private_json(path)
        if binding.get("binding_sha256") != binding_sha256:
            return
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileNotFoundError:
        return


def ensure_binding_slot_available(sha_prefix: str, *, now: int | None = None) -> None:
    path = APPROVAL_BINDINGS_DIR / f"{sha_prefix}.json"
    try:
        binding = _read_private_json(path)
    except FileNotFoundError:
        return
    validate_approval_binding(binding, now=0)
    current = int(time.time()) if now is None else now
    expiry = binding.get("expires_at")
    if not isinstance(expiry, int) or expiry >= current:
        raise RuntimeError(f"an approval for sha:{sha_prefix} is already active")
    path.unlink()


def validate_button_marker(
    marker: dict[str, Any], binding: dict[str, Any]
) -> str:
    validate_approval_binding(binding)
    if set(marker) != MARKER_KEYS or marker.get("version") != MARKER_VERSION:
        raise ValueError("approval marker has an unexpected schema")
    status = str(marker.get("status") or "")
    action = str(marker.get("action") or "")
    if (action, status) not in {("approve", "approved"), ("reject", "rejected")}:
        raise ValueError("approval marker action and status do not match")
    exact = {
        "sha_prefix": binding["sha_prefix"],
        "full_sha": binding["full_sha"],
        "user_id": binding["approver_user_id"],
        "application_id": binding["expected_application_id"],
        "guild_id": binding["expected_guild_id"],
        "bot_user_id": binding["expected_bot_user_id"],
        "channel_id": binding["discord_prompt_channel_id"],
        "message_id": binding["discord_prompt_message_id"],
        "request_action": binding["request_action"],
        "request_target": binding["request_target"],
        "binding_sha256": binding["binding_sha256"],
    }
    for key, expected in exact.items():
        if marker.get(key) != expected:
            raise ValueError(f"approval marker {key} does not match")
    for key in ("interaction_id",):
        if not SNOWFLAKE_RE.fullmatch(str(marker.get(key) or "")):
            raise ValueError(f"approval marker {key} is invalid")
    if not isinstance(marker.get("ts"), str) or not marker["ts"]:
        raise ValueError("approval marker timestamp is invalid")
    return status


def check_button_marker(sha_prefix: str) -> dict[str, Any] | None:
    """Return the marker dict if router wrote a result for this sha prefix."""
    path = APPROVALS_DIR / f"{sha_prefix}.json"
    try:
        return _read_private_json(path)
    except FileNotFoundError:
        return None


def clear_button_marker(sha_prefix: str) -> None:
    path = APPROVALS_DIR / f"{sha_prefix}.json"
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("unsafe approval marker cannot be cleared")
        path.unlink()
    except FileNotFoundError:
        return


def attach_components(
    channel_id: str,
    message_id: str,
    components: list[dict[str, Any]],
    token: str,
) -> None:
    json_request(
        "PATCH",
        f"/channels/{channel_id}/messages/{message_id}",
        token,
        {"components": components, "allowed_mentions": {"parse": []}},
        timeout=20,
    )


def build_components(sha_prefix: str) -> list[dict]:
    """Discord action row with Approve and Reject buttons."""
    return [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "style": 3,
                    "label": "Approve",
                    "custom_id": f"approve:{sha_prefix}",
                },
                {
                    "type": 2,
                    "style": 4,
                    "label": "Reject",
                    "custom_id": f"reject:{sha_prefix}",
                },
            ],
        }
    ]


def build_attachment_review(action: str, target: str, full_sha: str) -> str:
    manifest = json.dumps(
        {"action": action, "target": target},
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    longest = max((len(run) for run in re.findall(r"`+", manifest)), default=0)
    fence = "`" * max(3, longest + 1)
    return "\n".join(
        (
            "**Approval requested**",
            f"**Draft SHA-256:** `{full_sha}`",
            "",
            "**Frozen action and target:**",
            f"{fence}json",
            manifest,
            fence,
            "",
            "The exact UTF-8 draft is attached. Review it, then tap Approve or Reject.",
        )
    )


def approval_prompt_nonce(channel_id: str, content: str, draft_text: str) -> str:
    """Return Discord's bounded deterministic idempotency key for one prompt."""

    material = "\0".join((channel_id, content, draft_text)).encode("utf-8")
    return "tka-" + hashlib.sha256(material).hexdigest()[:21]


def send_approval_prompt(
    channel_id: str, content: str, draft_text: str, token: str
) -> str:
    _ensure_private_directory(APPROVAL_BINDINGS_DIR)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".approval-draft.", suffix=".txt", dir=APPROVAL_BINDINGS_DIR
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(draft_text.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        nonce = approval_prompt_nonce(channel_id, content, draft_text)
        payload = {
            "content": content,
            "allowed_mentions": {"parse": []},
            "nonce": nonce,
            "enforce_nonce": True,
        }
        body, content_type = multipart_message(payload, [temporary])
        _, raw = request(
            "POST",
            f"/channels/{channel_id}/messages",
            token,
            body=body,
            content_type=content_type,
            timeout=45,
            max_attempts=1,
        )
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DiscordPOSTAmbiguousError(
                "Discord approval POST returned invalid JSON; no approval was armed"
            ) from exc
        if (
            not isinstance(response, dict)
            or not SNOWFLAKE_RE.fullmatch(str(response.get("id") or ""))
            or str(response.get("channel_id") or "") != channel_id
            or str(response.get("nonce") or "") != nonce
        ):
            raise DiscordPOSTAmbiguousError(
                "Discord approval POST response could not be bound; no approval was armed"
            )
        return str(response["id"])
    finally:
        temporary.unlink(missing_ok=True)


def remove_components_best_effort(
    channel_id: str, message_id: str, token: str
) -> None:
    try:
        json_request(
            "PATCH",
            f"/channels/{channel_id}/messages/{message_id}",
            token,
            {"components": [], "allowed_mentions": {"parse": []}},
            timeout=20,
        )
    except Exception:
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel-id", required=True, help="Discord channel or thread id to post in.")
    parser.add_argument("--approval-exchange-id", required=True)
    parser.add_argument("--timeout-sec", type=int, default=1800)
    parser.add_argument("--poll-interval-sec", type=int, default=5)
    args = parser.parse_args()

    if not SNOWFLAKE_RE.fullmatch(args.channel_id):
        raise SystemExit("--channel-id must be a Discord snowflake.")
    if not SNOWFLAKE_RE.fullmatch(DEFAULT_APPROVER):
        raise SystemExit("discord.owner_user_id must be a configured Discord snowflake.")
    configured_principals = (
        (CONFIG.discord.application_id, "discord.application_id"),
        (CONFIG.discord.guild_id, "discord.guild_id"),
        (CONFIG.discord.bot_user_id, "discord.bot_user_id"),
    )
    for value, label in configured_principals:
        if not SNOWFLAKE_RE.fullmatch(value):
            raise SystemExit(f"{label} must be a configured Discord snowflake.")
    try:
        exchange = json.loads(
            safe_files.read("approval", args.approval_exchange_id, consume=True)
        )
    except (json.JSONDecodeError, OSError, RuntimeError, ValueError) as exc:
        raise SystemExit("Approval exchange is invalid or unsafe.") from exc
    if not isinstance(exchange, dict) or set(exchange) != {"draft", "action", "target"}:
        raise SystemExit("Approval exchange must contain only draft, action, and target.")
    draft_text = exchange.get("draft")
    if not isinstance(draft_text, str) or not draft_text.strip() or len(draft_text) > 200_000:
        raise SystemExit("Approval draft is empty or too large.")
    try:
        action = _require_text(exchange.get("action"), "request action", 200)
        target = _require_text(exchange.get("target"), "request target", 500)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    review_packet = f"{action}\n{target}\n{draft_text}"
    if public_safe_output(review_packet, agent_name="Claude") != review_packet.strip():
        raise SystemExit(
            "Approval draft matched the public-channel sensitive-data filter; "
            "review and approve it in a private local session."
        )

    full_sha = sha256_text(draft_text)
    sha_prefix = full_sha

    try:
        ensure_binding_slot_available(sha_prefix)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    clear_button_marker(sha_prefix)

    token = load_discord_token()
    validate_principal(token)
    validate_destination(token, args.channel_id)
    try:
        prompt_ids = [
            send_approval_prompt(
                args.channel_id,
                build_attachment_review(action, target, full_sha),
                draft_text,
                token,
            )
        ]
    except DiscordPOSTAmbiguousError as exc:
        raise SystemExit(
            "Discord approval prompt outcome is ambiguous. No approval binding or "
            "buttons were created; retry the same frozen request to reconcile by nonce."
        ) from exc

    deadline = time.time() + max(1, args.timeout_sec)
    newest_prompt_id = prompt_ids[-1]
    binding = build_approval_binding(
        sha_prefix=sha_prefix,
        full_sha=full_sha,
        approver_user_id=DEFAULT_APPROVER,
        expected_application_id=CONFIG.discord.application_id,
        expected_guild_id=CONFIG.discord.guild_id,
        expected_bot_user_id=CONFIG.discord.bot_user_id,
        channel_id=args.channel_id,
        message_id=newest_prompt_id,
        request_action=action,
        request_target=target,
        expires_at=int(deadline) + 1,
    )
    try:
        write_approval_binding(binding)
        attach_components(
            args.channel_id,
            newest_prompt_id,
            build_components(sha_prefix),
            token,
        )
    except Exception:
        clear_approval_binding(sha_prefix, binding["binding_sha256"])
        raise

    try:
        while time.time() < deadline:
            marker = check_button_marker(sha_prefix)
            if marker:
                status = validate_button_marker(marker, binding)
                channel_id = marker["channel_id"]
                approval_message_id = marker["message_id"]
                if status == "approved":
                    out = {
                        "status": "approved",
                        "via": "button",
                        "channel_id": channel_id,
                        "message_id": approval_message_id,
                        "review_reference": f"{channel_id}:{approval_message_id}",
                        "authorization_capability": False,
                        "full_sha": full_sha,
                        "sha_prefix": sha_prefix,
                        "prompt_message_ids": prompt_ids,
                    }
                    print(json.dumps(out, indent=2))
                    clear_button_marker(sha_prefix)
                    return 0
                if status == "rejected":
                    out = {
                        "status": "rejected",
                        "via": "button",
                        "channel_id": channel_id,
                        "message_id": approval_message_id,
                        "full_sha": full_sha,
                        "sha_prefix": sha_prefix,
                        "prompt_message_ids": prompt_ids,
                    }
                    print(json.dumps(out, indent=2))
                    clear_button_marker(sha_prefix)
                    return 2

            time.sleep(max(1, args.poll_interval_sec))

        print(json.dumps({
            "status": "timeout",
            "channel_id": args.channel_id,
            "full_sha": full_sha,
            "sha_prefix": sha_prefix,
            "prompt_message_ids": prompt_ids,
        }, indent=2))
        return 1
    finally:
        remove_components_best_effort(args.channel_id, newest_prompt_id, token)
        clear_approval_binding(sha_prefix, binding["binding_sha256"])


if __name__ == "__main__":
    sys.exit(main())
