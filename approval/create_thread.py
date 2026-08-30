#!/usr/bin/env python3
"""Create or reconcile one starter-message Discord thread from JSON stdin."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from send_message import load_token  # noqa: E402

sys.path.insert(0, str(_HERE.parent / "conversations"))
from config import CONFIG  # noqa: E402
from discord_destination import validate_owner_anchor, validate_principal  # noqa: E402
from discord_http import DiscordHTTPError, json_request  # noqa: E402
from public_output import public_safe_output, withheld_notice  # noqa: E402

SNOWFLAKE = re.compile(r"[1-9][0-9]{16,19}\Z")
RECOVERY_ABSENCE_PROBES = 3
RECOVERY_PROBE_DELAY_SECONDS = 0.25


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise RuntimeError("thread request is too large")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("thread request must be one UTF-8 JSON object") from exc
    expected = {"operation", "channel_id", "message_id", "name", "auto_archive"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise RuntimeError("thread request has an invalid object shape")
    if payload["operation"] not in {"create", "reconcile", "recover"}:
        raise RuntimeError("thread operation must be create, reconcile, or recover")
    for key in ("channel_id", "message_id"):
        value = payload[key]
        if not isinstance(value, str) or not SNOWFLAKE.fullmatch(value):
            raise RuntimeError(f"thread {key} must be a Discord snowflake")
    name = payload["name"]
    if (
        not isinstance(name, str)
        or not name.strip()
        or len(name) > 100
        or "\n" in name
        or "\r" in name
    ):
        raise RuntimeError("thread name is invalid")
    if payload["auto_archive"] not in {60, 1440, 4320, 10080}:
        raise RuntimeError("thread auto-archive duration is invalid")
    return payload


def _safe_name(name: str) -> str:
    value = public_safe_output(name, agent_name="Claude")
    if value == withheld_notice("Claude"):
        value = "Threadkeep conversation"
    value = " ".join(value.split())[:100].strip()
    if not value:
        raise RuntimeError("thread name became empty after filtering")
    return value


def _validate_thread(
    value: dict[str, Any], *, channel_id: str, message_id: str, name: str
) -> dict[str, Any]:
    exact = (
        str(value.get("id") or "") == message_id
        and str(value.get("parent_id") or "") == channel_id
        and value.get("type") == 11
        and str(value.get("owner_id") or "") == CONFIG.discord.bot_user_id
        and str(value.get("name") or "") == name
    )
    if not exact:
        raise RuntimeError("Discord thread does not match its frozen starter binding")
    return value


def _get_existing(
    token: str, *, channel_id: str, message_id: str, name: str
) -> dict[str, Any] | None:
    try:
        value = json_request(
            "GET", f"/channels/{message_id}", token, timeout=30, max_attempts=4
        )
    except DiscordHTTPError as exc:
        if exc.status == 404:
            return None
        raise
    return _validate_thread(
        value, channel_id=channel_id, message_id=message_id, name=name
    )


def _create_once(
    token: str,
    *,
    channel_id: str,
    message_id: str,
    name: str,
    auto_archive: int,
) -> dict[str, Any]:
    return json_request(
        "POST",
        f"/channels/{channel_id}/messages/{message_id}/threads",
        token,
        {"name": name, "auto_archive_duration": auto_archive},
        timeout=45,
        max_attempts=1,
    )


def _bounded_absence_probe(
    token: str,
    *,
    channel_id: str,
    message_id: str,
    name: str,
) -> dict[str, Any] | None:
    """Require several exact 404 observations before a recovery POST.

    A starter-message thread has the deterministic ID of its source message.
    Rechecking that exact ID protects against a delayed read after an accepted
    create whose response was lost. The probe count is deliberately bounded so
    a Discord outage fails instead of hanging the listener.
    """

    for attempt in range(RECOVERY_ABSENCE_PROBES):
        existing = _get_existing(
            token,
            channel_id=channel_id,
            message_id=message_id,
            name=name,
        )
        if existing is not None:
            return existing
        if attempt + 1 < RECOVERY_ABSENCE_PROBES:
            time.sleep(RECOVERY_PROBE_DELAY_SECONDS)
    return None


def _absent_result(channel_id: str, message_id: str) -> dict[str, str]:
    return {
        "outcome": "absent",
        "channel_id": channel_id,
        "thread_id": message_id,
    }


def _resolve_thread(
    request: dict[str, Any], token: str, *, name: str
) -> dict[str, Any]:
    channel_id = request["channel_id"]
    message_id = request["message_id"]
    operation = request["operation"]
    existing = _get_existing(
        token, channel_id=channel_id, message_id=message_id, name=name
    )
    if existing is not None:
        return existing

    if operation in {"reconcile", "recover"}:
        existing = _bounded_absence_probe(
            token,
            channel_id=channel_id,
            message_id=message_id,
            name=name,
        )
        if existing is not None:
            return existing
        if operation == "reconcile":
            return _absent_result(channel_id, message_id)

    try:
        created = _create_once(
            token,
            channel_id=channel_id,
            message_id=message_id,
            name=name,
            auto_archive=request["auto_archive"],
        )
        return _validate_thread(
            created, channel_id=channel_id, message_id=message_id, name=name
        )
    except Exception:
        reconciled = _get_existing(
            token,
            channel_id=channel_id,
            message_id=message_id,
            name=name,
        )
        if reconciled is None:
            raise
        return reconciled


def main() -> int:
    request = _read_request()
    channel_id = request["channel_id"]
    message_id = request["message_id"]
    name = _safe_name(request["name"])
    token = load_token()
    validate_principal(token)
    validate_owner_anchor(token, channel_id, message_id)

    result = _resolve_thread(request, token, name=name)
    if result.get("outcome") == "absent":
        output = result
    else:
        output = {
            "id": result["id"],
            "name": result["name"],
            "parent_id": result["parent_id"],
            "type": result["type"],
            "owner_id": result["owner_id"],
        }
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"thread helper failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
