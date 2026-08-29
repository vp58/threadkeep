"""Synchronous Discord REST calls without placing credentials in argv."""
from __future__ import annotations

import json
import http.client
import math
import mimetypes
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


API_ROOT = "https://discord.com/api/v10"
USER_AGENT = "Threadkeep/0.2"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail closed before urllib can forward a Discord credential."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def direct_urlopen(request: urllib.request.Request, *, timeout: float):
    """Open one Discord request without proxies or credentialed redirects."""

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirectHandler(),
    )
    return opener.open(request, timeout=timeout)


def require_direct_discord_transport() -> None:
    """Fail closed before a bot credential enters an ambient HTTP proxy."""

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


class DiscordHTTPError(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"Discord API returned HTTP {status}: {body[:300]}")
        self.status = status
        self.body = body


class DiscordPOSTAmbiguousError(RuntimeError):
    """A Discord POST may have committed and must not be retried blindly."""


def _retry_after(body: bytes) -> float | None:
    try:
        value = json.loads(body.decode("utf-8")).get("retry_after")
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        return None
    return float(value)


def request(
    method: str,
    path: str,
    token: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    timeout: float = 30,
    max_attempts: int = 4,
) -> tuple[int, bytes]:
    require_direct_discord_transport()
    method = method.upper()
    if (
        isinstance(max_attempts, bool)
        or not isinstance(max_attempts, int)
        or max_attempts < 1
    ):
        raise ValueError("max_attempts must be a positive integer")
    if method == "POST" and max_attempts != 1:
        raise ValueError(
            "Discord POST requests require max_attempts=1; "
            "the caller must reconcile or quarantine an ambiguous outcome"
        )
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("invalid Discord REST path")
    headers = {
        "Authorization": f"Bot {token}",
        "User-Agent": USER_AGENT,
    }
    if content_type:
        headers["Content-Type"] = content_type
    for attempt in range(max_attempts):
        req = urllib.request.Request(
            f"{API_ROOT}{path}", data=body, headers=headers, method=method
        )
        try:
            with direct_urlopen(req, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read()
            finally:
                exc.close()
            if method == "POST" and 500 <= exc.code < 600:
                raise DiscordPOSTAmbiguousError(
                    "Discord POST returned a server error; its outcome is unknown"
                ) from exc
            if exc.code == 429 and attempt + 1 < max_attempts:
                delay = _retry_after(payload)
                if delay is None:
                    raise DiscordHTTPError(exc.code, payload.decode("utf-8", "replace"))
                time.sleep(delay)
                continue
            if 500 <= exc.code < 600 and attempt + 1 < max_attempts:
                time.sleep(min(2**attempt, 8))
                continue
            raise DiscordHTTPError(
                exc.code, payload.decode("utf-8", errors="replace")
            ) from exc
        except (
            TimeoutError,
            urllib.error.URLError,
            OSError,
            http.client.HTTPException,
        ) as exc:
            if method == "POST":
                raise DiscordPOSTAmbiguousError(
                    "Discord POST transport failed; its outcome is unknown"
                ) from exc
            if attempt + 1 >= max_attempts:
                raise RuntimeError("Discord REST request failed") from exc
            time.sleep(min(2**attempt, 8))
    raise RuntimeError("Discord REST retry loop ended unexpectedly")


def json_request(
    method: str,
    path: str,
    token: str,
    payload: dict[str, Any] | None = None,
    *,
    timeout: float = 30,
    max_attempts: int = 4,
) -> dict[str, Any]:
    body = None
    content_type = None
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        content_type = "application/json"
    _, raw = request(
        method,
        path,
        token,
        body=body,
        content_type=content_type,
        timeout=timeout,
        max_attempts=max_attempts,
    )
    if not raw:
        if method.upper() == "POST":
            raise DiscordPOSTAmbiguousError(
                "Discord POST returned no JSON result; its outcome cannot be bound"
            )
        return {}
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        if method.upper() == "POST":
            raise DiscordPOSTAmbiguousError(
                "Discord POST returned invalid JSON; its outcome cannot be bound"
            ) from exc
        raise RuntimeError("Discord REST response is not JSON") from exc
    if not isinstance(value, dict):
        if method.upper() == "POST":
            raise DiscordPOSTAmbiguousError(
                "Discord POST returned a non-object result; its outcome cannot be bound"
            )
        raise RuntimeError("Discord REST response is not an object")
    return value


def multipart_message(payload: dict[str, Any], files: list[Path]) -> tuple[bytes, str]:
    boundary = "threadkeep-" + secrets.token_hex(24)
    chunks: list[bytes] = []

    def field(name: str, value: bytes, content_type: str | None = None, filename: str | None = None) -> None:
        chunks.append(f"--{boundary}\r\n".encode("ascii"))
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            safe_name = filename.replace('"', "_").replace("\r", "_").replace("\n", "_")
            disposition += f'; filename="{safe_name}"'
        chunks.append((disposition + "\r\n").encode("utf-8"))
        if content_type:
            chunks.append(f"Content-Type: {content_type}\r\n".encode("ascii"))
        chunks.append(b"\r\n")
        chunks.append(value)
        chunks.append(b"\r\n")

    field("payload_json", json.dumps(payload, separators=(",", ":")).encode("utf-8"), "application/json")
    total = 0
    for index, path in enumerate(files):
        resolved = path.expanduser()
        metadata = resolved.stat()
        if not resolved.is_file() or metadata.st_size > 25 * 1024 * 1024:
            raise RuntimeError("Discord attachment is not a regular file or is too large")
        total += metadata.st_size
        if total > 25 * 1024 * 1024:
            raise RuntimeError("Discord attachments exceed the 25 MiB request limit")
        field(
            f"files[{index}]",
            resolved.read_bytes(),
            mimetypes.guess_type(resolved.name)[0] or "application/octet-stream",
            resolved.name,
        )
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"
