"""Fail-closed verification of the reviewed Apple Silicon Claude CLI build."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any


EXPECTED_VERSION = "2.1.251 (Claude Code)"
EXPECTED_SHA256 = "625869b01e0050f260b2980fac248fd9cef9e462612bded4ec9d3d49ff8969a5"
EXPECTED_TEAM_ID = "Q6L2SF6YDW"
EXPECTED_IDENTIFIER = "com.anthropic.claude-code"
EXPECTED_AUTHORITY = "Developer ID Application: Anthropic PBC (Q6L2SF6YDW)"
DEFAULT_PATH = Path("/opt/homebrew/bin/claude")
EXPECTED_CANONICAL_PATH = (
    Path.home() / ".local/share/claude/versions/2.1.251"
)


def _clean_environment() -> dict[str, str]:
    return {
        "HOME": str(Path.home()),
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
    }


def _stable_sha256(path: Path) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("reviewed Claude CLI cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("reviewed Claude CLI is not a regular file")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or total != before.st_size
        ):
            raise RuntimeError("reviewed Claude CLI changed while it was verified")
        return digest.hexdigest(), after
    finally:
        os.close(descriptor)


def _signature(path: Path) -> dict[str, str]:
    environment = _clean_environment()
    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=environment,
        start_new_session=True,
    )
    if verified.returncode != 0:
        raise RuntimeError("Claude CLI code signature verification failed")
    details = subprocess.run(
        ["/usr/bin/codesign", "-dv", "--verbose=4", str(path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=environment,
        start_new_session=True,
    )
    if details.returncode != 0:
        raise RuntimeError("Claude CLI code signature details are unavailable")
    values: dict[str, str] = {}
    authorities: list[str] = []
    for line in (details.stdout + "\n" + details.stderr).splitlines():
        if line.startswith("Authority="):
            authorities.append(line.split("=", 1)[1])
        elif "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    values["Authority"] = authorities[0] if authorities else ""
    return values


def _version(path: Path) -> str:
    result = subprocess.run(
        [str(path), "--version"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env=_clean_environment(),
        start_new_session=True,
    )
    if result.returncode != 0 or result.stderr.strip():
        raise RuntimeError("Claude CLI version probe failed")
    return result.stdout.strip()


def _architecture(path: Path) -> str:
    result = subprocess.run(
        ["/usr/bin/file", "-b", str(path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env=_clean_environment(),
        start_new_session=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Claude CLI architecture probe failed")
    return result.stdout.strip()


def verify(
    path: Path = DEFAULT_PATH,
    *,
    expected_canonical_path: Path = EXPECTED_CANONICAL_PATH,
    expected_sha256: str = EXPECTED_SHA256,
    signature_inspector: Callable[[Path], dict[str, str]] = _signature,
    version_inspector: Callable[[Path], str] = _version,
    architecture_inspector: Callable[[Path], str] = _architecture,
    machine: str | None = None,
) -> dict[str, Any]:
    """Verify one exact official arm64 build without modifying local state."""

    if (machine or platform.machine()) != "arm64":
        raise RuntimeError("reviewed Claude CLI requires Apple Silicon arm64")
    path = Path(os.path.abspath(path.expanduser()))
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("reviewed Claude CLI path cannot be resolved") from exc
    if canonical != expected_canonical_path.expanduser().resolve(strict=False):
        raise RuntimeError("Claude CLI resolved outside the reviewed version path")
    digest, metadata = _stable_sha256(canonical)
    if metadata.st_uid != os.getuid():
        raise RuntimeError("Claude CLI is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise RuntimeError("Claude CLI is writable by another user")
    if digest != expected_sha256:
        raise RuntimeError("Claude CLI SHA-256 does not match the reviewed build")
    architecture = architecture_inspector(canonical)
    if not re.search(r"\bMach-O 64-bit executable arm64\b", architecture):
        raise RuntimeError("Claude CLI is not a native arm64 Mach-O executable")
    signature = signature_inspector(canonical)
    if signature.get("Identifier") != EXPECTED_IDENTIFIER:
        raise RuntimeError("Claude CLI has an unexpected signing identifier")
    if signature.get("TeamIdentifier") != EXPECTED_TEAM_ID:
        raise RuntimeError("Claude CLI has an unexpected signing team")
    if signature.get("Authority") != EXPECTED_AUTHORITY:
        raise RuntimeError("Claude CLI has an unexpected signing authority")
    version = version_inspector(canonical)
    if version != EXPECTED_VERSION:
        raise RuntimeError("Claude CLI version does not match the reviewed build")
    return {
        "architecture": "arm64",
        "canonical_path": str(canonical),
        "identifier": EXPECTED_IDENTIFIER,
        "sha256": digest,
        "team_identifier": EXPECTED_TEAM_ID,
        "version": version,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--path", type=Path, default=DEFAULT_PATH)
    args = parser.parse_args()
    if args.command != "verify":
        raise RuntimeError("unsupported Claude CLI command")
    print(json.dumps(verify(args.path), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
