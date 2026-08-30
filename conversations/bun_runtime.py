#!/usr/bin/env python3
"""Fail-closed verification of the reviewed Apple Silicon Bun runtime."""
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


EXPECTED_VERSION = "1.3.12"
EXPECTED_SHA256 = "39e644cea4e6db24a3af36013695655d6f789b4b98f1f13bacb882ac6e5c3c18"
EXPECTED_TEAM_ID = "7FRXF46ZSN"
EXPECTED_IDENTIFIER = "bun"
EXPECTED_AUTHORITY = "Developer ID Application: Jarred Sumner (7FRXF46ZSN)"
DEFAULT_PATH = Path("/opt/homebrew/bin/bun")
EXPECTED_CANONICAL_PATH = Path("/opt/homebrew/Cellar/bun/1.3.12/bin/bun")


def _clean_environment() -> dict[str, str]:
    return {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LANG": "C"}


def _stable_sha256(path: Path) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("reviewed Bun runtime cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("reviewed Bun runtime is not a regular file")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or total != before.st_size:
            raise RuntimeError("reviewed Bun runtime changed while it was verified")
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
        raise RuntimeError("Bun code signature verification failed")
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
        raise RuntimeError("Bun code signature details are unavailable")
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
        raise RuntimeError("Bun version probe failed")
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
        raise RuntimeError("Bun architecture probe failed")
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
    """Verify one exact official Bun build without modifying local state."""

    if (machine or platform.machine()) != "arm64":
        raise RuntimeError("reviewed Bun runtime requires Apple Silicon arm64")
    path = Path(os.path.abspath(path.expanduser()))
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("reviewed Bun runtime path cannot be resolved") from exc
    if canonical != expected_canonical_path.expanduser().resolve(strict=False):
        raise RuntimeError("Bun resolved outside the reviewed version path")
    digest, metadata = _stable_sha256(canonical)
    if metadata.st_uid != os.getuid():
        raise RuntimeError("Bun is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise RuntimeError("Bun is writable by another user")
    if digest != expected_sha256:
        raise RuntimeError("Bun SHA-256 does not match the reviewed build")
    architecture = architecture_inspector(canonical)
    if not re.search(r"\bMach-O 64-bit executable arm64\b", architecture):
        raise RuntimeError("Bun is not a native arm64 Mach-O executable")
    signature = signature_inspector(canonical)
    if signature.get("Identifier") != EXPECTED_IDENTIFIER:
        raise RuntimeError("Bun has an unexpected signing identifier")
    if signature.get("TeamIdentifier") != EXPECTED_TEAM_ID:
        raise RuntimeError("Bun has an unexpected signing team")
    if signature.get("Authority") != EXPECTED_AUTHORITY:
        raise RuntimeError("Bun has an unexpected signing authority")
    version = version_inspector(canonical)
    if version != EXPECTED_VERSION:
        raise RuntimeError("Bun version does not match the reviewed build")
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
    print(json.dumps(verify(args.path), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
