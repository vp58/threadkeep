#!/usr/bin/env python3
"""Verify the one explicitly trusted shared Vault skill source."""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any


MAX_SETTINGS_BYTES = 1024 * 1024
REQUIRED_SKILLS = (
    Path("eli5/SKILL.md"),
    Path("marketing/websites/vinaytalks/SKILL.md"),
)


def _safe_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be inspected") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError(f"{label} must be a current-user-owned safe directory")


def _stable_file(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > MAX_SETTINGS_BYTES
        ):
            raise RuntimeError(f"{label} metadata is unsafe")
        content = bytearray()
        while chunk := os.read(descriptor, 65_536):
            content.extend(chunk)
            if len(content) > MAX_SETTINGS_BYTES:
                raise RuntimeError(f"{label} is too large")
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
        if before_identity != after_identity or len(content) != before.st_size:
            raise RuntimeError(f"{label} changed during verification")
        return bytes(content)
    finally:
        os.close(descriptor)


def _stable_relative_file(root: Path, relative: Path, label: str) -> bytes:
    current = root
    for component in relative.parts[:-1]:
        if component in {"", ".", ".."}:
            raise RuntimeError(f"{label} has an unsafe relative path")
        current /= component
        _safe_directory(current, f"{label} parent")
    return _stable_file(current / relative.name, label)


def _settings_are_inert(settings_path: Path) -> None:
    if not settings_path.exists() and not settings_path.is_symlink():
        return
    raw = _stable_file(settings_path, "shared Vault .claude/settings.json")
    try:
        settings = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("shared Vault settings are not valid UTF-8 JSON") from exc
    if not isinstance(settings, dict):
        raise RuntimeError("shared Vault settings must be a JSON object")
    plugins = settings.get("enabledPlugins", {})
    if not isinstance(plugins, dict) or any(value is not False for value in plugins.values()):
        raise RuntimeError("shared Vault must not enable additional Claude plugins")
    marketplaces = settings.get("extraKnownMarketplaces", {})
    if marketplaces not in ({}, None):
        raise RuntimeError("shared Vault must not add Claude plugin marketplaces")


def verify(root: Path) -> dict[str, Any]:
    """Bind skill discovery to one canonical, current-user-owned Vault root."""

    requested = Path(os.path.abspath(root.expanduser()))
    try:
        canonical = requested.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("shared Vault root cannot be resolved") from exc
    if requested != canonical:
        raise RuntimeError("shared Vault root must be canonical and not a symlink")
    claude_dir = canonical / ".claude"
    skills_link = claude_dir / "skills"
    skills_root = canonical / "x_System" / "Skills"
    for path, label in (
        (canonical, "shared Vault root"),
        (claude_dir, "shared Vault .claude directory"),
        (canonical / "x_System", "shared Vault x_System directory"),
        (skills_root, "shared Vault skill directory"),
    ):
        _safe_directory(path, label)
    try:
        link_metadata = skills_link.lstat()
    except OSError as exc:
        raise RuntimeError("shared Vault .claude/skills link is missing") from exc
    if (
        not stat.S_ISLNK(link_metadata.st_mode)
        or link_metadata.st_uid != os.getuid()
        or link_metadata.st_nlink != 1
    ):
        raise RuntimeError("shared Vault .claude/skills must be a current-user symlink")
    if skills_link.resolve(strict=True) != skills_root:
        raise RuntimeError("shared Vault .claude/skills points outside the canonical skill root")
    _settings_are_inert(claude_dir / "settings.json")
    for relative in REQUIRED_SKILLS:
        content = _stable_relative_file(
            skills_root, relative, f"required shared skill {relative}"
        )
        if not content.startswith(b"---\n"):
            raise RuntimeError(f"required shared skill {relative} lacks frontmatter")
    return {
        "root": str(canonical),
        "skills_root": str(skills_root),
        "required_skills": [str(path) for path in REQUIRED_SKILLS],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
