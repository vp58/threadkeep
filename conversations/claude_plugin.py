#!/usr/bin/env python3
"""Fail closed unless the installed Claude Discord plugin is reviewed."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import shlex
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

import bun_runtime


PLUGIN_ID = "discord@claude-plugins-official"
PLUGIN_VERSION = "0.0.4"
MAX_RUNTIME_ENTRIES = 10_000
MAX_RUNTIME_BYTES = 128 * 1024 * 1024

# Anthropic published two source revisions under the same 0.0.4 manifest.
# Both revisions were reviewed. The commit and server digest must match as a
# pair so a future in-place marketplace update cannot silently cross this
# ingress security boundary.
REVIEWED_SERVER_REVISIONS = {
    "da61886c07a4773f647b6b277e4efdfb436728cc":
        "f634be3115c873b6181960de014181d01e28c2be556e0d41736733a941f5d451",
    "ed404106fcd80ba98ecb7c851e531dcb626d13b7":
        "6edc17d9e9d04930967361ba51c8e03b8f8508647a1dfc11d79ee6a0eb1010b7",
}

REVIEWED_FILES = {
    ".claude-plugin/plugin.json":
        "3e559b00317540f96fe3b24aee4a816af8b43d648f6e1dd9896e59aa835cd3d8",
    ".mcp.json":
        "01c15597e40a5999d7b1c15bd6f9656abc8a04d3a0956704a9dfd2df01b74960",
    ".npmrc":
        "3a951f66e7e0f3e2dd1832473a871357c4a507b51100636b73bcf6ff0dd78b6c",
    "ACCESS.md":
        "73a4078a35ab2d3feb5c27f53437acc4fe6c1a2040e58f6f52d3c0791bfdaa89",
    "LICENSE":
        "dfd016a63459229ceb791be757c3bede084fb22303c36b61342db1b8f58cc450",
    "README.md":
        "328fdbda672da357bb424d396b37fc60f2d6d4f24036ab80485f5c8ec8b3070a",
    "bun.lock":
        "c3d69584e51e46a758bd9c8a8bfef12b46fe9f2bb57a367f4deb073edd26c55e",
    "package.json":
        "fa2ece9108aca2ae17e7b1909f468ee8f055e53a45882eb25108a3e394f17e46",
    "skills/access/SKILL.md":
        "4fc3da872e033c37576a904b15a1bcac6b1ce6c7bc43f1f96abd7cad4855ac7a",
    "skills/configure/SKILL.md":
        "9364d7895d6f38b917a711128e7b391884fb8b8d69a62c7d72a81e95b6e2b948",
}

# Deterministic manifest digest of every regular file, directory, and symlink
# under node_modules for the reviewed M5 installation. The digest is checked
# before copying and again before every listener launch.
REVIEWED_NODE_MODULES_DIGEST = (
    "601a2e9699770e4e753c333c5e60b229407204888fd613b82279f0f226875014"
)
RUNTIME_LAYOUT_VERSION = 1


def _manifest_record(digest: Any, kind: bytes, relative: str, payload: bytes = b"") -> None:
    encoded = relative.encode("utf-8")
    digest.update(kind)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


def _safe_tree_directory(metadata: os.stat_result, relative: str) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError(f"unsafe Claude plugin dependency directory: {relative}")


def dependency_manifest(
    root: Path,
    *,
    require_private: bool = False,
    require_single_link: bool = False,
) -> dict[str, Any]:
    """Hash a stable, bounded, non-following manifest of node_modules."""

    root = Path(os.path.abspath(root.expanduser()))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        root_descriptor = os.open(root, flags)
    except OSError as exc:
        raise RuntimeError("Claude plugin dependency tree cannot be opened safely") from exc
    manifest = hashlib.sha256()
    counters = {"directories": 0, "files": 0, "symlinks": 0, "bytes": 0}

    def walk(descriptor: int, relative_parent: str) -> None:
        before_directory = os.fstat(descriptor)
        _safe_tree_directory(before_directory, relative_parent or ".")
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as exc:
            raise RuntimeError("Claude plugin dependency tree cannot be listed") from exc
        for name in names:
            if not name or "/" in name or "\x00" in name:
                raise RuntimeError("Claude plugin dependency tree has a malformed name")
            relative = f"{relative_parent}/{name}" if relative_parent else name
            if sum(counters[key] for key in ("directories", "files", "symlinks")) >= MAX_RUNTIME_ENTRIES:
                raise RuntimeError("Claude plugin dependency tree has too many entries")
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(f"Claude plugin dependency cannot be inspected: {relative}") from exc
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise RuntimeError(f"Claude plugin dependency changed: {relative}")
                    _safe_tree_directory(opened, relative)
                    counters["directories"] += 1
                    _manifest_record(manifest, b"D", relative)
                    walk(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                if (
                    metadata.st_uid != os.getuid()
                    or (require_single_link and metadata.st_nlink != 1)
                    or (
                        require_private
                        and stat.S_IMODE(metadata.st_mode) & 0o022
                    )
                ):
                    raise RuntimeError(f"unsafe Claude plugin dependency file: {relative}")
                file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                file_flags |= getattr(os, "O_NOFOLLOW", 0)
                file_descriptor = os.open(name, file_flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(file_descriptor)
                    identity = (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_size,
                        opened.st_mtime_ns,
                        opened.st_ctime_ns,
                    )
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise RuntimeError(f"Claude plugin dependency changed: {relative}")
                    file_digest = hashlib.sha256()
                    total = 0
                    while chunk := os.read(file_descriptor, 1024 * 1024):
                        file_digest.update(chunk)
                        total += len(chunk)
                        if counters["bytes"] + total > MAX_RUNTIME_BYTES:
                            raise RuntimeError("Claude plugin dependency tree is too large")
                    after = os.fstat(file_descriptor)
                    after_identity = (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    )
                    if identity != after_identity or total != opened.st_size:
                        raise RuntimeError(f"Claude plugin dependency changed: {relative}")
                    counters["files"] += 1
                    counters["bytes"] += total
                    payload = total.to_bytes(8, "big") + file_digest.digest()
                    _manifest_record(manifest, b"F", relative, payload)
                finally:
                    os.close(file_descriptor)
            elif stat.S_ISLNK(metadata.st_mode):
                if metadata.st_uid != os.getuid():
                    raise RuntimeError(f"unsafe Claude plugin dependency symlink: {relative}")
                target = os.readlink(name, dir_fd=descriptor)
                normalized = posixpath.normpath(posixpath.join(relative_parent, target))
                if target.startswith("/") or normalized == ".." or normalized.startswith("../"):
                    raise RuntimeError(f"Claude plugin dependency symlink escapes the tree: {relative}")
                after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (
                    after.st_dev,
                    after.st_ino,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ) != (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                ):
                    raise RuntimeError(f"Claude plugin dependency changed: {relative}")
                counters["symlinks"] += 1
                _manifest_record(manifest, b"L", relative, target.encode("utf-8"))
            else:
                raise RuntimeError(f"unsupported Claude plugin dependency: {relative}")
        after_directory = os.fstat(descriptor)
        if (
            before_directory.st_dev,
            before_directory.st_ino,
            before_directory.st_mtime_ns,
            before_directory.st_ctime_ns,
        ) != (
            after_directory.st_dev,
            after_directory.st_ino,
            after_directory.st_mtime_ns,
            after_directory.st_ctime_ns,
        ):
            raise RuntimeError("Claude plugin dependency directory changed during verification")

    try:
        walk(root_descriptor, "")
    finally:
        os.close(root_descriptor)
    return {"sha256": manifest.hexdigest(), **counters}


def _read_regular(path: Path, *, maximum: int = 8_000_000) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > maximum
        ):
            raise RuntimeError(f"unsafe Claude plugin file: {path.name}")
        content = bytearray()
        while chunk := os.read(descriptor, min(65_536, maximum + 1 - len(content))):
            content.extend(chunk)
            if len(content) > maximum:
                raise RuntimeError(f"Claude plugin file is too large: {path.name}")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or after.st_nlink != 1
        ):
            raise RuntimeError(f"Claude plugin file changed while reading: {path.name}")
        return bytes(content)
    finally:
        os.close(descriptor)


def _safe_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError(f"unsafe Claude plugin directory: {path}")


def _object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} is not a JSON object")
    return value


def verify(*, home: Path | None = None) -> Path:
    root = (home or Path.home()).expanduser().resolve()
    registry = root / ".claude" / "plugins" / "installed_plugins.json"
    installed = _object(_read_regular(registry), "Claude plugin registry")
    records = installed.get("plugins", {}).get(PLUGIN_ID)
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise RuntimeError("exactly one user-scoped official Discord plugin is required")
    record = records[0]
    if record.get("scope") != "user" or record.get("version") != PLUGIN_VERSION:
        raise RuntimeError(f"Claude Discord plugin must be user-scoped version {PLUGIN_VERSION}")

    expected_root = (
        root
        / ".claude"
        / "plugins"
        / "cache"
        / "claude-plugins-official"
        / "discord"
        / PLUGIN_VERSION
    )
    configured = Path(str(record.get("installPath") or "")).expanduser()
    if configured != expected_root or configured.resolve(strict=True) != expected_root:
        raise RuntimeError("Claude Discord plugin install path is not canonical")
    current = root
    for component in expected_root.relative_to(root).parts:
        current /= component
        _safe_directory(current)

    commit = str(record.get("gitCommitSha") or "")
    expected_server = REVIEWED_SERVER_REVISIONS.get(commit)
    if expected_server is None:
        raise RuntimeError("Claude Discord plugin source commit has not been reviewed")

    manifest = _object(
        _read_regular(expected_root / ".claude-plugin" / "plugin.json"),
        "Claude Discord plugin manifest",
    )
    if manifest.get("name") != "discord" or manifest.get("version") != PLUGIN_VERSION:
        raise RuntimeError("Claude Discord plugin manifest identity does not match")

    expected = dict(REVIEWED_FILES)
    expected["server.ts"] = expected_server
    for relative, digest in expected.items():
        actual = hashlib.sha256(_read_regular(expected_root / relative)).hexdigest()
        if actual != digest:
            raise RuntimeError(f"Claude Discord plugin digest mismatch: {relative}")

    node_modules = expected_root / "node_modules"
    _safe_directory(node_modules)
    dependencies = dependency_manifest(node_modules)
    if dependencies["sha256"] != REVIEWED_NODE_MODULES_DIGEST:
        raise RuntimeError("Claude Discord plugin dependency manifest is not reviewed")
    return expected_root


def _runtime_root(home: Path, dependency_digest: str) -> Path:
    identity = (
        f"v{RUNTIME_LAYOUT_VERSION}-{PLUGIN_VERSION}-"
        f"bun-{bun_runtime.EXPECTED_VERSION}-{dependency_digest[:16]}"
    )
    return home / ".local/share/threadkeep/claude-discord-runtime" / identity


def _wrapper_bytes(source: Path, runtime: Path, bun: Path) -> bytes:
    expected = ("run", "--cwd", str(source), "--shell=bun", "--silent", "start")
    checks = "\n".join(
        f'[ "${{{index}}}" = {shlex.quote(value)} ] || exit 64'
        for index, value in enumerate(expected, start=1)
    )
    script = f"""#!/bin/sh
set -eu
if [ "${{1:-}}" = run ] && [ "${{2:-}}" = --cwd ] && [ "${{3:-}}" = {shlex.quote(str(source))} ]; then
[ "$#" -eq 6 ] || exit 64
{checks}
cd {shlex.quote(str(runtime))}
exec {shlex.quote(str(bun))} --no-install {shlex.quote(str(runtime / 'server.ts'))}
fi
exec {shlex.quote(str(bun))} "$@"
"""
    return script.encode("utf-8")


def _safe_runtime_root(runtime: Path) -> None:
    expected_entries = {"bin", "node_modules", "server.ts"}
    try:
        actual_entries = set(os.listdir(runtime))
    except OSError as exc:
        raise RuntimeError("Claude Discord private runtime is unavailable") from exc
    if actual_entries != expected_entries:
        raise RuntimeError("Claude Discord private runtime has unexpected entries")
    _safe_directory(runtime)
    _safe_directory(runtime / "bin")
    _safe_directory(runtime / "node_modules")


def verify_runtime(
    *, home: Path | None = None, bun_path: Path = bun_runtime.DEFAULT_PATH
) -> Path:
    """Verify the offline private MCP runtime used for every listener start."""

    root = (home or Path.home()).expanduser().resolve()
    source = verify(home=root)
    bun = Path(bun_runtime.verify(bun_path)["canonical_path"])
    runtime = _runtime_root(root, REVIEWED_NODE_MODULES_DIGEST)
    _safe_runtime_root(runtime)
    server_digest = REVIEWED_SERVER_REVISIONS[
        _object(
            _read_regular(root / ".claude/plugins/installed_plugins.json"),
            "Claude plugin registry",
        )["plugins"][PLUGIN_ID][0]["gitCommitSha"]
    ]
    if hashlib.sha256(_read_regular(runtime / "server.ts")).hexdigest() != server_digest:
        raise RuntimeError("Claude Discord private runtime server digest mismatch")
    wrapper = runtime / "bin" / "bun"
    if stat.S_IMODE(wrapper.lstat().st_mode) != 0o500:
        raise RuntimeError("Claude Discord private runtime wrapper mode must be 0500")
    if _read_regular(wrapper) != _wrapper_bytes(source, runtime, bun):
        raise RuntimeError("Claude Discord private runtime wrapper is not reviewed")
    dependencies = dependency_manifest(
        runtime / "node_modules",
        require_private=True,
        require_single_link=True,
    )
    if dependencies["sha256"] != REVIEWED_NODE_MODULES_DIGEST:
        raise RuntimeError("Claude Discord private dependency manifest is not reviewed")
    return runtime


def _make_private_parent(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError("Claude Discord runtime parent is unsafe")
    os.chmod(path, 0o700, follow_symlinks=False)


def _harden_runtime_tree(runtime: Path) -> None:
    for current, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        directory = Path(current)
        for name in files:
            path = directory / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise RuntimeError("Claude Discord runtime copy contains an unsafe file")
            os.chmod(path, 0o400, follow_symlinks=False)
        for name in directories:
            path = directory / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise RuntimeError("Claude Discord runtime copy contains an unsafe directory")
            os.chmod(path, 0o500, follow_symlinks=False)
    os.chmod(runtime / "bin" / "bun", 0o500, follow_symlinks=False)
    os.chmod(runtime, 0o500, follow_symlinks=False)


def install_runtime(
    *, home: Path | None = None, bun_path: Path = bun_runtime.DEFAULT_PATH
) -> Path:
    """Create a versioned offline copy without running package installers."""

    root = (home or Path.home()).expanduser().resolve()
    source = verify(home=root)
    bun = Path(bun_runtime.verify(bun_path)["canonical_path"])
    parent = _runtime_root(root, REVIEWED_NODE_MODULES_DIGEST).parent
    runtime = _runtime_root(root, REVIEWED_NODE_MODULES_DIGEST)
    _make_private_parent(parent)
    if runtime.exists() or runtime.is_symlink():
        return verify_runtime(home=root, bun_path=bun_path)
    staging = Path(tempfile.mkdtemp(prefix=".install-", dir=parent))
    try:
        shutil.copy2(source / "server.ts", staging / "server.ts", follow_symlinks=False)
        shutil.copytree(
            source / "node_modules",
            staging / "node_modules",
            symlinks=True,
            copy_function=shutil.copyfile,
        )
        (staging / "bin").mkdir(mode=0o700)
        (staging / "bin" / "bun").write_bytes(_wrapper_bytes(source, runtime, bun))
        _harden_runtime_tree(staging)
        copied = dependency_manifest(
            staging / "node_modules",
            require_private=True,
            require_single_link=True,
        )
        if copied["sha256"] != REVIEWED_NODE_MODULES_DIGEST:
            raise RuntimeError("Claude Discord dependency copy changed during installation")
        os.rename(staging, runtime)
    except Exception:
        if staging.exists():
            for current, directories, files in os.walk(staging, topdown=False):
                for name in files:
                    path = Path(current) / name
                    if not path.is_symlink():
                        os.chmod(path, 0o600, follow_symlinks=False)
                for name in directories:
                    path = Path(current) / name
                    if not path.is_symlink():
                        os.chmod(path, 0o700, follow_symlinks=False)
            os.chmod(staging, 0o700, follow_symlinks=False)
            shutil.rmtree(staging)
        raise
    return verify_runtime(home=root, bun_path=bun_path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=("verify", "install-runtime", "verify-runtime", "runtime-bin")
    )
    args = parser.parse_args()
    if args.command == "verify":
        path = verify()
        print(json.dumps({"ok": True, "path": str(path), "version": PLUGIN_VERSION}))
    elif args.command == "install-runtime":
        path = install_runtime()
        print(json.dumps({"ok": True, "runtime": str(path)}))
    elif args.command == "verify-runtime":
        path = verify_runtime()
        print(json.dumps({"ok": True, "runtime": str(path)}))
    elif args.command == "runtime-bin":
        print(verify_runtime() / "bin")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
