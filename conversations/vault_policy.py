#!/usr/bin/env python3
"""Seal the canonical Vault P0 rules for unattended Threadkeep workers.

The snapshot is mechanically derived from the canonical Vault ``CLAUDE.md``.
Threadkeep never maintains a second prose copy of those rules.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


POLICY_SEAL_VERSION = 1
POLICY_SOURCE_FILENAME = "CLAUDE.md"
MAX_POLICY_SOURCE_BYTES = 512 * 1024
MAX_POLICY_SNAPSHOT_BYTES = 512 * 1024
EXPECTED_ROOT_HEADING = "# Vault Guide"
EXPECTED_P0_HEADINGS = (
    "## Most Critical Constraint (P0)",
    "## Hard Preview Boundary (P0)",
    "## Dash Repository Boundary (P0)",
    "## Discord Plugin Security (P0)",
    "## Tool Routing (P0)",
    "## P0 Hard Rules (one-line each, link to detail)",
)


@dataclass(frozen=True)
class VaultPolicySeal:
    version: int
    source_path: Path
    source_sha256: str
    snapshot_path: Path
    snapshot_sha256: str
    text: str

    def binding(self) -> dict[str, str | int]:
        return {
            "version": self.version,
            "source_path": str(self.source_path),
            "source_sha256": self.source_sha256,
            "snapshot_path": str(self.snapshot_path),
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass
class _OpenedFile:
    directory_fds: list[int]
    directory_metadata: list[os.stat_result]
    file_fd: int
    file_metadata: os.stat_result

    def close(self) -> None:
        os.close(self.file_fd)
        for descriptor in reversed(self.directory_fds):
            os.close(descriptor)


def _normalized_absolute(path: Path, label: str) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise RuntimeError(f"{label} must be an absolute path without traversal")
    return Path(os.path.normpath(os.fspath(path)))


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_directory(metadata: os.stat_result, label: str, *, private: bool) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"{label} must be a real directory")
    if private:
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeError(f"{label} must be current-user-owned with mode 700")
        return
    if metadata.st_uid not in {0, os.getuid()}:
        raise RuntimeError(f"{label} has an untrusted owner")
    mode = stat.S_IMODE(metadata.st_mode)
    root_sticky_boundary = (
        metadata.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o022)
    )
    if mode & 0o022 and not root_sticky_boundary:
        raise RuntimeError(f"{label} must not be group or world writable")


def _validate_file(
    metadata: os.stat_result,
    label: str,
    *,
    maximum: int,
    exact_mode: int | None,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
    ):
        raise RuntimeError(f"{label} metadata is unsafe")
    mode = stat.S_IMODE(metadata.st_mode)
    if exact_mode is not None:
        if mode != exact_mode:
            raise RuntimeError(f"{label} must have mode {exact_mode:o}")
    elif mode & 0o022:
        raise RuntimeError(f"{label} must not be group or world writable")


def _open_file(path: Path, label: str, *, maximum: int, exact_mode: int | None) -> _OpenedFile:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_only is None or os.open not in os.supports_dir_fd:
        raise RuntimeError("this platform cannot safely open the Vault policy")
    directory_flags = os.O_RDONLY | no_follow | directory_only
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NONBLOCK", 0)
    directories: list[int] = []
    directory_metadata: list[os.stat_result] = []
    file_fd: int | None = None
    try:
        root_fd = os.open(path.anchor, directory_flags)
        directories.append(root_fd)
        root_metadata = os.fstat(root_fd)
        _validate_directory(root_metadata, f"{label} root", private=False)
        directory_metadata.append(root_metadata)
        for component in path.parts[1:-1]:
            try:
                descriptor = os.open(component, directory_flags, dir_fd=directories[-1])
            except OSError as exc:
                raise RuntimeError(f"{label} ancestry contains a symlink or unsafe path") from exc
            directories.append(descriptor)
            metadata = os.fstat(descriptor)
            _validate_directory(metadata, f"{label} ancestry", private=False)
            directory_metadata.append(metadata)
        try:
            file_fd = os.open(path.name, file_flags, dir_fd=directories[-1])
        except OSError as exc:
            raise RuntimeError(f"{label} cannot be opened without following links") from exc
        file_metadata = os.fstat(file_fd)
        _validate_file(
            file_metadata,
            label,
            maximum=maximum,
            exact_mode=exact_mode,
        )
        return _OpenedFile(directories, directory_metadata, file_fd, file_metadata)
    except BaseException:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(directories):
            os.close(descriptor)
        raise


def _workspace_identity(workspace: Path | None) -> tuple[int, int] | None:
    if workspace is None:
        return None
    requested = _normalized_absolute(workspace, "worker workspace")
    try:
        canonical = requested.resolve(strict=True)
        metadata = canonical.stat()
    except OSError as exc:
        raise RuntimeError("worker workspace is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("worker workspace must be a directory")
    return metadata.st_dev, metadata.st_ino


def _read_stable_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    exact_mode: int | None = None,
    workspace: Path | None = None,
) -> tuple[Path, bytes]:
    lexical = _normalized_absolute(path, label)
    workspace_id = _workspace_identity(workspace)
    opened = _open_file(
        lexical,
        label,
        maximum=maximum,
        exact_mode=exact_mode,
    )
    try:
        if workspace_id is not None and any(
            (metadata.st_dev, metadata.st_ino) == workspace_id
            for metadata in opened.directory_metadata
        ):
            raise RuntimeError(f"{label} must not be inside the worker workspace")
        try:
            canonical = lexical.resolve(strict=True)
            canonical_metadata = canonical.stat()
        except OSError as exc:
            raise RuntimeError(f"{label} changed while being resolved") from exc
        if (canonical_metadata.st_dev, canonical_metadata.st_ino) != (
            opened.file_metadata.st_dev,
            opened.file_metadata.st_ino,
        ):
            raise RuntimeError(f"{label} changed while being resolved")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(opened.file_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(opened.file_fd)
        _validate_file(after, label, maximum=maximum, exact_mode=exact_mode)
        if (
            _file_identity(opened.file_metadata) != _file_identity(after)
            or len(payload) != after.st_size
        ):
            raise RuntimeError(f"{label} changed while being read")
        for descriptor, before in zip(
            opened.directory_fds, opened.directory_metadata, strict=True
        ):
            current = os.fstat(descriptor)
            _validate_directory(current, f"{label} ancestry", private=False)
            if _directory_identity(before) != _directory_identity(current):
                raise RuntimeError(f"{label} ancestry changed while being read")
        reopened = _open_file(
            lexical,
            label,
            maximum=maximum,
            exact_mode=exact_mode,
        )
        try:
            if (
                len(reopened.directory_metadata) != len(opened.directory_metadata)
                or any(
                    _directory_identity(first) != _directory_identity(second)
                    for first, second in zip(
                        opened.directory_metadata,
                        reopened.directory_metadata,
                        strict=True,
                    )
                )
                or _file_identity(after) != _file_identity(reopened.file_metadata)
            ):
                raise RuntimeError(f"{label} changed while being read")
        finally:
            reopened.close()
    finally:
        opened.close()
    if len(payload) > maximum:
        raise RuntimeError(f"{label} exceeds its size limit")
    return canonical, payload


def extract_p0_policy(source: str) -> str:
    """Extract every and only P0 section from the canonical heading schema."""

    if "\x00" in source:
        raise RuntimeError("canonical Vault policy contains a NUL byte")
    lines = source.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != EXPECTED_ROOT_HEADING:
        raise RuntimeError("canonical Vault policy root heading changed")
    headings: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        stripped = line.rstrip("\r\n")
        if stripped.startswith("## ") and not stripped.startswith("### "):
            headings.append((index, stripped))
    observed_p0 = tuple(
        heading
        for _, heading in headings
        if "(P0)" in heading or heading.startswith("## P0 ")
    )
    if observed_p0 != EXPECTED_P0_HEADINGS:
        raise RuntimeError("canonical Vault P0 heading schema changed")

    sections: list[str] = []
    for expected in EXPECTED_P0_HEADINGS:
        matches = [position for position, heading in headings if heading == expected]
        if len(matches) != 1:
            raise RuntimeError("canonical Vault P0 heading schema changed")
        start = matches[0]
        end = next(
            (position for position, _ in headings if position > start),
            len(lines),
        )
        section = "".join(lines[start:end]).strip()
        if section == expected:
            raise RuntimeError(f"canonical Vault P0 section is empty: {expected}")
        sections.append(section)
    return "\n\n".join(sections) + "\n"


def _snapshot_bytes(source_path: Path, source_sha256: str, policy_text: str) -> bytes:
    header = (
        "# Threadkeep Sealed Vault P0 Policy\n\n"
        "Generated mechanically from the canonical Vault source. Do not edit.\n\n"
        f"Seal version: {POLICY_SEAL_VERSION}\n"
        f"Source path: {source_path}\n"
        f"Source SHA-256: {source_sha256}\n\n"
    )
    payload = (header + policy_text).encode("utf-8")
    if len(payload) > MAX_POLICY_SNAPSHOT_BYTES:
        raise RuntimeError("sealed Vault P0 policy exceeds its size limit")
    return payload


def _open_private_directory(
    path: Path, *, runtime_root: Path, create: bool
) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_only is None or os.open not in os.supports_dir_fd:
        raise RuntimeError("this platform cannot safely create the policy snapshot")
    flags = os.O_RDONLY | no_follow | directory_only | getattr(os, "O_CLOEXEC", 0)
    requested = _normalized_absolute(path, "policy snapshot directory")
    root = _normalized_absolute(runtime_root, "policy runtime root")
    try:
        requested.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(
            "policy snapshot directory must stay under its private runtime root"
        ) from exc
    current_fd = os.open(requested.anchor, flags)
    try:
        _validate_directory(
            os.fstat(current_fd), "policy snapshot directory ancestry", private=False
        )
        root_depth = len(root.parts)
        for depth, component in enumerate(requested.parts[1:], start=2):
            is_private = depth >= root_depth
            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create or not is_private:
                    raise RuntimeError("policy snapshot directory is unavailable") from None
                os.mkdir(component, mode=0o700, dir_fd=current_fd)
                child_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
            _validate_directory(
                os.fstat(current_fd),
                "policy snapshot directory"
                if is_private
                else "policy snapshot directory ancestry",
                private=is_private,
            )
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _write_snapshot(snapshot_path: Path, payload: bytes, runtime_root: Path) -> None:
    snapshot = _normalized_absolute(snapshot_path, "policy snapshot")
    root = _normalized_absolute(runtime_root, "policy runtime root")
    try:
        snapshot.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("policy snapshot must stay under its private runtime root") from exc
    if snapshot == root or snapshot.parent == snapshot:
        raise RuntimeError("policy snapshot path is invalid")
    root_fd = _open_private_directory(root, runtime_root=root, create=False)
    os.close(root_fd)
    parent_fd = _open_private_directory(
        snapshot.parent, runtime_root=root, create=True
    )
    temporary_name = f".{snapshot.name}.{secrets.token_hex(16)}.tmp"
    temporary_fd: int | None = None
    try:
        try:
            existing = os.stat(snapshot.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            _validate_file(
                existing,
                "existing policy snapshot",
                maximum=MAX_POLICY_SNAPSHOT_BYTES,
                exact_mode=0o400,
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        temporary_fd = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        view = memoryview(payload)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                raise RuntimeError("could not write the sealed Vault policy")
            view = view[written:]
        os.fsync(temporary_fd)
        os.fchmod(temporary_fd, 0o400)
        os.close(temporary_fd)
        temporary_fd = None
        os.replace(
            temporary_name,
            snapshot.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _canonical_source(vault_root: Path) -> Path:
    root = _normalized_absolute(vault_root, "canonical Vault root")
    try:
        canonical = root.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("canonical Vault root is unavailable") from exc
    if canonical != root or not canonical.is_dir():
        raise RuntimeError("canonical Vault root must be a real, canonical directory")
    return canonical / POLICY_SOURCE_FILENAME


def _derive_policy(
    vault_root: Path, workspace: Path | None
) -> tuple[Path, str, bytes, str]:
    source_path, source_payload = _read_stable_file(
        _canonical_source(vault_root),
        "canonical Vault policy source",
        maximum=MAX_POLICY_SOURCE_BYTES,
        workspace=workspace,
    )
    try:
        source_text = source_payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("canonical Vault policy must be valid UTF-8") from exc
    policy_text = extract_p0_policy(source_text)
    source_sha256 = hashlib.sha256(source_payload).hexdigest()
    snapshot_payload = _snapshot_bytes(source_path, source_sha256, policy_text)
    return source_path, source_sha256, snapshot_payload, snapshot_payload.decode("utf-8")


def seal_vault_policy(
    *,
    vault_root: Path,
    snapshot_path: Path,
    runtime_root: Path,
    workspace: Path | None = None,
) -> VaultPolicySeal:
    source_path, source_sha256, snapshot_payload, snapshot_text = _derive_policy(
        vault_root, workspace
    )
    _write_snapshot(snapshot_path, snapshot_payload, runtime_root)
    canonical_snapshot, observed_snapshot = _read_stable_file(
        snapshot_path,
        "sealed Vault policy snapshot",
        maximum=MAX_POLICY_SNAPSHOT_BYTES,
        exact_mode=0o400,
        workspace=workspace,
    )
    if observed_snapshot != snapshot_payload:
        raise RuntimeError("sealed Vault policy snapshot does not match its source")
    return VaultPolicySeal(
        version=POLICY_SEAL_VERSION,
        source_path=source_path,
        source_sha256=source_sha256,
        snapshot_path=canonical_snapshot,
        snapshot_sha256=hashlib.sha256(snapshot_payload).hexdigest(),
        text=snapshot_text,
    )


def validate_vault_policy_seal(
    seal: VaultPolicySeal,
    *,
    vault_root: Path,
    runtime_root: Path,
    workspace: Path | None = None,
) -> str:
    if seal.version != POLICY_SEAL_VERSION:
        raise RuntimeError("sealed Vault policy version changed")
    source_path, source_sha256, expected_payload, expected_text = _derive_policy(
        vault_root, workspace
    )
    canonical_snapshot, observed_payload = _read_stable_file(
        seal.snapshot_path,
        "sealed Vault policy snapshot",
        maximum=MAX_POLICY_SNAPSHOT_BYTES,
        exact_mode=0o400,
        workspace=workspace,
    )
    root = _normalized_absolute(runtime_root, "policy runtime root")
    try:
        canonical_snapshot.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "sealed Vault policy snapshot left its private runtime root"
        ) from exc
    expected_binding = {
        "version": POLICY_SEAL_VERSION,
        "source_path": str(source_path),
        "source_sha256": source_sha256,
        "snapshot_path": str(canonical_snapshot),
        "snapshot_sha256": hashlib.sha256(expected_payload).hexdigest(),
    }
    if (
        expected_binding != seal.binding()
        or observed_payload != expected_payload
        or expected_text != seal.text
    ):
        raise RuntimeError("canonical Vault policy changed after policy binding")
    return expected_text


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Seal canonical Vault P0 policy")
    parser.add_argument("--vault-root", required=True, type=Path)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--workspace", type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    seal = seal_vault_policy(
        vault_root=args.vault_root,
        snapshot_path=args.snapshot,
        runtime_root=args.runtime_root,
        workspace=args.workspace,
    )
    print(json.dumps(seal.binding(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
