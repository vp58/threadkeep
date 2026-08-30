from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path


MAX_TRUSTED_INSTRUCTIONS_BYTES = 256_000


@dataclass(frozen=True)
class TrustedInstructions:
    text: str
    sha256: str
    canonical_path: Path


@dataclass(frozen=True)
class _WorkspaceBoundary:
    paths: tuple[Path, Path]
    device: int
    inode: int


@dataclass
class _OpenedTrustedPath:
    directory_fds: list[int]
    directory_metadata: list[os.stat_result]
    file_fd: int
    file_metadata: os.stat_result

    def close(self) -> None:
        os.close(self.file_fd)
        for descriptor in reversed(self.directory_fds):
            os.close(descriptor)


def _normalized_absolute(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise RuntimeError(f"configured Codex {label} must be an absolute path")
    if ".." in path.parts:
        raise RuntimeError(
            f"configured Codex {label} must not contain traversal components"
        )
    return Path(os.path.normpath(os.fspath(path)))


def _paths_overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first.is_relative_to(second)
        or second.is_relative_to(first)
    )


def _workspace_paths(workspace: Path | None) -> _WorkspaceBoundary | None:
    if workspace is None:
        return None
    lexical = _normalized_absolute(workspace, "working_directory")
    try:
        canonical = lexical.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("configured Codex working_directory is unavailable") from exc
    try:
        metadata = canonical.stat()
    except OSError as exc:
        raise RuntimeError("configured Codex working_directory is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("configured Codex working_directory is not a directory")
    return _WorkspaceBoundary(
        paths=(lexical, canonical),
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def _reject_workspace_overlap(
    instructions_path: Path,
    workspace: _WorkspaceBoundary | None,
    *,
    path_kind: str,
) -> None:
    if workspace is None:
        return
    if any(
        _paths_overlap(instructions_path, workspace_path)
        for workspace_path in workspace.paths
    ):
        raise RuntimeError(
            f"trusted Codex instructions file must not {path_kind} overlap "
            "the Codex working_directory"
        )


def _reject_workspace_identity_overlap(
    opened: _OpenedTrustedPath, workspace: _WorkspaceBoundary | None
) -> None:
    if workspace is None:
        return
    workspace_identity = (workspace.device, workspace.inode)
    if any(
        (metadata.st_dev, metadata.st_ino) == workspace_identity
        for metadata in opened.directory_metadata
    ):
        raise RuntimeError(
            "trusted Codex instructions file must not overlap the Codex "
            "working_directory through a filesystem alias"
        )


def _validate_trusted_directory(metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(
            "configured Codex instructions path components must be real directories"
        )
    if metadata.st_uid not in {0, os.getuid()}:
        raise RuntimeError(
            "configured Codex instructions ancestry must be owned by root or "
            "the current user"
        )
    mode = stat.S_IMODE(metadata.st_mode)
    root_sticky_boundary = (
        metadata.st_uid == 0
        and bool(mode & stat.S_ISVTX)
        and bool(mode & 0o022)
    )
    if mode & 0o022 and not root_sticky_boundary:
        raise RuntimeError(
            "configured Codex instructions ancestry must not be group or world writable"
        )


def _validate_trusted_file(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("configured Codex instructions file is not regular")
    if metadata.st_uid != os.getuid():
        raise RuntimeError(
            "configured Codex instructions file must be owned by the current user"
        )
    if metadata.st_mode & 0o022:
        raise RuntimeError(
            "configured Codex instructions file must not be group or world writable"
        )
    if metadata.st_nlink != 1:
        raise RuntimeError(
            "configured Codex instructions file must be a single-link regular file"
        )
    if metadata.st_size > MAX_TRUSTED_INSTRUCTIONS_BYTES:
        raise RuntimeError("configured Codex instructions file is too large")


def _open_trusted_path(path: Path) -> _OpenedTrustedPath:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_only = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_only is None or os.open not in os.supports_dir_fd:
        raise RuntimeError(
            "this platform cannot validate Codex instructions path ancestry safely"
        )

    directory_flags = os.O_RDONLY | no_follow | directory_only
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NONBLOCK", 0)
    directory_fds: list[int] = []
    directory_metadata: list[os.stat_result] = []
    file_fd: int | None = None
    try:
        root_fd = os.open(path.anchor, directory_flags)
        directory_fds.append(root_fd)
        root_metadata = os.fstat(root_fd)
        _validate_trusted_directory(root_metadata)
        directory_metadata.append(root_metadata)

        for component in path.parts[1:-1]:
            try:
                descriptor = os.open(
                    component, directory_flags, dir_fd=directory_fds[-1]
                )
            except OSError as exc:
                raise RuntimeError(
                    "configured Codex instructions path components must be real "
                    "trusted directories without symlinks"
                ) from exc
            directory_fds.append(descriptor)
            metadata = os.fstat(descriptor)
            _validate_trusted_directory(metadata)
            directory_metadata.append(metadata)

        try:
            file_fd = os.open(path.name, file_flags, dir_fd=directory_fds[-1])
        except OSError as exc:
            raise RuntimeError(
                "configured Codex instructions file cannot be opened safely"
            ) from exc
        file_metadata = os.fstat(file_fd)
        _validate_trusted_file(file_metadata)
        return _OpenedTrustedPath(
            directory_fds, directory_metadata, file_fd, file_metadata
        )
    except Exception:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)
        raise


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


def _canonical_open_path(path: Path, metadata: os.stat_result) -> Path:
    try:
        canonical = path.resolve(strict=True)
        canonical_metadata = canonical.stat()
    except OSError as exc:
        raise RuntimeError(
            "configured Codex instructions path changed while being validated"
        ) from exc
    if (canonical_metadata.st_dev, canonical_metadata.st_ino) != (
        metadata.st_dev,
        metadata.st_ino,
    ):
        raise RuntimeError(
            "configured Codex instructions path changed while being validated"
        )
    return canonical


def read_trusted_instructions(
    path: Path, *, workspace: Path | None = None
) -> TrustedInstructions:
    """Read one stable snapshot through an owner-controlled, symlink-free path."""

    lexical_path = _normalized_absolute(path, "instructions_file")
    workspace_paths = _workspace_paths(workspace)
    _reject_workspace_overlap(
        lexical_path, workspace_paths, path_kind="lexically"
    )

    opened = _open_trusted_path(lexical_path)
    try:
        _reject_workspace_identity_overlap(opened, workspace_paths)
        canonical_path = _canonical_open_path(lexical_path, opened.file_metadata)
        _reject_workspace_overlap(
            canonical_path, workspace_paths, path_kind="canonically"
        )

        chunks: list[bytes] = []
        remaining = MAX_TRUSTED_INSTRUCTIONS_BYTES + 1
        while remaining:
            chunk = os.read(opened.file_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)

        file_after_read = os.fstat(opened.file_fd)
        _validate_trusted_file(file_after_read)
        if (
            _file_identity(opened.file_metadata) != _file_identity(file_after_read)
            or len(payload) != opened.file_metadata.st_size
        ):
            raise RuntimeError(
                "configured Codex instructions file changed while reading"
            )

        for descriptor, before in zip(
            opened.directory_fds, opened.directory_metadata, strict=True
        ):
            after = os.fstat(descriptor)
            _validate_trusted_directory(after)
            if _directory_identity(before) != _directory_identity(after):
                raise RuntimeError(
                    "configured Codex instructions ancestry changed while reading"
                )

        reopened = _open_trusted_path(lexical_path)
        try:
            if len(opened.directory_metadata) != len(reopened.directory_metadata):
                raise RuntimeError(
                    "configured Codex instructions ancestry changed while reading"
                )
            if any(
                _directory_identity(before) != _directory_identity(after)
                for before, after in zip(
                    opened.directory_metadata,
                    reopened.directory_metadata,
                    strict=True,
                )
            ):
                raise RuntimeError(
                    "configured Codex instructions ancestry changed while reading"
                )
            if _file_identity(file_after_read) != _file_identity(
                reopened.file_metadata
            ):
                raise RuntimeError(
                    "configured Codex instructions file changed while reading"
                )
            canonical_after_read = _canonical_open_path(
                lexical_path, reopened.file_metadata
            )
            if canonical_after_read != canonical_path:
                raise RuntimeError(
                    "configured Codex instructions path changed while reading"
                )
        finally:
            reopened.close()
    finally:
        opened.close()

    if len(payload) > MAX_TRUSTED_INSTRUCTIONS_BYTES:
        raise RuntimeError("configured Codex instructions file is too large")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            "configured Codex instructions file must be valid UTF-8"
        ) from exc
    if "\x00" in text:
        raise RuntimeError("configured Codex instructions file contains a NUL byte")
    return TrustedInstructions(
        text=text,
        sha256=hashlib.sha256(payload).hexdigest(),
        canonical_path=canonical_path,
    )


def load_trusted_instructions(path: Path) -> tuple[str, str]:
    snapshot = read_trusted_instructions(path)
    return snapshot.text, snapshot.sha256
