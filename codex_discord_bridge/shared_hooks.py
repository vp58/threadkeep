from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from conversations.vault_policy import _read_stable_file


HOOK_BINDING_VERSION = 2
MAX_HOOK_FILE_BYTES = 1024 * 1024
HOOK_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class BoundHookFile:
    relative_path: str
    source_path: Path
    sha256: str
    size: int
    content: bytes


@dataclass(frozen=True)
class HookDefinition:
    matcher: str
    command: str
    status_message: str
    timeout_seconds: int = HOOK_TIMEOUT_SECONDS

    def config_group(self) -> dict[str, object]:
        return {
            "matcher": self.matcher,
            "hooks": [
                {
                    "type": "command",
                    "command": self.command,
                    "timeout": self.timeout_seconds,
                    "statusMessage": self.status_message,
                }
            ],
        }


@dataclass(frozen=True)
class SharedHookBinding:
    vault_root: Path
    source_manifest_sha256: str
    files: tuple[BoundHookFile, ...]


@dataclass(frozen=True)
class RuntimeHookBinding:
    source: SharedHookBinding
    runtime_root: Path
    hooks_path: Path
    manifest_path: Path
    manifest_sha256: str
    config_sha256: str
    definitions: tuple[HookDefinition, ...]

    def config_text(self) -> str:
        payload = {
            "description": (
                "Threadkeep sealed canonical Vault guardrails. Hook decisions are "
                "defense in depth and are not an outbound authorization boundary."
            ),
            "hooks": {
                "PreToolUse": [definition.config_group() for definition in self.definitions]
            },
        }
        return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"


_HOOK_FILES = (
    ".claude/hooks/security_validator.py",
    ".claude/hooks/em-dash-write-validator.py",
    "x_System/Scripts/outbound_send_gate_hook.py",
    "x_System/Scripts/hook_command_detect.py",
)


def _canonical_vault_root(vault_root: Path) -> Path:
    if not vault_root.is_absolute() or ".." in vault_root.parts:
        raise RuntimeError("canonical Vault hook root must be an absolute path")
    requested = Path(os.path.normpath(os.fspath(vault_root)))
    try:
        canonical = requested.resolve(strict=True)
        metadata = requested.lstat()
    except OSError as exc:
        raise RuntimeError("canonical Vault hook root is unavailable") from exc
    if (
        canonical != requested
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError("canonical Vault hook root metadata is unsafe")
    return canonical


def bind_shared_hooks(
    vault_root: Path,
    *,
    expected_source_manifest_sha256: str | None = None,
    workspace: Path | None = None,
) -> SharedHookBinding:
    """Read the complete exact hook source closure from the canonical Vault."""

    root = _canonical_vault_root(vault_root)
    files: list[BoundHookFile] = []
    for relative in _HOOK_FILES:
        canonical, content = _read_stable_file(
            root / relative,
            f"canonical Vault hook {relative}",
            maximum=MAX_HOOK_FILE_BYTES,
            workspace=workspace,
        )
        try:
            metadata = canonical.lstat()
        except OSError as exc:
            raise RuntimeError(f"canonical Vault hook {relative} is unavailable") from exc
        if not metadata.st_mode & stat.S_IXUSR:
            raise RuntimeError(f"canonical Vault hook {relative} must be owner executable")
        files.append(
            BoundHookFile(
                relative_path=relative,
                source_path=canonical,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
                content=content,
            )
        )
    manifest = {
        "version": HOOK_BINDING_VERSION,
        "vault_root": str(root),
        "files": [
            {
                "relative_path": file.relative_path,
                "source_path": str(file.source_path),
                "sha256": file.sha256,
                "size": file.size,
            }
            for file in files
        ],
    }
    digest = hashlib.sha256(
        json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    if expected_source_manifest_sha256 is not None and digest != expected_source_manifest_sha256:
        raise RuntimeError("canonical Vault hook closure changed after policy binding")
    return SharedHookBinding(root, digest, tuple(files))


def _snapshot_names(binding: SharedHookBinding) -> dict[str, str]:
    names: dict[str, str] = {}
    seen: set[str] = set()
    for file in binding.files:
        name = Path(file.relative_path).name
        if name in seen:
            raise RuntimeError("canonical Vault hook closure has duplicate basenames")
        seen.add(name)
        names[file.relative_path] = name
    return names


def _hook_command(*parts: str | Path) -> str:
    return " ".join(shlex.quote(str(value)) for value in parts)


def _runtime_definitions(
    runtime_root: Path, binding: SharedHookBinding
) -> tuple[HookDefinition, ...]:
    names = _snapshot_names(binding)
    return (
        HookDefinition(
            matcher="^Bash$",
            command=_hook_command(
                "/usr/bin/python3",
                "-I",
                "-S",
                runtime_root / names[".claude/hooks/security_validator.py"],
                "--detector",
                runtime_root / names["x_System/Scripts/hook_command_detect.py"],
            ),
            status_message="Threadkeep command safety guard",
        ),
        HookDefinition(
            matcher="^(Bash|apply_patch)$",
            command=_hook_command(
                "/usr/bin/python3",
                "-I",
                "-S",
                runtime_root / names[".claude/hooks/em-dash-write-validator.py"],
            ),
            status_message="Threadkeep written text guard",
        ),
        HookDefinition(
            matcher="^Bash$",
            command=_hook_command(
                "/usr/bin/python3",
                "-I",
                "-S",
                runtime_root / names["x_System/Scripts/outbound_send_gate_hook.py"],
                "--threadkeep-deny-only",
            ),
            status_message="Threadkeep outbound wrapper deny guard",
        ),
    )


def _runtime_root(codex_home: Path, binding: SharedHookBinding) -> Path:
    return (
        codex_home.parent.parent
        / "hook-runtime"
        / f"v{HOOK_BINDING_VERSION}-{binding.source_manifest_sha256}"
    )


def _runtime_payload(
    binding: SharedHookBinding,
    runtime_root: Path,
    definitions: tuple[HookDefinition, ...],
) -> tuple[bytes, str, str]:
    provisional = RuntimeHookBinding(
        source=binding,
        runtime_root=runtime_root,
        hooks_path=Path(),
        manifest_path=runtime_root / "manifest.json",
        manifest_sha256="",
        config_sha256="",
        definitions=definitions,
    )
    config_sha256 = hashlib.sha256(
        provisional.config_text().encode("utf-8")
    ).hexdigest()
    names = _snapshot_names(binding)
    payload = {
        "version": HOOK_BINDING_VERSION,
        "source_manifest_sha256": binding.source_manifest_sha256,
        "runtime_root": str(runtime_root),
        "config_sha256": config_sha256,
        "files": [
            {
                "name": names[file.relative_path],
                "source_relative_path": file.relative_path,
                "sha256": file.sha256,
                "size": file.size,
                "mode": "0400",
            }
            for file in binding.files
        ],
        "definitions": [
            {
                "matcher": definition.matcher,
                "command": definition.command,
                "status_message": definition.status_message,
                "timeout_seconds": definition.timeout_seconds,
            }
            for definition in definitions
        ],
    }
    content = json.dumps(payload, indent=2, ensure_ascii=True).encode("utf-8") + b"\n"
    return content, hashlib.sha256(content).hexdigest(), config_sha256


def _require_directory(path: Path, label: str, mode: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise RuntimeError(f"{label} metadata is unsafe")


def _read_private_file(path: Path, label: str, expected_mode: int) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_size > MAX_HOOK_FILE_BYTES
    ):
        raise RuntimeError(f"{label} metadata is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        content = bytearray()
        while chunk := os.read(descriptor, 65_536):
            content.extend(chunk)
            if len(content) > MAX_HOOK_FILE_BYTES:
                raise RuntimeError(f"{label} exceeds its size limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(before) != identity(after) or len(content) != after.st_size:
        raise RuntimeError(f"{label} changed while being read")
    return bytes(content)


def validate_hook_bridge(
    codex_home: Path,
    binding: SharedHookBinding,
    *,
    expected_manifest_sha256: str | None = None,
) -> RuntimeHookBinding:
    _require_directory(codex_home.parent.parent, "isolated Codex state directory", 0o700)
    _require_directory(codex_home.parent, "isolated Codex worker home", 0o700)
    _require_directory(codex_home, "isolated CODEX_HOME", 0o700)
    runtime_parent = codex_home.parent.parent / "hook-runtime"
    _require_directory(runtime_parent, "isolated Codex hook runtime parent", 0o700)
    runtime_root = _runtime_root(codex_home, binding)
    _require_directory(runtime_root, "sealed Codex hook runtime", 0o500)
    definitions = _runtime_definitions(runtime_root, binding)
    manifest_content, manifest_sha256, config_sha256 = _runtime_payload(
        binding, runtime_root, definitions
    )
    if expected_manifest_sha256 is not None and manifest_sha256 != expected_manifest_sha256:
        raise RuntimeError("sealed Codex hook runtime changed after policy binding")
    names = _snapshot_names(binding)
    expected_entries = {"manifest.json", *names.values()}
    try:
        entries = set(os.listdir(runtime_root))
    except OSError as exc:
        raise RuntimeError("sealed Codex hook runtime cannot be listed") from exc
    if entries != expected_entries:
        raise RuntimeError("sealed Codex hook runtime contains an unexpected entry")
    for file in binding.files:
        content = _read_private_file(
            runtime_root / names[file.relative_path],
            f"sealed Codex hook {file.relative_path}",
            0o400,
        )
        if content != file.content or hashlib.sha256(content).hexdigest() != file.sha256:
            raise RuntimeError("sealed Codex hook differs from its canonical Vault source")
    observed_manifest = _read_private_file(
        runtime_root / "manifest.json", "sealed Codex hook manifest", 0o400
    )
    if observed_manifest != manifest_content:
        raise RuntimeError("sealed Codex hook manifest differs from reviewed policy")

    runtime = RuntimeHookBinding(
        source=binding,
        runtime_root=runtime_root,
        hooks_path=codex_home / "hooks.json",
        manifest_path=runtime_root / "manifest.json",
        manifest_sha256=manifest_sha256,
        config_sha256=config_sha256,
        definitions=definitions,
    )
    hooks_content = _read_private_file(
        runtime.hooks_path, "isolated Codex hook config", 0o600
    )
    expected_hooks = runtime.config_text().encode("utf-8")
    if (
        hooks_content != expected_hooks
        or hashlib.sha256(hooks_content).hexdigest() != config_sha256
    ):
        raise RuntimeError("isolated Codex hook config differs from reviewed policy")
    return runtime


def _write_private_file(path: Path, content: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError("private hook snapshot write did not make progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(mode)


def write_hook_bridge(codex_home: Path, binding: SharedHookBinding) -> RuntimeHookBinding:
    """Create an immutable private runtime snapshot derived from the Vault source."""

    _require_directory(codex_home.parent.parent, "isolated Codex state directory", 0o700)
    _require_directory(codex_home.parent, "isolated Codex worker home", 0o700)
    _require_directory(codex_home, "isolated CODEX_HOME", 0o700)
    runtime_parent = codex_home.parent.parent / "hook-runtime"
    try:
        os.mkdir(runtime_parent, 0o700)
    except FileExistsError:
        pass
    _require_directory(runtime_parent, "isolated Codex hook runtime parent", 0o700)
    runtime_root = _runtime_root(codex_home, binding)
    names = _snapshot_names(binding)
    definitions = _runtime_definitions(runtime_root, binding)
    manifest_content, _, _ = _runtime_payload(binding, runtime_root, definitions)
    if not runtime_root.exists():
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{runtime_root.name}.", dir=runtime_parent
            )
        )
        try:
            staging.chmod(0o700)
            for file in binding.files:
                _write_private_file(
                    staging / names[file.relative_path], file.content, 0o400
                )
            _write_private_file(staging / "manifest.json", manifest_content, 0o400)
            staging.chmod(0o500)
            os.rename(staging, runtime_root)
        finally:
            if staging.exists():
                staging.chmod(0o700)
                for child in staging.iterdir():
                    child.chmod(0o600)
                    child.unlink()
                staging.rmdir()

    provisional = RuntimeHookBinding(
        source=binding,
        runtime_root=runtime_root,
        hooks_path=codex_home / "hooks.json",
        manifest_path=runtime_root / "manifest.json",
        manifest_sha256="",
        config_sha256="",
        definitions=definitions,
    )
    target = provisional.hooks_path
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise RuntimeError("refusing to replace an unsafe isolated Codex hook config")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".hooks.json.", dir=codex_home)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(provisional.config_text().encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return validate_hook_bridge(codex_home, binding)
