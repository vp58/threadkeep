from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_SKILL_FILE_BYTES = 2 * 1024 * 1024
MAX_SKILL_FILES = 256
MAX_SKILL_TREE_BYTES = 16 * 1024 * 1024
SKILL_BINDING_VERSION = 1


@dataclass(frozen=True)
class SkillSpec:
    name: str
    directory: Path
    bridge_name: str

    @property
    def skill_file(self) -> Path:
        return self.directory / "SKILL.md"


REQUIRED_SKILLS = (
    SkillSpec("skill-finder", Path("skill-finder"), "skill-finder"),
    SkillSpec("eli5", Path("eli5"), "eli5"),
    SkillSpec(
        "marketing/websites/vinaytalks",
        Path("marketing/websites/vinaytalks"),
        "vinaytalks",
    ),
    SkillSpec("triage", Path("triage"), "triage"),
)


@dataclass(frozen=True)
class BoundSkill:
    name: str
    path: Path
    sha256: str


@dataclass(frozen=True)
class SharedSkillBinding:
    root: Path
    manifest_sha256: str
    skills: tuple[BoundSkill, ...]

    def input_items(self, text: str) -> list[dict[str, str]]:
        selected = select_skills(text)
        if not selected:
            return [{"type": "text", "text": text}]
        by_name = {skill.name: skill for skill in self.skills}
        missing = selected.difference(by_name)
        if missing:
            raise RuntimeError("required shared skill is missing from the bound manifest")
        ordered = [spec.name for spec in REQUIRED_SKILLS if spec.name in selected]
        absent_markers = [f"${name}" for name in ordered if f"${name}" not in text]
        enriched = text
        if absent_markers:
            enriched = " ".join(absent_markers) + "\n\n" + text
        items: list[dict[str, str]] = [{"type": "text", "text": enriched}]
        items.extend(
            {
                "type": "skill",
                "name": name,
                "path": str(by_name[name].path),
            }
            for name in ordered
        )
        return items


_ELI5_PATTERN = re.compile(
    r"(?i)(?:\$eli5\b|\beli\s*5\b|\bexplain\s+like\s+i(?:'| a)?m\s+(?:5|five)\b)"
)
_VINAYTALKS_PATTERN = re.compile(
    r"(?i)(?:\$marketing/websites/vinaytalks\b|\bvinaytalks(?:\.com)?\b)"
)
_TRIAGE_PATTERN = re.compile(
    r"(?i)(?:\$triage\b|\b(?:triage|process|clear|clean\s+up)\s+"
    r"(?:my\s+)?(?:personal\s+|work\s+)?"
    r"(?:all|email|inbox|messages|notes|slack|tasks)\b)"
)
_CREATE_PATTERN = re.compile(
    r"(?i)\b(?:build|compose|convert|craft|create|deploy|design|draft|draw|edit|"
    r"generate|host|illustrate|make|produce|publish|render|ship|transform|"
    r"update(?!\s+(?:me|us)\b)|write)\w*\b"
)
_TURN_INTO_PATTERN = re.compile(r"(?is)\bturn\b.{0,120}?\binto\b")
_ARTIFACT_PATTERN = re.compile(
    r"(?i)\b(?:animation|artifact|asset|chart|deck|diagram|document|explainer|"
    r"graphic|image|infographic|mockup|one[- ]?pager|page|pdf|presentation|"
    r"report|site|slide|spreadsheet|video|visual|website|worksheet)\w*\b"
)


def select_skills(text: str) -> set[str]:
    """Route every turn through the canonical Vault skill finder.

    The direct routes below remove ambiguity for the workflows that have
    standing product behavior. The skill finder keeps the rest of the shared
    Vault available without copying or hard-coding its complete catalog here.
    """

    selected: set[str] = {"skill-finder"}
    if _ELI5_PATTERN.search(text):
        selected.update(
            {"eli5", "marketing/websites/vinaytalks"}
        )
    artifact = _ARTIFACT_PATTERN.search(text)
    if _VINAYTALKS_PATTERN.search(text) or (
        artifact
        and (_CREATE_PATTERN.search(text) or _TURN_INTO_PATTERN.search(text))
    ):
        selected.add("marketing/websites/vinaytalks")
    if _TRIAGE_PATTERN.search(text):
        selected.add("triage")
    return selected


def _real_user_home() -> Path:
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError) as exc:
        raise RuntimeError("current user's canonical home is unavailable") from exc
    metadata = home.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError(
            "current user's canonical home must be owned and not group/world writable"
        )
    return home


def _safe_directory_metadata(metadata: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError(f"{label} must be a current-user-owned safe directory")


def _descriptor_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_skills_root(root: Path) -> tuple[Path, int]:
    requested = Path(os.path.abspath(root.expanduser()))
    try:
        canonical = requested.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("shared Vault skill root cannot be resolved") from exc
    if requested != canonical or canonical.parts[-2:] != ("x_System", "Skills"):
        raise RuntimeError(
            "shared Vault skill root must be the canonical x_System/Skills directory"
        )
    home = _real_user_home()
    try:
        relative = canonical.relative_to(home)
    except ValueError as exc:
        raise RuntimeError("shared Vault skill root must stay under the current user's home") from exc
    if len(relative.parts) < 3:
        raise RuntimeError("shared Vault skill root is missing its Vault directory")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(home, flags)
    try:
        _safe_directory_metadata(os.fstat(descriptor), "canonical home")
        current = home
        for component in relative.parts:
            if component in {"", ".", ".."}:
                raise RuntimeError("shared Vault skill root contains an unsafe component")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            current /= component
            _safe_directory_metadata(
                os.fstat(descriptor), f"shared Vault path component {current}"
            )
        opened = os.fstat(descriptor)
        named = canonical.lstat()
        if _descriptor_identity(opened) != _descriptor_identity(named):
            raise RuntimeError("shared Vault skill root changed while it was opened")
        return canonical, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_file(parent_fd: int, name: str, label: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > MAX_SKILL_FILE_BYTES
        ):
            raise RuntimeError(f"{label} metadata is unsafe")
        content = bytearray()
        while chunk := os.read(descriptor, 65_536):
            content.extend(chunk)
            if len(content) > MAX_SKILL_FILE_BYTES:
                raise RuntimeError(f"{label} exceeds the per-file size limit")
        after = os.fstat(descriptor)
        if _descriptor_identity(before) != _descriptor_identity(after):
            raise RuntimeError(f"{label} changed while it was read")
        if len(content) != before.st_size:
            raise RuntimeError(f"{label} returned an incomplete stable read")
        return bytes(content), after
    finally:
        os.close(descriptor)


def _scan_tree(
    directory_fd: int,
    relative: Path,
    records: list[dict[str, Any]],
    totals: dict[str, int],
) -> None:
    before = os.fstat(directory_fd)
    _safe_directory_metadata(before, f"shared skill directory {relative}")
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise RuntimeError(f"shared skill directory {relative} cannot be listed") from exc
    for name in names:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise RuntimeError("shared skill contains an unsafe file name")
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError("shared skill entry cannot be inspected") from exc
        child_relative = relative / name
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"shared skill entry {child_relative} must not be a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            child_fd = os.open(name, flags, dir_fd=directory_fd)
            try:
                _scan_tree(child_fd, child_relative, records, totals)
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"shared skill entry {child_relative} is not a regular file")
        content, stable = _read_regular_file(
            directory_fd, name, f"shared skill file {child_relative}"
        )
        if (stable.st_dev, stable.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RuntimeError(f"shared skill file {child_relative} changed before reading")
        totals["files"] += 1
        totals["bytes"] += len(content)
        if totals["files"] > MAX_SKILL_FILES or totals["bytes"] > MAX_SKILL_TREE_BYTES:
            raise RuntimeError("required shared skill closure exceeds its review budget")
        records.append(
            {
                "path": child_relative.as_posix(),
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    after = os.fstat(directory_fd)
    if _descriptor_identity(before) != _descriptor_identity(after):
        raise RuntimeError(f"shared skill directory {relative} changed while scanning")


def _frontmatter_name(content: bytes, label: str) -> str:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{label} must be UTF-8") from exc
    if not text.startswith("---\n"):
        raise RuntimeError(f"{label} lacks YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise RuntimeError(f"{label} has unterminated YAML frontmatter")
    names = []
    for line in text[4:end].splitlines():
        if not line.startswith("name:"):
            continue
        value = line.removeprefix("name:").strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        names.append(value)
    if len(names) != 1 or not names[0]:
        raise RuntimeError(f"{label} must declare exactly one skill name")
    return names[0]


def bind_shared_skills(
    root: Path, expected_manifest_sha256: str | None = None
) -> SharedSkillBinding:
    """Read and hash only the reviewed canonical skill closures."""

    canonical, root_fd = _open_skills_root(root)
    records: list[dict[str, Any]] = []
    totals = {"files": 0, "bytes": 0}
    bound: list[BoundSkill] = []
    root_before = os.fstat(root_fd)
    try:
        for spec in REQUIRED_SKILLS:
            directory_fd = os.dup(root_fd)
            try:
                for component in spec.directory.parts:
                    flags = (
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                    )
                    child_fd = os.open(component, flags, dir_fd=directory_fd)
                    os.close(directory_fd)
                    directory_fd = child_fd
                    _safe_directory_metadata(
                        os.fstat(directory_fd), f"required shared skill {spec.name}"
                    )
                directory_before = os.fstat(directory_fd)
                skill_records: list[dict[str, Any]] = []
                _scan_tree(directory_fd, spec.directory, skill_records, totals)
                skill_record = next(
                    (
                        record
                        for record in skill_records
                        if record["path"] == spec.skill_file.as_posix()
                    ),
                    None,
                )
                if skill_record is None:
                    raise RuntimeError(
                        f"required shared skill {spec.name} lacks SKILL.md"
                    )
                content, _ = _read_regular_file(
                    directory_fd,
                    "SKILL.md",
                    f"required shared skill {spec.name}",
                )
                if hashlib.sha256(content).hexdigest() != skill_record["sha256"]:
                    raise RuntimeError(
                        f"required shared skill {spec.name} changed during binding"
                    )
                if (
                    _frontmatter_name(
                        content, f"required shared skill {spec.name}"
                    )
                    != spec.name
                ):
                    raise RuntimeError(
                        f"required shared skill {spec.name} changed its declared name"
                    )
                if _descriptor_identity(directory_before) != _descriptor_identity(
                    os.fstat(directory_fd)
                ):
                    raise RuntimeError(
                        f"required shared skill {spec.name} changed during binding"
                    )
            finally:
                os.close(directory_fd)
            skill_path = canonical / spec.skill_file
            records.extend(skill_records)
            bound.append(
                BoundSkill(
                    name=spec.name,
                    path=skill_path,
                    sha256=skill_record["sha256"],
                )
            )
        root_after = os.fstat(root_fd)
        if _descriptor_identity(root_before) != _descriptor_identity(root_after):
            raise RuntimeError("shared Vault skill root changed during binding")
    finally:
        os.close(root_fd)
    manifest = {
        "version": SKILL_BINDING_VERSION,
        "root": str(canonical),
        "skills": [
            {"name": skill.name, "path": str(skill.path), "sha256": skill.sha256}
            for skill in bound
        ],
        "files": records,
    }
    digest = hashlib.sha256(
        json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()
    if expected_manifest_sha256 is not None and digest != expected_manifest_sha256:
        raise RuntimeError("shared Vault skills changed after policy binding")
    return SharedSkillBinding(canonical, digest, tuple(bound))


def _require_private_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError(f"{label} must be a private current-user-owned real directory")


def validate_skill_bridge(codex_home: Path, binding: SharedSkillBinding) -> None:
    _require_private_directory(codex_home, "isolated CODEX_HOME")
    bridge = codex_home / "skills"
    _require_private_directory(bridge, "isolated Codex skill bridge")
    expected = {
        spec.bridge_name: binding.root / spec.directory for spec in REQUIRED_SKILLS
    }
    try:
        observed_names = set(os.listdir(bridge))
    except OSError as exc:
        raise RuntimeError("isolated Codex skill bridge cannot be listed") from exc
    if observed_names != set(expected):
        raise RuntimeError("isolated Codex skill bridge contains unexpected entries")
    for name, target in expected.items():
        link = bridge / name
        try:
            metadata = link.lstat()
            raw_target = os.readlink(link)
        except OSError as exc:
            raise RuntimeError(f"isolated Codex skill bridge {name} is unavailable") from exc
        if (
            not stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or raw_target != str(target)
            or link.resolve(strict=True) != target
        ):
            raise RuntimeError(f"isolated Codex skill bridge {name} was redirected")


def prepare_skill_bridge(codex_home: Path, root: Path) -> bool:
    """Create one validated, link-only bridge to the canonical Vault skills."""

    binding = bind_shared_skills(root)
    _require_private_directory(codex_home, "isolated CODEX_HOME")
    bridge = codex_home / "skills"
    if bridge.exists() or bridge.is_symlink():
        validate_skill_bridge(codex_home, binding)
        return False
    try:
        os.mkdir(bridge, 0o700)
        for spec in REQUIRED_SKILLS:
            os.symlink(
                str(binding.root / spec.directory),
                bridge / spec.bridge_name,
                target_is_directory=True,
            )
        validate_skill_bridge(codex_home, binding)
    except BaseException:
        for spec in REQUIRED_SKILLS:
            link = bridge / spec.bridge_name
            if link.is_symlink():
                link.unlink()
        try:
            bridge.rmdir()
        except OSError:
            pass
        raise
    return True


def remove_created_skill_bridge(codex_home: Path, root: Path) -> None:
    """Rollback a bridge that this install created after full validation."""

    binding = bind_shared_skills(root)
    validate_skill_bridge(codex_home, binding)
    bridge = codex_home / "skills"
    for spec in REQUIRED_SKILLS:
        (bridge / spec.bridge_name).unlink()
    bridge.rmdir()
