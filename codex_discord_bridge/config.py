from __future__ import annotations

import hashlib
import json
import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path


def _ancestor_identities(path: Path) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    current = path
    while True:
        try:
            metadata = current.stat()
        except OSError as exc:
            raise RuntimeError(f"control path is unavailable: {current}") from exc
        identities.add((metadata.st_dev, metadata.st_ino))
        parent = current.parent
        if parent == current:
            return identities
        current = parent


def _paths_overlap(first: Path, second: Path) -> bool:
    """Compare lexical ancestry and inode ancestry across macOS firmlinks."""

    first_resolved = first.resolve(strict=False)
    second_resolved = second.resolve(strict=False)
    if (
        first_resolved == second_resolved
        or first_resolved.is_relative_to(second_resolved)
        or second_resolved.is_relative_to(first_resolved)
    ):
        return True
    try:
        first_metadata = first_resolved.stat()
        second_metadata = second_resolved.stat()
    except OSError:
        # Textual containment above is still meaningful for a not-yet-created
        # child. Identity comparison becomes available after installation;
        # every sensitive generated child is also covered by its existing
        # state-directory parent in the caller's control-path set.
        return False
    first_identity = (first_metadata.st_dev, first_metadata.st_ino)
    second_identity = (second_metadata.st_dev, second_metadata.st_ino)
    return (
        first_identity in _ancestor_identities(second_resolved)
        or second_identity in _ancestor_identities(first_resolved)
    )


def _canonical_user_home() -> Path:
    account = pwd.getpwuid(os.getuid())
    home_input = Path(account.pw_dir)
    if not home_input.is_absolute() or any(
        part in {".", ".."} for part in home_input.parts
    ):
        raise RuntimeError("canonical HOME is unsafe")
    try:
        home = home_input.resolve(strict=True)
        home_metadata = home.lstat()
    except OSError as exc:
        raise RuntimeError("canonical HOME is unavailable") from exc
    if (
        home != Path(os.path.normpath(os.fspath(home_input)))
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.getuid()
        or stat.S_IMODE(home_metadata.st_mode) & 0o022
    ):
        raise RuntimeError(
            "canonical HOME must be current-user-owned and not group/world writable"
        )
    return home


def _validated_state_dir(path: Path) -> Path:
    """Enforce the installer state boundary again at every runtime start."""

    home = _canonical_user_home()
    home_input = home

    if any(part in {".", ".."} for part in path.parts):
        raise RuntimeError("Codex state_dir must not contain traversal components")
    requested = path.absolute()
    try:
        relative = requested.relative_to(home_input)
    except ValueError:
        try:
            relative = requested.resolve(strict=False).relative_to(home)
        except ValueError as exc:
            raise RuntimeError("Codex state_dir must stay under canonical HOME") from exc
    approved = ("Library", "Application Support", "Threadkeep")
    if (
        relative.parts[: len(approved)] != approved
        or len(relative.parts) <= len(approved)
    ):
        raise RuntimeError(
            "Codex state_dir must stay under ~/Library/Application Support/Threadkeep"
        )

    current = home
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise RuntimeError("Codex state_dir topology is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("Codex state_dir components must be real directories")
        if metadata.st_uid != os.getuid():
            raise RuntimeError("Codex state_dir components must be current-user-owned")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise RuntimeError(
                "Codex state_dir components must not be group/world writable"
            )
    canonical = current.resolve(strict=True)
    approved_root = home.joinpath(*approved).resolve(strict=True)
    if canonical == approved_root or not canonical.is_relative_to(approved_root):
        raise RuntimeError(
            "Codex state_dir must stay under ~/Library/Application Support/Threadkeep"
        )
    return canonical


@dataclass(frozen=True)
class Config:
    """Validated runtime configuration for the Codex provider.

    The first five fields stay positional so protocol and ingress tests can
    construct small fixtures. Production configuration comes from Threadkeep's
    shared config loader through ``from_threadkeep``.
    """

    guild_id: str
    channel_id: str
    owner_user_id: str
    bot_user_id: str
    application_id: str
    channel_trust: str = "public"
    working_directory: Path = Path.home() / ".threadkeep"
    state_dir: Path = Path.home() / "Library/Application Support/Threadkeep/codex-discord"
    codex_home: Path = Path.home() / "Library/Application Support/Threadkeep/codex-discord/home/.codex"
    codex_bin: Path = Path("/opt/homebrew/bin/codex")
    sandbox_mode: str = "workspace-write"
    full_computer_access_accepted: bool = False
    instructions_file: Path | None = None
    shared_skills_root: Path = Path.home() / "TheSystem/x_System/Skills"
    keychain_service: str = "threadkeep-secret"
    keychain_account: str = "discord-bot-token-codex"
    max_messages_per_minute: int = 5
    max_messages_per_hour: int = 30
    max_concurrent_workers: int = 3
    max_pending_jobs: int = 100
    max_input_chars: int = 12_000
    retention_days: int = 30
    max_database_bytes: int = 268_435_456

    @property
    def vault_root(self) -> Path:
        return self.shared_skills_root.parent.parent

    @property
    def vault_policy_snapshot(self) -> Path:
        return self.state_dir / "policy/vault-p0.md"

    def seal_vault_policy(self):
        from conversations.vault_policy import seal_vault_policy

        return seal_vault_policy(
            vault_root=self.vault_root,
            snapshot_path=self.vault_policy_snapshot,
            runtime_root=self.state_dir,
            workspace=self.working_directory,
        )

    def policy_fingerprint(
        self,
        instructions_sha256: str | None = None,
        account_binding: str | None = None,
        shared_skills_manifest_sha256: str | None = None,
        vault_policy_seal=None,
        shared_hooks_manifest_sha256: str | None = None,
    ) -> str:
        """Bind durable ingress and sessions to one reviewed runtime policy."""

        from .codex_auth import (
            SUPPORTED_CODEX_VERSION,
            SUPPORTED_EXPERIMENTAL_SCHEMA_SHA256,
            SUPPORTED_NATIVE_SHA256,
        )
        from .codex_policy import (
            MODEL_ID,
            MODEL_PROVIDER,
            POLICY_BINDING_VERSION,
            REASONING_EFFORT,
            base_instructions,
            thread_config,
        )
        from .trusted_instructions import read_trusted_instructions
        from .shared_skills import bind_shared_skills

        workspace = self.working_directory.resolve(strict=True)
        instructions_hash = None
        instructions_path = None
        if self.instructions_file is not None:
            instructions = read_trusted_instructions(
                self.instructions_file, workspace=self.working_directory
            )
            instructions_path = str(instructions.canonical_path)
            observed_hash = instructions.sha256
            if (
                instructions_sha256 is not None
                and observed_hash != instructions_sha256
            ):
                raise RuntimeError(
                    "configured Codex instructions changed while binding policy"
                )
            instructions_hash = observed_hash
        elif instructions_sha256 is not None:
            raise RuntimeError("instructions digest supplied without an instructions file")
        if (
            not isinstance(account_binding, str)
            or len(account_binding) != 64
            or any(character not in "0123456789abcdef" for character in account_binding)
        ):
            raise RuntimeError("a validated nonsecret ChatGPT account binding is required")
        if vault_policy_seal is None:
            raise RuntimeError("a sealed canonical Vault policy is required")
        from conversations.vault_policy import validate_vault_policy_seal

        validate_vault_policy_seal(
            vault_policy_seal,
            vault_root=self.vault_root,
            runtime_root=self.state_dir,
            workspace=self.working_directory,
        )
        shared_skills = bind_shared_skills(
            self.shared_skills_root,
            expected_manifest_sha256=shared_skills_manifest_sha256,
        )
        from .shared_hooks import bind_shared_hooks, validate_hook_bridge

        shared_hook_sources = bind_shared_hooks(
            self.vault_root,
            workspace=self.working_directory,
        )
        shared_hooks = validate_hook_bridge(
            self.codex_home,
            shared_hook_sources,
            expected_manifest_sha256=shared_hooks_manifest_sha256,
        )
        payload = {
            "version": POLICY_BINDING_VERSION,
            "base_instructions_hash": hashlib.sha256(
                base_instructions(
                    self.channel_trust,
                    full_computer_access=self.sandbox_mode == "danger-full-access",
                ).encode("utf-8")
            ).hexdigest(),
            "discord": {
                "guild_id": self.guild_id,
                "channel_id": self.channel_id,
                "owner_user_id": self.owner_user_id,
                "bot_user_id": self.bot_user_id,
                "application_id": self.application_id,
                "channel_trust": self.channel_trust,
            },
            "workspace": str(workspace),
            "sandbox_mode": self.sandbox_mode,
            "runtime": {
                "max_concurrent_workers": self.max_concurrent_workers,
            },
            "model": MODEL_ID,
            "model_provider": MODEL_PROVIDER,
            "reasoning_effort": REASONING_EFFORT,
            "thread_config": thread_config(self.sandbox_mode == "workspace-write"),
            "codex_version": SUPPORTED_CODEX_VERSION,
            "native_hash": SUPPORTED_NATIVE_SHA256,
            "schema_hash": SUPPORTED_EXPERIMENTAL_SCHEMA_SHA256,
            "chatgpt_account_binding": account_binding,
            "vault_policy": vault_policy_seal.binding(),
            "instructions_path": instructions_path,
            "instructions_hash": instructions_hash,
            "shared_skills_root": str(shared_skills.root),
            "shared_skills_manifest_sha256": shared_skills.manifest_sha256,
            "shared_skills": [
                {
                    "name": skill.name,
                    "path": str(skill.path),
                    "sha256": skill.sha256,
                }
                for skill in shared_skills.skills
            ],
            "shared_hooks_manifest_sha256": shared_hooks.manifest_sha256,
            "shared_hooks_config_sha256": shared_hooks.config_sha256,
            "shared_hook_files": [
                {
                    "relative_path": file.relative_path,
                    "source_path": str(file.source_path),
                    "sha256": file.sha256,
                    "size": file.size,
                }
                for file in shared_hooks.source.files
            ],
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        return hashlib.sha256(canonical).hexdigest()

    def instructions_digest(self) -> str | None:
        if self.instructions_file is None:
            return None
        from .trusted_instructions import read_trusted_instructions

        instructions = read_trusted_instructions(
            self.instructions_file,
            workspace=self.working_directory,
        )
        return instructions.sha256

    def shared_skills_digest(self) -> str:
        from .shared_skills import bind_shared_skills

        return bind_shared_skills(self.shared_skills_root).manifest_sha256

    def shared_hooks_digest(self) -> str:
        from .shared_hooks import bind_shared_hooks, validate_hook_bridge

        sources = bind_shared_hooks(
            self.vault_root, workspace=self.working_directory
        )
        return validate_hook_bridge(self.codex_home, sources).manifest_sha256

    @classmethod
    def from_threadkeep(cls) -> "Config":
        from conversations.config import CONFIG as threadkeep_config
        from conversations.config import REPO_ROOT, _config_path

        source = threadkeep_config.codex
        if not source.enabled:
            raise RuntimeError("the Codex orchestrator is disabled in Threadkeep config")
        required_ids = {
            "guild_id": source.guild_id,
            "channel_id": source.channel_id,
            "owner_user_id": source.owner_user_id,
            "bot_user_id": source.bot_user_id,
            "application_id": source.application_id,
        }
        for name, value in required_ids.items():
            if not value.isdecimal():
                raise ValueError(f"codex.{name} must be an immutable numeric Discord ID")
        claude_channels = {
            threadkeep_config.discord.chat_channel_id,
            threadkeep_config.discord.errors_channel_id,
        }
        if source.channel_id in claude_channels:
            raise ValueError("Claude and Codex must use different Discord channels")
        if source.channel_trust not in {"public", "owner_private"}:
            raise ValueError("codex.channel_trust must be 'public' or 'owner_private'")
        if (
            source.sandbox_mode == "danger-full-access"
            and not source.full_computer_access_accepted
        ):
            raise RuntimeError(
                "danger-full-access requires explicit full_computer_access_accepted=true"
            )
        if not source.working_directory.is_dir():
            raise RuntimeError("configured Codex working_directory does not exist")
        instructions_file = source.instructions_file
        if source.sandbox_mode == "danger-full-access" and instructions_file is None:
            instructions_file = threadkeep_config.paths.workspace_root / "CLAUDE.md"
        if instructions_file is not None and not instructions_file.is_file():
            raise RuntimeError("configured Codex instructions_file does not exist")
        path_fields = {
            "working_directory": source.working_directory,
            "state_dir": source.state_dir,
            "codex_home": source.codex_home,
            "codex_bin": source.codex_bin,
            "shared_skills_root": source.shared_skills_root,
        }
        if instructions_file is not None:
            path_fields["instructions_file"] = instructions_file
        for name, path in path_fields.items():
            if not path.is_absolute():
                raise ValueError(f"codex.{name} must be an absolute path")

        workspace = source.working_directory.resolve()
        expected_shared_skills_root = (
            threadkeep_config.paths.workspace_root / "x_System/Skills"
        ).resolve(strict=True)
        if source.shared_skills_root.resolve(strict=True) != expected_shared_skills_root:
            raise RuntimeError(
                "codex.shared_skills_root must be the canonical [paths].workspace_root/x_System/Skills"
            )
        from .shared_skills import bind_shared_skills

        shared_skills_root = bind_shared_skills(
            source.shared_skills_root
        ).root
        if _paths_overlap(workspace, shared_skills_root):
            raise RuntimeError(
                "canonical shared Vault skill root must not overlap the Codex working_directory"
            )
        from .shared_hooks import bind_shared_hooks

        shared_hooks = bind_shared_hooks(
            shared_skills_root.parent.parent,
            workspace=source.working_directory,
        )
        trusted_instructions_path = None
        if instructions_file is not None:
            from .trusted_instructions import read_trusted_instructions

            trusted_instructions_path = read_trusted_instructions(
                instructions_file, workspace=source.working_directory
            ).canonical_path
        state_dir = _validated_state_dir(source.state_dir)
        expected_codex_home = state_dir / "home/.codex"
        if source.codex_home.resolve() != expected_codex_home:
            raise RuntimeError(
                "codex.codex_home must be the isolated state_dir/home/.codex path"
            )
        control_paths = {
            "Threadkeep repository": REPO_ROOT.resolve(),
            "Threadkeep config": _config_path().resolve(),
            "Codex state directory": state_dir,
            "isolated Codex worker home": source.codex_home.parent.resolve(),
            "isolated CODEX_HOME": source.codex_home.resolve(),
            "canonical shared Vault skill root": shared_skills_root,
        }
        for hook_file in shared_hooks.files:
            control_paths[
                f"canonical Vault hook {hook_file.relative_path}"
            ] = hook_file.source_path
        if trusted_instructions_path is not None:
            control_paths["trusted Codex instructions file"] = trusted_instructions_path
        for label, control_path in control_paths.items():
            if _paths_overlap(workspace, control_path):
                raise RuntimeError(
                    f"{label} must not overlap the Codex working_directory"
                )
        if not source.keychain_service or not source.keychain_account:
            raise ValueError("Codex Keychain service and account must be non-empty")
        if (
            source.keychain_service == "threadkeep-secret"
            and source.keychain_account == "discord-bot-token"
        ):
            raise ValueError("Codex must not use the Claude Discord Keychain account")
        limits = {
            "max_messages_per_minute": source.max_messages_per_minute,
            "max_messages_per_hour": source.max_messages_per_hour,
            "max_pending_jobs": source.max_pending_jobs,
            "max_input_chars": source.max_input_chars,
            "retention_days": source.retention_days,
            "max_database_bytes": source.max_database_bytes,
        }
        for name, value in limits.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"codex.{name} must be a positive integer")
        if source.max_messages_per_minute > source.max_messages_per_hour:
            raise ValueError(
                "codex.max_messages_per_minute cannot exceed max_messages_per_hour"
            )
        if (
            not isinstance(source.max_concurrent_workers, int)
            or isinstance(source.max_concurrent_workers, bool)
            or not 1 <= source.max_concurrent_workers <= 4
        ):
            raise ValueError("codex.max_concurrent_workers must be between 1 and 4")
        return cls(
            **required_ids,
            channel_trust=source.channel_trust,
            working_directory=source.working_directory,
            state_dir=state_dir,
            codex_home=expected_codex_home,
            codex_bin=source.codex_bin,
            sandbox_mode=source.sandbox_mode,
            full_computer_access_accepted=source.full_computer_access_accepted,
            instructions_file=instructions_file,
            shared_skills_root=shared_skills_root,
            keychain_service=source.keychain_service,
            keychain_account=source.keychain_account,
            max_concurrent_workers=source.max_concurrent_workers,
            **limits,
        )

    @classmethod
    def from_env(cls) -> "Config":
        """Compatibility alias for the original deployment package."""

        return cls.from_threadkeep()
