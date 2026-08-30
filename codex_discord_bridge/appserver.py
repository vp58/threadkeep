from __future__ import annotations

import asyncio
import json
import os
import signal
import time
import tomllib
from pathlib import Path
from typing import Any

from .codex_auth import (
    ChatGPTAccountBinding,
    EXPECTED_SERVER_REQUEST_METHODS as EXPECTED_SERVER_REQUEST_METHODS,
    SUPPORTED_CODEX_VERSION,
    app_server_command,
    canonical_user_home,
    chatgpt_account_binding,
    child_environment,
    reject_filesystem_credentials,
)
from .codex_policy import (
    CONTROL_PLANE_DISABLED_FEATURES,
    BASE_INSTRUCTIONS,
    MODEL_ID,
    MODEL_PROVIDER,
    REASONING_EFFORT,
    SAFE_DISABLED_FEATURES,
    SAFE_PERMISSION_PROFILE,
    base_instructions,
    git_trust_roots,
    isolated_config_text,
    prepare_runtime_tmp,
    thread_config,
    validate_isolated_config,
)
from .process_supervisor import supervisor_command
from .shared_skills import (
    SharedSkillBinding,
    bind_shared_skills,
    validate_skill_bridge,
)
from .shared_hooks import (
    RuntimeHookBinding,
    bind_shared_hooks,
    validate_hook_bridge,
)
from .trusted_instructions import read_trusted_instructions
from conversations.vault_policy import VaultPolicySeal, validate_vault_policy_seal


class ProtocolError(RuntimeError):
    pass


CLIENT_CAPABILITIES = {"experimentalApi": True}
OFFICIAL_CHATGPT_BASE_URL = "https://chatgpt.com/backend-api/"
PROCESS_TERMINATION_TIMEOUT_SECONDS = 5


class CodexAppServer:
    """Protocol-safe JSONL client for the installed Codex app-server."""

    def __init__(
        self,
        codex_bin: Path,
        work_dir: Path,
        *,
        workspace_dir: Path | None = None,
        sandbox_mode: str | None = None,
        channel_trust: str = "public",
        full_computer_access_accepted: bool = False,
        codex_home: Path | None = None,
        instructions_file: Path | None = None,
        instructions_sha256: str | None = None,
        account_binding: str | None = None,
        shared_skills_root: Path | None = None,
        shared_skills_manifest_sha256: str | None = None,
        shared_hooks_manifest_sha256: str | None = None,
        vault_policy_seal: VaultPolicySeal | None = None,
        vault_root: Path | None = None,
        policy_runtime_root: Path | None = None,
    ):
        self.codex_bin = codex_bin
        self.work_dir = work_dir
        self.workspace_dir = workspace_dir or Path(
            os.environ.get("THREADKEEP_CODEX_WORKING_DIRECTORY", str(work_dir))
        )
        self.sandbox_mode = sandbox_mode or os.environ.get(
            "THREADKEEP_CODEX_SANDBOX_MODE", "workspace-write"
        )
        if self.sandbox_mode not in {"workspace-write", "danger-full-access"}:
            raise ValueError("unsupported Codex sandbox mode")
        self.safe_mode = self.sandbox_mode == "workspace-write"
        if channel_trust not in {"public", "owner_private"}:
            raise ValueError("unsupported Discord channel trust level")
        self.channel_trust = channel_trust
        if not self.safe_mode and not full_computer_access_accepted:
            raise RuntimeError(
                "danger-full-access requires explicit full computer access acceptance"
            )
        self.codex_home = codex_home or work_dir.parent / "home/.codex"
        self.worker_home = canonical_user_home()
        self.tmp_dir = self.workspace_dir / ".threadkeep-tmp"
        self.instructions_file = instructions_file
        self.instructions_sha256 = instructions_sha256
        self.account_binding = account_binding
        self.shared_skills_root = shared_skills_root or (
            self.workspace_dir / "x_System/Skills"
        )
        self.shared_skills_manifest_sha256 = shared_skills_manifest_sha256
        self.shared_hooks_manifest_sha256 = shared_hooks_manifest_sha256
        self.vault_policy_seal = vault_policy_seal
        self.vault_root = vault_root or self.shared_skills_root.parent.parent
        self.policy_runtime_root = policy_runtime_root or work_dir.parent
        self.process: asyncio.subprocess.Process | None = None
        self.next_id = 1
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.notifications: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.notification_buffer: list[dict[str, Any]] = []
        self.reader_task: asyncio.Task | None = None
        self.stderr_task: asyncio.Task | None = None
        self.send_lock = asyncio.Lock()
        self.loaded_threads: set[str] = set()
        self.active_turns: dict[str, str] = {}
        self.last_protocol_error: str | None = None
        self.stderr_error_count = 0
        self.chatgpt_plan_type: str | None = None
        self.hook_current_hashes: tuple[str, ...] | None = None
        self.hook_warning_count = 0

    def _permissions_profile(self) -> str:
        return (
            ":danger-full-access"
            if self.sandbox_mode == "danger-full-access"
            else SAFE_PERMISSION_PROFILE
        )

    def _base_instructions(self) -> str:
        vault_policy = self._bound_vault_policy()
        instructions = base_instructions(
            self.channel_trust,
            full_computer_access=not self.safe_mode,
        )
        if self.instructions_file is None:
            return instructions + "\n\nCanonical sealed Vault P0 policy:\n" + vault_policy
        trusted = read_trusted_instructions(
            self.instructions_file, workspace=self.workspace_dir
        )
        if (
            self.instructions_sha256 is not None
            and trusted.sha256 != self.instructions_sha256
        ):
            raise RuntimeError("configured Codex instructions changed after policy binding")
        return (
            instructions
            + "\n\nCanonical sealed Vault P0 policy:\n"
            + vault_policy
            + "\n\nAdditional trusted workspace instructions supplied by Threadkeep:\n"
            + trusted.text
        )

    def _bound_vault_policy(self) -> str:
        if self.vault_policy_seal is None:
            raise RuntimeError("sealed canonical Vault policy is required")
        return validate_vault_policy_seal(
            self.vault_policy_seal,
            vault_root=self.vault_root,
            runtime_root=self.policy_runtime_root,
            workspace=self.workspace_dir,
        )

    def _common_thread_policy(self) -> dict[str, Any]:
        return {
            "cwd": str(self.workspace_dir),
            "runtimeWorkspaceRoots": [str(self.workspace_dir)],
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "permissions": self._permissions_profile(),
            "baseInstructions": self._base_instructions(),
            "model": MODEL_ID,
            "modelProvider": MODEL_PROVIDER,
            "config": thread_config(self.safe_mode),
        }

    def _start_policy(self) -> dict[str, Any]:
        return {
            **self._common_thread_policy(),
            "allowProviderModelFallback": False,
            "dynamicTools": [],
        }

    def _resume_policy(self) -> dict[str, Any]:
        return self._common_thread_policy()

    def _turn_policy(self) -> dict[str, Any]:
        policy: dict[str, Any] = {
            "cwd": str(self.workspace_dir),
            "runtimeWorkspaceRoots": [str(self.workspace_dir)],
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "permissions": self._permissions_profile(),
            "model": MODEL_ID,
            "effort": REASONING_EFFORT,
        }
        return policy

    async def require_bound_chatgpt_principal(self) -> ChatGPTAccountBinding:
        reject_filesystem_credentials(self.codex_home)
        result = await self.request("account/read", {"refreshToken": False})
        try:
            observed = chatgpt_account_binding(result)
        except RuntimeError as exc:
            raise ProtocolError(str(exc)) from exc
        if self.account_binding is None:
            self.account_binding = observed.digest
        elif observed.digest != self.account_binding:
            raise RuntimeError("isolated ChatGPT principal changed after policy binding")
        self.chatgpt_plan_type = observed.plan_type
        reject_filesystem_credentials(self.codex_home)
        return observed

    async def _require_model(self) -> None:
        cursor: str | None = None
        matches: list[dict[str, Any]] = []
        while True:
            result = await self.request(
                "model/list",
                {"cursor": cursor, "includeHidden": True, "limit": 100},
            )
            data = result.get("data")
            if not isinstance(data, list):
                raise ProtocolError("model/list returned malformed data")
            for item in data:
                if not isinstance(item, dict):
                    raise ProtocolError("model/list returned a malformed model")
                if item.get("id") == MODEL_ID or item.get("model") == MODEL_ID:
                    matches.append(item)
            cursor = result.get("nextCursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or not cursor:
                raise ProtocolError("model/list returned an invalid cursor")
        if len(matches) != 1:
            raise ProtocolError("the pinned Codex model is missing or ambiguous")
        model = matches[0]
        if model.get("id") != MODEL_ID or model.get("model") != MODEL_ID:
            raise ProtocolError("the pinned Codex model identity changed")
        efforts = model.get("supportedReasoningEfforts")
        if not isinstance(efforts, list) or REASONING_EFFORT not in {
            item.get("reasoningEffort")
            for item in efforts
            if isinstance(item, dict)
        }:
            raise ProtocolError("the pinned Codex model no longer supports Ultra")

    async def _require_permission_profile(self) -> None:
        cursor: str | None = None
        matches: list[dict[str, Any]] = []
        while True:
            result = await self.request(
                "permissionProfile/list",
                {"cwd": str(self.workspace_dir), "cursor": cursor, "limit": 100},
            )
            data = result.get("data")
            if not isinstance(data, list):
                raise ProtocolError("permissionProfile/list returned malformed data")
            for item in data:
                if not isinstance(item, dict):
                    raise ProtocolError(
                        "permissionProfile/list returned a malformed profile"
                    )
                if item.get("id") == SAFE_PERMISSION_PROFILE:
                    matches.append(item)
            cursor = result.get("nextCursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or not cursor:
                raise ProtocolError("permissionProfile/list returned an invalid cursor")
        if len(matches) != 1 or matches[0].get("allowed") is not True:
            raise ProtocolError("the reviewed Threadkeep permission profile is unavailable")

    async def _require_effective_config(self) -> None:
        result = await self.request(
            "config/read", {"cwd": str(self.workspace_dir), "includeLayers": True}
        )
        config = result.get("config")
        if not isinstance(config, dict):
            raise ProtocolError("config/read returned malformed effective config")
        required = {
            "forced_login_method": "chatgpt",
            "cli_auth_credentials_store": "keyring",
            "model": MODEL_ID,
            "model_provider": MODEL_PROVIDER,
            "model_reasoning_effort": REASONING_EFFORT,
            "project_doc_max_bytes": 0,
            "project_doc_fallback_filenames": [],
        }
        if any(config.get(key) != value for key, value in required.items()):
            raise ProtocolError("Codex effective identity or model config changed")
        layers = result.get("layers")
        if not isinstance(layers, list):
            raise ProtocolError("config/read omitted config layers")
        expected_config = str((self.codex_home / "config.toml").resolve())
        session_config: dict[str, Any] = {
            "features": {
                feature: False
                for feature in (
                    SAFE_DISABLED_FEATURES
                    if self.safe_mode
                    else CONTROL_PLANE_DISABLED_FEATURES
                )
            },
            "project_doc_fallback_filenames": [],
            "project_doc_max_bytes": 0,
        }
        session_config["features"]["hooks"] = True
        if self.safe_mode:
            session_config["web_search"] = "disabled"
        user_config = tomllib.loads(
            isolated_config_text(self.workspace_dir, self.safe_mode)
        )
        if len(layers) < 3:
            raise ProtocolError("Codex loaded an unexpected config layer")

        def require_layer(
            layer: object,
            expected_source: dict[str, Any],
            expected_layer_config: dict[str, Any],
        ) -> None:
            if not isinstance(layer, dict) or set(layer) != {
                "name",
                "version",
                "config",
            }:
                raise ProtocolError("config/read returned a malformed layer")
            version = layer.get("version")
            if (
                not isinstance(version, str)
                or len(version) != 71
                or not version.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in version[7:])
            ):
                raise ProtocolError("config/read returned a malformed layer version")
            if layer.get("name") != expected_source:
                raise ProtocolError("Codex loaded an unexpected config layer source")
            if layer.get("config") != expected_layer_config:
                raise ProtocolError("Codex config layer content changed")

        require_layer(layers[0], {"type": "sessionFlags"}, session_config)
        require_layer(
            layers[-2],
            {"type": "user", "file": expected_config, "profile": None},
            user_config,
        )
        require_layer(
            layers[-1],
            {"type": "system", "file": "/etc/codex/config.toml"},
            {},
        )

        allowed_roots = git_trust_roots(self.workspace_dir)
        allowed_parents = {self.workspace_dir, *self.workspace_dir.parents}
        seen_project_folders: set[Path] = set()
        for project_layer in layers[1:-2]:
            if not isinstance(project_layer, dict) or set(project_layer) != {
                "name",
                "version",
                "config",
                "disabledReason",
            }:
                raise ProtocolError("Codex loaded an unexpected config layer")
            source = project_layer.get("name")
            disabled_reason = project_layer.get("disabledReason")
            if (
                not isinstance(source, dict)
                or set(source) != {"type", "dotCodexFolder"}
                or source.get("type") != "project"
                or not isinstance(disabled_reason, str)
                or not disabled_reason.strip()
                or not isinstance(project_layer.get("config"), dict)
            ):
                raise ProtocolError("Codex loaded an active or malformed project layer")
            version = project_layer.get("version")
            if (
                not isinstance(version, str)
                or len(version) != 71
                or not version.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in version[7:])
            ):
                raise ProtocolError("config/read returned a malformed layer version")
            raw_folder = source.get("dotCodexFolder")
            if not isinstance(raw_folder, str):
                raise ProtocolError("Codex project layer path is malformed")
            folder = Path(raw_folder)
            try:
                canonical_folder = folder.resolve(strict=True)
            except OSError as exc:
                raise ProtocolError("Codex project layer path is unavailable") from exc
            if (
                not folder.is_absolute()
                or folder != canonical_folder
                or folder.name != ".codex"
                or not folder.is_dir()
                or folder.is_symlink()
                or folder.parent not in allowed_parents
                or not any(folder.parent.is_relative_to(root) for root in allowed_roots)
                or folder in seen_project_folders
            ):
                raise ProtocolError("Codex project layer escaped the untrusted workspace")
            seen_project_folders.add(folder)
        if config.get("openai_base_url") is not None or config.get(
            "chatgpt_base_url"
        ) != OFFICIAL_CHATGPT_BASE_URL:
            raise ProtocolError("Codex effective OpenAI endpoint changed")
        for key in (
            "model_providers",
            "hooks",
            "exec_policy",
            "notify",
            "otel",
            "instructions",
            "developer_instructions",
            "model_instructions_file",
        ):
            if config.get(key) not in (None, {}, []):
                raise ProtocolError(f"Codex effective control-plane config set {key}")
        expected_shell_environment_policy = {
            "inherit": None,
            "ignore_default_excludes": None,
            "exclude": None,
            "include_only": None,
            "set": None,
            "experimental_use_profile": None,
            "filters": None,
        }
        if config.get("shell_environment_policy") != expected_shell_environment_policy:
            raise ProtocolError("Codex effective shell environment policy changed")
        expected_effective_profile = {
            "description": "Threadkeep workspace-only policy",
            "extends": ":workspace",
            "filesystem": {
                ":minimal": "read",
                ":root": "deny",
                ":slash_tmp": "deny",
                ":tmpdir": "deny",
                "glob_scan_max_depth": None,
            },
            "network": {
                "allow_local_binding": None,
                "allow_upstream_proxy": None,
                "dangerously_allow_all_unix_sockets": None,
                "dangerously_allow_non_loopback_proxy": None,
                "domains": None,
                "enable_socks5": None,
                "enable_socks5_udp": None,
                "enabled": False,
                "mitm": None,
                "mode": None,
                "proxy_url": None,
                "socks_url": None,
                "unix_sockets": None,
            },
            "workspace_roots": None,
        }
        if config.get("default_permissions") != SAFE_PERMISSION_PROFILE or config.get(
            "permissions"
        ) != {SAFE_PERMISSION_PROFILE: expected_effective_profile}:
            raise ProtocolError("Codex effective permission profile changed")
        features = config.get("features")
        required_disabled = (
            SAFE_DISABLED_FEATURES
            if self.safe_mode
            else CONTROL_PLANE_DISABLED_FEATURES
        )
        if not isinstance(features, dict) or any(
            features.get(feature) is not False for feature in required_disabled
        ) or features.get("hooks") is not True:
            raise ProtocolError("Codex effective control-plane feature flags changed")
        for key in ("mcp_servers", "apps"):
            if config.get(key) not in (None, {}):
                raise ProtocolError(f"Codex unexpectedly enabled {key}")
        skills = config.get("skills")
        if (
            not isinstance(skills, dict)
            or skills.get("include_instructions") is not False
            or not isinstance(skills.get("bundled"), dict)
            or skills["bundled"].get("enabled") is not False
        ):
            raise ProtocolError("Codex effective skill config changed")
        if self.safe_mode:
            if config.get("web_search") != "disabled" or config.get(
                "sandbox_mode"
            ) is not None:
                raise ProtocolError("safe mode effective sandbox or web config changed")
            for key in ("browser_use", "computer_use"):
                if config.get(key) not in (None, {}):
                    raise ProtocolError(f"safe mode unexpectedly enabled {key}")

    async def _require_no_config_requirements(self) -> None:
        result = await self.request("configRequirements/read", None)
        if set(result) != {"requirements"} or result.get("requirements") is not None:
            raise ProtocolError("Codex loaded administrator requirements")

    def _bound_shared_hooks(self) -> RuntimeHookBinding:
        sources = bind_shared_hooks(
            self.vault_root,
            workspace=self.workspace_dir,
        )
        return validate_hook_bridge(
            self.codex_home,
            sources,
            expected_manifest_sha256=self.shared_hooks_manifest_sha256,
        )

    async def _require_shared_hooks(self) -> RuntimeHookBinding:
        binding = self._bound_shared_hooks()
        result = await self.request(
            "hooks/list", {"cwds": [str(self.workspace_dir)]}
        )
        data = result.get("data")
        if not isinstance(data, list) or len(data) != 1:
            raise ProtocolError("hooks/list returned an unexpected workspace set")
        entry = data[0]
        if not isinstance(entry, dict) or set(entry) != {
            "cwd",
            "errors",
            "hooks",
            "warnings",
        }:
            raise ProtocolError("hooks/list returned a malformed workspace entry")
        if (
            entry.get("cwd") != str(self.workspace_dir)
            or entry.get("errors") != []
            or entry.get("warnings") != []
            or not isinstance(entry.get("hooks"), list)
            or len(entry["hooks"]) != len(binding.definitions)
            or self.hook_warning_count
        ):
            raise ProtocolError("Codex reported a hook discovery or config warning")
        hooks_path = binding.hooks_path.resolve(strict=True)
        current_hashes: list[str] = []
        expected_keys = {
            "additionalContextLimit",
            "async",
            "command",
            "currentHash",
            "displayOrder",
            "enabled",
            "eventName",
            "handlerType",
            "isManaged",
            "key",
            "matcher",
            "pluginId",
            "source",
            "sourcePath",
            "statusMessage",
            "timeoutSec",
            "trustStatus",
        }
        for index, (observed, expected) in enumerate(
            zip(entry["hooks"], binding.definitions, strict=True)
        ):
            if not isinstance(observed, dict) or set(observed) != expected_keys:
                raise ProtocolError("hooks/list returned malformed hook metadata")
            current_hash = observed.get("currentHash")
            expected_key = f"{hooks_path}:pre_tool_use:{index}:0"
            if (
                observed.get("key") != expected_key
                or observed.get("eventName") != "preToolUse"
                or observed.get("handlerType") != "command"
                or observed.get("command") != expected.command
                or observed.get("async") is not False
                or observed.get("matcher") != expected.matcher
                or observed.get("timeoutSec") != expected.timeout_seconds
                or observed.get("statusMessage") != expected.status_message
                or observed.get("additionalContextLimit") is not None
                or observed.get("sourcePath") != str(hooks_path)
                or observed.get("source") != "user"
                or observed.get("pluginId") is not None
                or observed.get("displayOrder") != index
                or observed.get("enabled") is not True
                or observed.get("isManaged") is not False
                or observed.get("trustStatus") != "untrusted"
                or not isinstance(current_hash, str)
                or len(current_hash) != 71
                or not current_hash.startswith("sha256:")
                or any(
                    character not in "0123456789abcdef"
                    for character in current_hash.removeprefix("sha256:")
                )
            ):
                raise ProtocolError("Codex loaded an unexpected or inactive hook")
            current_hashes.append(current_hash)
        observed_hashes = tuple(current_hashes)
        if self.hook_current_hashes is None:
            self.hook_current_hashes = observed_hashes
        elif self.hook_current_hashes != observed_hashes:
            raise ProtocolError("Codex hook definition hash changed after startup")
        self._bound_shared_hooks()
        return binding

    def _bound_shared_skills(self) -> SharedSkillBinding:
        binding = bind_shared_skills(
            self.shared_skills_root,
            expected_manifest_sha256=self.shared_skills_manifest_sha256,
        )
        validate_skill_bridge(self.codex_home, binding)
        return binding

    async def _require_shared_skills(self) -> SharedSkillBinding:
        binding = self._bound_shared_skills()
        result = await self.request(
            "skills/list", {"cwds": [str(self.workspace_dir)], "forceReload": True}
        )
        data = result.get("data")
        if not isinstance(data, list) or len(data) != 1:
            raise ProtocolError("skills/list returned an unexpected workspace set")
        entry = data[0]
        if not isinstance(entry, dict) or entry.get("cwd") != str(self.workspace_dir):
            raise ProtocolError("skills/list returned the wrong workspace")
        if entry.get("errors") != [] or not isinstance(entry.get("skills"), list):
            raise ProtocolError("Codex reported a skill discovery error")
        expected = {
            (skill.name, str(skill.path)): skill for skill in binding.skills
        }
        observed: set[tuple[str, str]] = set()
        for skill in entry["skills"]:
            if not isinstance(skill, dict):
                raise ProtocolError("skills/list returned a malformed skill")
            name = skill.get("name")
            path = skill.get("path")
            key = (name, path)
            if (
                not isinstance(name, str)
                or not isinstance(path, str)
                or skill.get("enabled") is not True
                or key not in expected
                or key in observed
            ):
                raise ProtocolError("Codex exposed an unexpected or disabled skill")
            dependencies = skill.get("dependencies")
            if dependencies not in (None, {}):
                if not isinstance(dependencies, dict):
                    raise ProtocolError("shared skill dependencies are malformed")
                tools = dependencies.get("tools")
                if tools not in (None, []):
                    raise ProtocolError("shared skills must not declare tool dependencies")
            observed.add(key)
        if observed != set(expected):
            raise ProtocolError("Codex omitted a required canonical shared skill")
        self._bound_shared_skills()
        return binding

    async def _require_no_mcp(self, thread_id: str) -> None:
        cursor: str | None = None
        while True:
            result = await self.request(
                "mcpServerStatus/list",
                {"threadId": thread_id, "cursor": cursor, "limit": 100},
            )
            data = result.get("data")
            if not isinstance(data, list) or data:
                raise ProtocolError("Codex exposed an MCP server")
            cursor = result.get("nextCursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or not cursor:
                raise ProtocolError("mcpServerStatus/list returned an invalid cursor")

    @staticmethod
    def _resolved_response_path(value: Any, label: str) -> Path:
        if not isinstance(value, str):
            raise ProtocolError(f"{label} is malformed")
        try:
            return Path(value).resolve(strict=True)
        except OSError as exc:
            raise ProtocolError(f"{label} cannot be resolved") from exc

    def _validate_thread_response(
        self,
        result: dict[str, Any],
        *,
        ephemeral: bool,
        expected_thread_id: str | None = None,
    ) -> str:
        workspace = self.workspace_dir.resolve(strict=True)
        if (
            result.get("approvalPolicy") != "never"
            or result.get("approvalsReviewer") != "user"
            or result.get("model") != MODEL_ID
            or result.get("modelProvider") != MODEL_PROVIDER
            or result.get("reasoningEffort") != REASONING_EFFORT
            or self._resolved_response_path(result.get("cwd"), "thread cwd")
            != workspace
        ):
            raise ProtocolError("thread response did not preserve the requested policy")
        roots = result.get("runtimeWorkspaceRoots")
        if not isinstance(roots, list) or len(roots) != 1:
            raise ProtocolError("thread response returned unexpected workspace roots")
        if self._resolved_response_path(roots[0], "runtime workspace root") != workspace:
            raise ProtocolError("thread response returned the wrong workspace root")
        profile = result.get("activePermissionProfile")
        if not isinstance(profile, dict) or profile.get("id") != self._permissions_profile():
            raise ProtocolError("thread response returned the wrong permission profile")
        sandbox = result.get("sandbox")
        if self.safe_mode:
            if profile.get("extends") != ":workspace" or sandbox != {
                "type": "workspaceWrite",
                "writableRoots": [],
                "networkAccess": False,
                "excludeTmpdirEnvVar": True,
                "excludeSlashTmp": True,
            }:
                raise ProtocolError("thread response weakened the workspace-only sandbox")
        elif profile.get("extends") is not None or sandbox != {
            "type": "dangerFullAccess"
        }:
            raise ProtocolError("thread response did not preserve full computer access")
        sources = result.get("instructionSources")
        if sources != []:
            raise ProtocolError("thread loaded an untrusted instruction source")
        thread = result.get("thread")
        if not isinstance(thread, dict):
            raise ProtocolError("thread response omitted the thread")
        thread_id = thread.get("id")
        expected_cli = SUPPORTED_CODEX_VERSION.removeprefix("codex-cli ")
        if (
            not isinstance(thread_id, str)
            or not thread_id
            or (expected_thread_id is not None and thread_id != expected_thread_id)
            or thread.get("modelProvider") != MODEL_PROVIDER
            or thread.get("cliVersion") != expected_cli
            or thread.get("ephemeral") is not ephemeral
            or self._resolved_response_path(thread.get("cwd"), "persisted thread cwd")
            != workspace
        ):
            raise ProtocolError("thread response returned malformed persisted metadata")
        return thread_id

    async def start(self) -> None:
        self.work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.workspace_dir = self.workspace_dir.resolve(strict=True)
        self.tmp_dir = self.workspace_dir / ".threadkeep-tmp"
        validate_isolated_config(self.codex_home, self.workspace_dir, self.safe_mode)
        reject_filesystem_credentials(self.codex_home)
        self._bound_vault_policy()
        self._bound_shared_hooks()
        if self.instructions_file is not None and not self.instructions_file.is_file():
            raise RuntimeError("configured Codex instructions file does not exist")
        self.tmp_dir = prepare_runtime_tmp(self.workspace_dir)
        self.work_dir.chmod(0o700)
        try:
            command = app_server_command(
                self.codex_bin,
                self.worker_home,
                codex_home=self.codex_home,
                tmp_dir=self.tmp_dir,
            )
            disabled_features = (
                SAFE_DISABLED_FEATURES
                if self.safe_mode
                else CONTROL_PLANE_DISABLED_FEATURES
            )
            command.extend(("--enable", "hooks"))
            for feature in disabled_features:
                command.extend(("--disable", feature))
            command.extend(
                (
                    "-c",
                    "project_doc_max_bytes=0",
                    "-c",
                    "project_doc_fallback_filenames=[]",
                )
            )
            if self.safe_mode:
                command.extend(("-c", 'web_search="disabled"'))
            command = supervisor_command(command)
            self.process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_environment(
                    self.worker_home,
                    codex_home=self.codex_home,
                    tmp_dir=self.tmp_dir,
                ),
                cwd=self.workspace_dir,
                limit=10_000_000,
                start_new_session=True,
            )
            self.reader_task = asyncio.create_task(
                self._reader_loop(), name="codex-appserver-reader"
            )
            self.stderr_task = asyncio.create_task(
                self._stderr_loop(), name="codex-appserver-stderr"
            )
            await self.request(
                "initialize",
                {
                    "clientInfo": {
                        "name": "codex-discord-bridge",
                        "version": "0.2.0",
                    },
                    "capabilities": CLIENT_CAPABILITIES,
                },
            )
            await self.notify("initialized", {})
            await self.require_bound_chatgpt_principal()
            await self._require_no_config_requirements()
            await self._require_effective_config()
            await self._require_model()
            await self._require_permission_profile()
            await self._require_shared_hooks()
            await self._require_shared_skills()
            self._bound_vault_policy()
            self._bound_shared_hooks()
            await self.require_bound_chatgpt_principal()
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        if self.process and self.process.returncode is None:
            # The supervisor stays leader of this dedicated process group until
            # every other member exits. This keeps the PGID reserved throughout
            # TERM and any required KILL escalation.
            process_group = self.process.pid
            try:
                os.killpg(process_group, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(
                    self.process.wait(), PROCESS_TERMINATION_TIMEOUT_SECONDS
                )
            except TimeoutError:
                try:
                    # The group leader is still alive, so its process-group ID
                    # cannot have been recycled for an unrelated process.
                    os.killpg(process_group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await self.process.wait()
        self.process = None
        for task in (self.reader_task, self.stderr_task):
            if task and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (self.reader_task, self.stderr_task) if task),
            return_exceptions=True,
        )
        self.reader_task = None
        self.stderr_task = None

    async def _stderr_loop(self) -> None:
        if not self.process or not self.process.stderr:
            return
        while line := await self.process.stderr.readline():
            if b"error" in line.lower() or b"fatal" in line.lower():
                self.stderr_error_count += 1
                await self.notifications.put({"method": "_appserver/stderr", "params": {}})

    async def _reader_loop(self) -> None:
        try:
            if not self.process or not self.process.stdout:
                raise ProtocolError("app-server has no stdout")
            while line := await self.process.stdout.readline():
                try:
                    message = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ProtocolError("app-server emitted invalid JSON") from exc
                if not isinstance(message, dict):
                    raise ProtocolError("app-server emitted a non-object")
                request_id = message.get("id")
                if request_id is not None and "method" in message:
                    await self._handle_server_request(message)
                elif request_id is not None:
                    future = self.pending.get(request_id)
                    if future and not future.done():
                        future.set_result(message)
                elif "method" in message:
                    if message.get("method") in {"configWarning", "warning"}:
                        try:
                            warning_text = json.dumps(
                                message.get("params", {}),
                                sort_keys=True,
                                ensure_ascii=True,
                            ).casefold()
                        except (TypeError, ValueError):
                            warning_text = "hook"
                        if "hook" in warning_text:
                            self.hook_warning_count += 1
                    await self.notifications.put(message)
            raise ProtocolError("app-server closed its output")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.last_protocol_error = type(exc).__name__
            for future in list(self.pending.values()):
                if not future.done():
                    future.set_exception(exc)
            await self.notifications.put(
                {"method": "_protocol/error", "params": {"message": type(exc).__name__}}
            )

    async def send(self, payload: dict[str, Any]) -> None:
        if not self.process or not self.process.stdin or getattr(self.process, "returncode", None) is not None:
            raise ProtocolError("app-server is not running")
        encoded = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
        async with self.send_lock:
            self.process.stdin.write(encoded)
            await self.process.stdin.drain()

    async def notify(self, method: str, params: dict[str, Any]) -> None:
        await self.send({"method": method, "params": params})

    async def read(self, timeout: int = 120) -> dict[str, Any]:
        """Read one message for isolated protocol tests before the dispatcher starts."""
        if not self.process or not self.process.stdout:
            raise ProtocolError("app-server is not running")
        line = await asyncio.wait_for(self.process.stdout.readline(), timeout)
        if not line:
            raise ProtocolError("app-server closed its output")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError("app-server emitted invalid JSON") from exc
        if not isinstance(message, dict):
            raise ProtocolError("app-server emitted a non-object")
        return message

    async def request(
        self,
        method: str,
        params: dict[str, Any] | None,
        timeout: int = 60,
    ) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[request_id] = future
        try:
            await self.send({"id": request_id, "method": method, "params": params})
            message = await asyncio.wait_for(future, timeout)
        finally:
            self.pending.pop(request_id, None)
        if "error" in message:
            error = message["error"]
            code = error.get("code") if isinstance(error, dict) else None
            safe_code = code if isinstance(code, int) and not isinstance(code, bool) else "unknown"
            raise ProtocolError(f"{method} failed with code {safe_code}")
        result = message.get("result", {})
        if not isinstance(result, dict):
            raise ProtocolError(f"{method} returned a non-object result")
        return result

    async def _handle_server_request(self, message: dict[str, Any]) -> None:
        request_id = message["id"]
        method = message.get("method")
        if method in {
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
        }:
            await self.send({"id": request_id, "result": {"decision": "decline"}})
            return
        if method in {"applyPatchApproval", "execCommandApproval"}:
            await self.send({"id": request_id, "result": {"decision": "abort"}})
            return
        if method == "item/tool/requestUserInput":
            await self.send({"id": request_id, "result": {"answers": {}}})
            return
        if method == "mcpServer/elicitation/request":
            await self.send(
                {"id": request_id, "result": {"action": "decline", "content": None, "_meta": None}}
            )
            return
        if method == "item/permissions/requestApproval":
            await self.send(
                {
                    "id": request_id,
                    "result": {
                        "permissions": {},
                        "scope": "turn",
                        "strictAutoReview": False,
                    },
                }
            )
            return
        if method == "item/tool/call":
            await self.send({"id": request_id, "result": {"contentItems": [], "success": False}})
            return
        if method == "currentTime/read":
            await self.send({"id": request_id, "result": {"currentTimeAt": int(time.time())}})
            return
        if method == "account/chatgptAuthTokens/refresh":
            await self.send(
                {
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": "externally managed ChatGPT tokens are disabled",
                    },
                }
            )
            raise ProtocolError(
                "unexpected externally managed ChatGPT token refresh request"
            )
        if method == "attestation/generate":
            await self.send(
                {
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": "client attestation is unavailable",
                    },
                }
            )
            raise ProtocolError("unexpected client attestation request")
        await self.send(
            {
                "id": request_id,
                "error": {"code": -32601, "message": f"unsupported server request: {method}"},
            }
        )
        raise ProtocolError(f"unsupported server request: {method}")

    async def deny_server_request(self, message: dict[str, Any]) -> None:
        """Compatibility wrapper retained for focused unit tests."""
        await self._handle_server_request(message)

    async def create_thread(self) -> str:
        validate_isolated_config(self.codex_home, self.workspace_dir, self.safe_mode)
        self._bound_vault_policy()
        self._bound_shared_hooks()
        await self.require_bound_chatgpt_principal()
        result = await self.request(
            "thread/start", {**self._start_policy(), "ephemeral": False}
        )
        thread_id = self._validate_thread_response(result, ephemeral=False)
        await self._require_no_config_requirements()
        await self._require_effective_config()
        await self._require_shared_hooks()
        await self._require_shared_skills()
        await self._require_no_mcp(thread_id)
        self._bound_vault_policy()
        self._bound_shared_hooks()
        await self.require_bound_chatgpt_principal()
        self.loaded_threads.add(thread_id)
        return thread_id

    async def probe_policy(self) -> None:
        """Create no turn and prove the effective policy before installation."""

        validate_isolated_config(self.codex_home, self.workspace_dir, self.safe_mode)
        self._bound_vault_policy()
        self._bound_shared_hooks()
        await self.require_bound_chatgpt_principal()
        result = await self.request(
            "thread/start", {**self._start_policy(), "ephemeral": True}
        )
        thread_id = self._validate_thread_response(result, ephemeral=True)
        await self._require_no_config_requirements()
        await self._require_effective_config()
        await self._require_shared_hooks()
        await self._require_shared_skills()
        await self._require_no_mcp(thread_id)
        await self.request("thread/unsubscribe", {"threadId": thread_id}, timeout=10)
        self._bound_vault_policy()
        self._bound_shared_hooks()
        await self.require_bound_chatgpt_principal()

    async def ensure_thread(self, thread_id: str) -> None:
        self._bound_vault_policy()
        self._bound_shared_hooks()
        await self.require_bound_chatgpt_principal()
        if thread_id in self.loaded_threads:
            return
        result = await self.request(
            "thread/resume",
            {"threadId": thread_id, **self._resume_policy(), "excludeTurns": True},
        )
        resumed = self._validate_thread_response(
            result, ephemeral=False, expected_thread_id=thread_id
        )
        await self._require_no_config_requirements()
        await self._require_effective_config()
        await self._require_shared_hooks()
        await self._require_shared_skills()
        await self._require_no_mcp(resumed)
        self._bound_vault_policy()
        self._bound_shared_hooks()
        await self.require_bound_chatgpt_principal()
        self.loaded_threads.add(thread_id)

    async def interrupt_turn(self, thread_id: str, turn_id: str) -> None:
        try:
            await self.request(
                "turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=10
            )
        except Exception:
            await self.close()

    @staticmethod
    def _notification_matches(
        message: dict[str, Any], thread_id: str, turn_id: str
    ) -> bool:
        if message.get("method") == "_protocol/error":
            return True
        params = message.get("params", {})
        message_thread = params.get("threadId")
        message_turn = params.get("turnId") or params.get("turn", {}).get("id")
        if message.get("method") in {"item/completed", "turn/completed"}:
            return message_thread == thread_id and message_turn == turn_id
        return message_thread in {None, thread_id} and message_turn in {None, turn_id}

    async def _next_notification(
        self, thread_id: str, turn_id: str, timeout: float
    ) -> dict[str, Any]:
        for index, message in enumerate(self.notification_buffer):
            if self._notification_matches(message, thread_id, turn_id):
                return self.notification_buffer.pop(index)
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Codex notification wait exceeded its deadline")
            message = await asyncio.wait_for(self.notifications.get(), remaining)
            if self._notification_matches(message, thread_id, turn_id):
                return message
            self.notification_buffer.append(message)
            if len(self.notification_buffer) > 10_000:
                raise ProtocolError("app-server notification buffer exceeded its safety limit")

    def _validate_hook_run(
        self,
        params: object,
        *,
        thread_id: str,
        turn_id: str,
        expected_status: str,
    ) -> tuple[str, int, dict[str, Any]]:
        if not isinstance(params, dict):
            raise ProtocolError("Codex emitted malformed hook notification parameters")
        if params.get("threadId") != thread_id or params.get("turnId") != turn_id:
            raise ProtocolError("Codex hook notification targeted the wrong turn")
        run = params.get("run")
        if not isinstance(run, dict):
            raise ProtocolError("Codex hook notification omitted its run")
        allowed_keys = {
            "completedAt",
            "displayOrder",
            "durationMs",
            "entries",
            "eventName",
            "executionMode",
            "handlerType",
            "id",
            "scope",
            "source",
            "sourcePath",
            "startedAt",
            "status",
            "statusMessage",
        }
        if not set(run).issubset(allowed_keys):
            raise ProtocolError("Codex hook notification contains unexpected metadata")
        display_order = run.get("displayOrder")
        binding = self._bound_shared_hooks()
        if (
            not isinstance(display_order, int)
            or isinstance(display_order, bool)
            or not 0 <= display_order < len(binding.definitions)
        ):
            raise ProtocolError("Codex hook notification has an unknown display order")
        expected = binding.definitions[display_order]
        run_id = run.get("id")
        entries = run.get("entries")
        if (
            not isinstance(run_id, str)
            or not run_id
            or run.get("eventName") != "preToolUse"
            or run.get("executionMode") != "sync"
            or run.get("handlerType") != "command"
            or run.get("scope") != "turn"
            or run.get("source") != "user"
            or run.get("sourcePath")
            != str((self.codex_home / "hooks.json").resolve(strict=True))
            or run.get("status") != expected_status
            or run.get("statusMessage") != expected.status_message
            or not isinstance(run.get("startedAt"), int)
            or isinstance(run.get("startedAt"), bool)
            or not isinstance(entries, list)
        ):
            raise ProtocolError("Codex emitted an unexpected hook run")
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"kind", "text"}
                or entry.get("kind")
                not in {"warning", "stop", "feedback", "context", "error"}
                or not isinstance(entry.get("text"), str)
                or entry.get("kind") in {"error", "warning"}
            ):
                raise ProtocolError("Codex hook run reported an error or malformed output")
        return run_id, display_order, run

    async def turn(
        self, thread_id: str, text: str, client_message_id: str, timeout: int = 3600
    ) -> str:
        validate_isolated_config(self.codex_home, self.workspace_dir, self.safe_mode)
        self._bound_vault_policy()
        await self.require_bound_chatgpt_principal()
        await self.ensure_thread(thread_id)
        await self._require_no_config_requirements()
        await self._require_effective_config()
        await self._require_shared_hooks()
        binding = await self._require_shared_skills()
        result = await self.request(
            "turn/start",
            {
                "threadId": thread_id,
                "clientUserMessageId": client_message_id,
                "input": binding.input_items(text),
                **self._turn_policy(),
            },
        )
        turn_id = result.get("turn", {}).get("id")
        if not turn_id:
            raise ProtocolError("turn/start returned no turn ID")
        self.active_turns[thread_id] = turn_id
        try:
            self._bound_shared_skills()
        except BaseException:
            await self.interrupt_turn(thread_id, turn_id)
            raise
        answer: str | None = None
        active_hook_runs: dict[str, tuple[int, dict[str, Any]]] = {}
        hook_credits = [0, 0, 0]
        deadline = asyncio.get_running_loop().time() + timeout
        try:
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError("Codex turn exceeded its deadline")
                message = await self._next_notification(thread_id, turn_id, remaining)
                method = message.get("method")
                params = message.get("params", {})
                if method == "_protocol/error":
                    raise ProtocolError(
                        f"app-server protocol reader failed: {self.last_protocol_error or 'unknown'}"
                    )
                if method == "hook/started":
                    run_id, display_order, run = self._validate_hook_run(
                        params,
                        thread_id=thread_id,
                        turn_id=turn_id,
                        expected_status="running",
                    )
                    if run_id in active_hook_runs:
                        raise ProtocolError("Codex emitted a duplicate hook start")
                    active_hook_runs[run_id] = (display_order, run)
                elif method == "hook/completed":
                    raw_run = params.get("run") if isinstance(params, dict) else None
                    status = raw_run.get("status") if isinstance(raw_run, dict) else None
                    if status not in {"completed", "blocked"}:
                        raise ProtocolError("Codex hook failed, stopped, or returned an unknown status")
                    run_id, display_order, run = self._validate_hook_run(
                        params,
                        thread_id=thread_id,
                        turn_id=turn_id,
                        expected_status=status,
                    )
                    started = active_hook_runs.pop(run_id, None)
                    if started is None or started[0] != display_order:
                        raise ProtocolError("Codex hook completion has no matching start")
                    started_run = started[1]
                    for key in (
                        "displayOrder",
                        "eventName",
                        "executionMode",
                        "handlerType",
                        "id",
                        "scope",
                        "source",
                        "sourcePath",
                        "startedAt",
                        "statusMessage",
                    ):
                        if started_run.get(key) != run.get(key):
                            raise ProtocolError("Codex hook metadata changed during execution")
                    if (
                        not isinstance(run.get("completedAt"), int)
                        or isinstance(run.get("completedAt"), bool)
                        or not isinstance(run.get("durationMs"), int)
                        or isinstance(run.get("durationMs"), bool)
                        or run["durationMs"] < 0
                    ):
                        raise ProtocolError("Codex hook completion timing is malformed")
                    if status == "completed":
                        hook_credits[display_order] += 1
                elif method == "item/started":
                    item = params.get("item", {})
                    item_type = item.get("type") if isinstance(item, dict) else None
                    required_orders: tuple[int, ...] = ()
                    if item_type == "commandExecution":
                        required_orders = (0, 1, 2)
                    elif item_type == "fileChange":
                        required_orders = (1,)
                    for display_order in required_orders:
                        if hook_credits[display_order] < 1:
                            raise ProtocolError(
                                "Codex started a local tool without every expected hook"
                            )
                        hook_credits[display_order] -= 1
                elif method == "item/completed":
                    item = params.get("item", {})
                    if item.get("type") == "agentMessage" and item.get("text"):
                        answer = item["text"]
                elif method == "error" and not params.get("willRetry"):
                    raise ProtocolError("turn failed with a non-retryable App Server error")
                elif method in {"configWarning", "warning"}:
                    try:
                        warning_text = json.dumps(
                            params, sort_keys=True, ensure_ascii=True
                        ).casefold()
                    except (TypeError, ValueError):
                        warning_text = "hook"
                    if "hook" in warning_text:
                        raise ProtocolError("Codex reported a hook warning during the turn")
                elif method == "turn/completed":
                    status = params.get("turn", {}).get("status")
                    if status != "completed":
                        raise ProtocolError(f"turn ended with {status}")
                    if not answer:
                        raise ProtocolError("turn completed without an agent message")
                    if active_hook_runs:
                        raise ProtocolError("Codex completed a turn with an unfinished hook")
                    return answer
        except (TimeoutError, asyncio.CancelledError):
            await self.interrupt_turn(thread_id, turn_id)
            raise
        except BaseException:
            await self.interrupt_turn(thread_id, turn_id)
            raise
        finally:
            self.active_turns.pop(thread_id, None)
            self._bound_shared_skills()
            await self._require_shared_hooks()
            self._bound_vault_policy()
            await self.require_bound_chatgpt_principal()
