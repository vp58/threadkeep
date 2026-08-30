from __future__ import annotations

import asyncio
import hmac
import json
import os
import subprocess

from .codex_auth import (
    reject_filesystem_credentials,
    require_chatgpt_login,
    require_supported_cli,
    require_supported_protocol,
)
from conversations.vault_policy import VaultPolicySeal
from conversations.discord_secret import load_discord_token
from .appserver import CodexAppServer
from .config import Config
from .discord_io import dedicated_token, verify_owner_private_audience
from .discord_permissions import verify_discord_permissions


EXPECTED_HOST_CPU = "Apple M5 Max"


def require_reviewed_host() -> str:
    commands = (
        (["/usr/bin/uname", "-s"], "Darwin", "operating system"),
        (["/usr/bin/uname", "-m"], "arm64", "architecture"),
        (["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], EXPECTED_HOST_CPU, "CPU"),
    )
    for command, expected, label in commands:
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"could not verify the reviewed host {label}") from exc
        observed = result.stdout.strip()
        if result.returncode != 0 or observed != expected:
            raise RuntimeError(
                f"reviewed host {label} must be exactly {expected!r}, found {observed or 'unknown'!r}"
            )
    return EXPECTED_HOST_CPU


def _discover_claude_tokens() -> list[str]:
    """Read only the canonical Claude Keychain credential for inequality checks."""

    try:
        return [load_discord_token(allow_environment=False)]
    except RuntimeError as exc:
        if str(exc) == "Discord bot credential is missing from macOS Keychain":
            return []
        raise


async def _verify_live_runtime(
    config: Config,
    token: str,
    checks: dict[str, str],
    instructions_sha256: str | None,
    shared_skills_manifest_sha256: str,
    shared_hooks_manifest_sha256: str,
    vault_policy_seal: VaultPolicySeal,
) -> str:
    await verify_discord_permissions(token, config)
    await verify_owner_private_audience(token, config)
    checks["discord_public_channel_permissions"] = "pass"
    checks["discord_channel_audience"] = f"pass: {config.channel_trust}"
    app = CodexAppServer(
        config.codex_bin,
        config.state_dir / "preflight-appserver",
        workspace_dir=config.working_directory,
        sandbox_mode=config.sandbox_mode,
        channel_trust=config.channel_trust,
        full_computer_access_accepted=config.full_computer_access_accepted,
        codex_home=config.codex_home,
        instructions_file=config.instructions_file,
        instructions_sha256=instructions_sha256,
        account_binding=None,
        shared_skills_root=config.shared_skills_root,
        shared_skills_manifest_sha256=shared_skills_manifest_sha256,
        shared_hooks_manifest_sha256=shared_hooks_manifest_sha256,
        vault_policy_seal=vault_policy_seal,
        vault_root=config.vault_root,
        policy_runtime_root=config.state_dir,
    )
    try:
        await app.start()
        await app.probe_policy()
        checks["live_app_server_effective_policy"] = "pass"
        checks["canonical_shared_vault_skills"] = "pass"
        checks["chatgpt_account_type"] = (
            f"pass: {app.chatgpt_plan_type}"
            if app.chatgpt_plan_type
            else "pass"
        )
        if app.account_binding is None:
            raise RuntimeError("App Server omitted the ChatGPT account binding")
        return app.account_binding
    finally:
        await app.close()


def main() -> int:
    checks: dict[str, str] = {}
    warnings: dict[str, str] = {}
    try:
        config = Config.from_discoparty()
        checks["discoparty_codex_config"] = "pass"
    except Exception as exc:
        checks["discoparty_codex_config"] = f"block: {type(exc).__name__}"
        print(json.dumps({"checks": checks, "warnings": warnings}, indent=2))
        return 2
    try:
        host = require_reviewed_host()
        checks["reviewed_m5_max_host"] = f"pass: {host}"
    except Exception as exc:
        checks["reviewed_m5_max_host"] = f"block: {type(exc).__name__}"
        print(json.dumps({"checks": checks, "warnings": warnings}, indent=2))
        return 2
    checks["hook_policy_loaded"] = "pass"
    if config.sandbox_mode == "danger-full-access":
        warnings["hook_fail_open_limit"] = (
            "Codex 0.151 PreToolUse may continue tool execution after hook framework, "
            "process, timeout, or malformed-output failures. The operator explicitly "
            "accepted this bleeding-edge full-access risk."
        )
    codex = config.codex_bin
    worker_home = config.codex_home.parent
    tmp_dir = config.working_directory / ".discoparty-tmp"
    try:
        require_chatgpt_login(
            codex,
            worker_home,
            codex_home=config.codex_home,
            tmp_dir=tmp_dir,
        )
        checks["chatgpt_subscription_auth"] = "pass"
    except Exception as exc:
        checks["chatgpt_subscription_auth"] = f"block: {type(exc).__name__}"
    checks["openai_api_key_absent"] = (
        "pass" if "OPENAI_API_KEY" not in os.environ else "block"
    )
    try:
        reject_filesystem_credentials(config.codex_home)
        checks["keyring_only_credentials"] = "pass"
    except Exception as exc:
        checks["keyring_only_credentials"] = f"block: {type(exc).__name__}"
    try:
        version = require_supported_cli(
            codex,
            worker_home,
            codex_home=config.codex_home,
            tmp_dir=tmp_dir,
        )
        checks["codex_cli"] = f"pass: {version}"
    except Exception as exc:
        checks["codex_cli"] = f"block: {type(exc).__name__}"
    try:
        methods = require_supported_protocol(
            codex,
            worker_home,
            codex_home=config.codex_home,
            tmp_dir=tmp_dir,
        )
        checks["official_experimental_app_server_schema"] = f"pass: {len(methods)} methods"
    except Exception as exc:
        checks["official_experimental_app_server_schema"] = f"block: {type(exc).__name__}"
    try:
        token = dedicated_token(config)
        claude_tokens = _discover_claude_tokens()
        if any(hmac.compare_digest(token, candidate) for candidate in claude_tokens):
            raise RuntimeError("Codex and Claude Discord credentials must differ")
        if claude_tokens:
            checks["dedicated_discord_credential"] = "pass"
        else:
            warnings["dedicated_discord_credential"] = (
                "no local Claude token source was discoverable, so token inequality was not proven"
            )
        instructions_sha256 = config.instructions_digest()
        shared_skills_manifest_sha256 = config.shared_skills_digest()
        shared_hooks_manifest_sha256 = config.shared_hooks_digest()
        vault_policy_seal = config.seal_vault_policy()
        account_binding = asyncio.run(
            _verify_live_runtime(
                config,
                token,
                checks,
                instructions_sha256,
                shared_skills_manifest_sha256,
                shared_hooks_manifest_sha256,
                vault_policy_seal,
            )
        )
        config.policy_fingerprint(
            instructions_sha256,
            account_binding,
            shared_skills_manifest_sha256,
            vault_policy_seal,
            shared_hooks_manifest_sha256,
        )
        checks["canonical_shared_vault_hooks"] = "pass"
        checks["sealed_canonical_vault_policy"] = "pass"
    except Exception as exc:
        checks.setdefault(
            "discord_public_channel_permissions", f"block: {type(exc).__name__}"
        )
        checks.setdefault("discord_channel_audience", f"block: {type(exc).__name__}")
        checks.setdefault(
            "live_app_server_effective_policy", f"block: {type(exc).__name__}"
        )
        checks.setdefault(
            "canonical_shared_vault_skills", f"block: {type(exc).__name__}"
        )
        checks.setdefault(
            "canonical_shared_vault_hooks", f"block: {type(exc).__name__}"
        )
        checks.setdefault(
            "sealed_canonical_vault_policy", f"block: {type(exc).__name__}"
        )
    checks["working_directory"] = (
        "pass" if config.working_directory.is_dir() else "block"
    )
    checks["sandbox_policy"] = "pass"
    if (
        config.sandbox_mode == "danger-full-access"
        and not config.full_computer_access_accepted
    ):
        checks["sandbox_policy"] = "block"
    if config.sandbox_mode == "danger-full-access":
        checks["unrestricted_local_command_profile"] = "pass"
        warnings["same_user_full_access"] = (
            "danger-full-access removes local command sandbox restrictions and gives shell, "
            "filesystem, process, and direct command-network activity the authority of the "
            "local macOS user"
        )
        warnings["host_ui_surface"] = (
            "the CLI App Server has no configured first-class browser or Computer Use host; "
            "danger-full-access does not add those separate tools"
        )
    else:
        warnings["same_user_full_access"] = (
            "workspace-write keeps local command writes inside the reviewed workspace policy"
        )
    warnings["public_channel_output"] = (
        "responses may be public to server members; only the configured immutable owner ID can trigger work"
    )
    warnings["discord_mfa"] = "manual account-level verification remains required"
    print(json.dumps({"checks": checks, "warnings": warnings}, indent=2))
    return 0 if all(value.startswith("pass") for value in checks.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
