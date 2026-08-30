"""Regression tests for the Claude Discord launch security boundary."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("DISCOPARTY_CONFIG", str(REPO_ROOT / "config.example.toml"))
os.environ.setdefault("DISCOPARTY_OWNER_USER_ID", "111111111111111111")
os.environ.setdefault("DISCOPARTY_DISCORD_APPLICATION_ID", "222222222222222222")
os.environ.setdefault("DISCOPARTY_DISCORD_BOT_USER_ID", "333333333333333333")
os.environ.setdefault("DISCOPARTY_DISCORD_GUILD_ID", "444444444444444444")
sys.path.insert(0, str(REPO_ROOT / "conversations"))

import bun_runtime  # noqa: E402
import claude_cli  # noqa: E402
import claude_plugin  # noqa: E402
import discord_access  # noqa: E402
import lib  # noqa: E402
import listener_contract  # noqa: E402
import shared_skills  # noqa: E402
import vault_policy  # noqa: E402
sys.path.insert(0, str(REPO_ROOT / "conversations" / "queue"))
import drainer  # noqa: E402
import mq  # noqa: E402


class ClaudePluginPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name).resolve()
        self.plugin = (
            self.home
            / ".claude/plugins/cache/claude-plugins-official/discord/0.0.4"
        )
        self.plugin.mkdir(parents=True, mode=0o700)
        (self.plugin / "node_modules").mkdir(mode=0o700)
        dependency = self.plugin / "node_modules" / "dependency.js"
        dependency.write_bytes(b"export const reviewed = true\n")
        dependency.chmod(0o600)
        self.fake_bun = self.home / "reviewed-bun"
        self.fake_bun.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.fake_bun.chmod(0o500)
        self.commit = "a" * 40
        self.contents = {
            ".claude-plugin/plugin.json": json.dumps(
                {"name": "discord", "version": "0.0.4"}
            ).encode(),
            ".mcp.json": b"mcp",
            "bun.lock": b"lock",
            "package.json": b"package",
            "server.ts": b"server",
        }
        for relative, content in self.contents.items():
            path = self.plugin / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o600)
        registry = self.home / ".claude/plugins/installed_plugins.json"
        registry.write_text(
            json.dumps(
                {
                    "plugins": {
                        claude_plugin.PLUGIN_ID: [
                            {
                                "scope": "user",
                                "version": claude_plugin.PLUGIN_VERSION,
                                "installPath": str(self.plugin),
                                "gitCommitSha": self.commit,
                            }
                        ]
                    }
                }
            )
        )
        registry.chmod(0o600)
        self.reviewed_files = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in self.contents.items()
            if name != "server.ts"
        }
        self.patch_files = mock.patch.object(
            claude_plugin, "REVIEWED_FILES", self.reviewed_files
        )
        self.patch_revisions = mock.patch.object(
            claude_plugin,
            "REVIEWED_SERVER_REVISIONS",
            {self.commit: hashlib.sha256(b"server").hexdigest()},
        )
        self.patch_dependencies = mock.patch.object(
            claude_plugin,
            "REVIEWED_NODE_MODULES_DIGEST",
            claude_plugin.dependency_manifest(
                self.plugin / "node_modules"
            )["sha256"],
        )
        self.patch_bun = mock.patch.object(
            claude_plugin.bun_runtime,
            "verify",
            return_value={"canonical_path": str(self.fake_bun)},
        )
        self.patch_files.start()
        self.patch_revisions.start()
        self.patch_dependencies.start()
        self.patch_bun.start()

    def tearDown(self) -> None:
        self.patch_bun.stop()
        self.patch_dependencies.stop()
        self.patch_files.stop()
        self.patch_revisions.stop()
        self.temporary.cleanup()

    def test_exact_reviewed_artifact_is_accepted(self) -> None:
        self.assertEqual(claude_plugin.verify(home=self.home), self.plugin)

    def test_changed_server_is_rejected(self) -> None:
        (self.plugin / "server.ts").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "server.ts"):
            claude_plugin.verify(home=self.home)

    def test_unreviewed_commit_is_rejected(self) -> None:
        registry = self.home / ".claude/plugins/installed_plugins.json"
        value = json.loads(registry.read_text())
        value["plugins"][claude_plugin.PLUGIN_ID][0]["gitCommitSha"] = "b" * 40
        registry.write_text(json.dumps(value))
        registry.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "has not been reviewed"):
            claude_plugin.verify(home=self.home)

    def test_unmanifested_or_changed_dependency_is_rejected(self) -> None:
        dependency = self.plugin / "node_modules" / "dependency.js"
        dependency.write_bytes(b"malicious")
        with self.assertRaisesRegex(RuntimeError, "dependency manifest"):
            claude_plugin.verify(home=self.home)

    def test_private_offline_runtime_rejects_post_install_tampering(self) -> None:
        runtime = claude_plugin.install_runtime(
            home=self.home, bun_path=self.fake_bun
        )
        self.assertEqual(
            claude_plugin.verify_runtime(home=self.home, bun_path=self.fake_bun),
            runtime,
        )
        wrapper = (runtime / "bin" / "bun").read_text()
        self.assertIn("--no-install", wrapper)
        self.assertNotIn("bun install", wrapper)
        wrong_plugin_args = subprocess.run(
            [
                str(runtime / "bin" / "bun"),
                "run",
                "--cwd",
                str(self.plugin),
                "--shell=bun",
                "start",
            ],
            check=False,
        )
        self.assertEqual(wrong_plugin_args.returncode, 64)
        normal_bun = subprocess.run(
            [str(runtime / "bin" / "bun"), "--version"], check=False
        )
        self.assertEqual(normal_bun.returncode, 0)

        dependency = runtime / "node_modules" / "dependency.js"
        dependency.chmod(0o600)
        dependency.write_bytes(b"malicious")
        dependency.chmod(0o400)
        with self.assertRaisesRegex(RuntimeError, "dependency manifest"):
            claude_plugin.verify_runtime(home=self.home, bun_path=self.fake_bun)


class ClaudeCliPinTests(unittest.TestCase):
    def test_exact_arm64_hash_signature_and_version_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "claude"
            binary.write_bytes(b"reviewed-cli")
            binary.chmod(0o755)
            digest = hashlib.sha256(b"reviewed-cli").hexdigest()
            signature = {
                "Identifier": claude_cli.EXPECTED_IDENTIFIER,
                "TeamIdentifier": claude_cli.EXPECTED_TEAM_ID,
                "Authority": claude_cli.EXPECTED_AUTHORITY,
            }
            result = claude_cli.verify(
                binary,
                expected_canonical_path=binary,
                expected_sha256=digest,
                signature_inspector=lambda _path: signature,
                version_inspector=lambda _path: claude_cli.EXPECTED_VERSION,
                architecture_inspector=lambda _path: "Mach-O 64-bit executable arm64",
                machine="arm64",
            )
            self.assertEqual(result["sha256"], digest)

            binary.write_bytes(b"tampered-cli")
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                claude_cli.verify(
                    binary,
                    expected_canonical_path=binary,
                    expected_sha256=digest,
                    signature_inspector=lambda _path: signature,
                    version_inspector=lambda _path: claude_cli.EXPECTED_VERSION,
                    architecture_inspector=lambda _path: "Mach-O 64-bit executable arm64",
                    machine="arm64",
                )

    def test_wrong_signer_or_non_arm64_host_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "claude"
            binary.write_bytes(b"reviewed-cli")
            binary.chmod(0o755)
            digest = hashlib.sha256(b"reviewed-cli").hexdigest()
            bad_signature = {
                "Identifier": claude_cli.EXPECTED_IDENTIFIER,
                "TeamIdentifier": "EVIL",
                "Authority": claude_cli.EXPECTED_AUTHORITY,
            }
            with self.assertRaisesRegex(RuntimeError, "signing team"):
                claude_cli.verify(
                    binary,
                    expected_canonical_path=binary,
                    expected_sha256=digest,
                    signature_inspector=lambda _path: bad_signature,
                    version_inspector=lambda _path: claude_cli.EXPECTED_VERSION,
                    architecture_inspector=lambda _path: "Mach-O 64-bit executable arm64",
                    machine="arm64",
                )
            with self.assertRaisesRegex(RuntimeError, "Apple Silicon"):
                claude_cli.verify(
                    binary,
                    expected_canonical_path=binary,
                    expected_sha256=digest,
                    machine="x86_64",
                )


class BunRuntimePinTests(unittest.TestCase):
    def test_exact_arm64_hash_signature_and_version_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "bun"
            binary.write_bytes(b"reviewed-bun")
            binary.chmod(0o755)
            digest = hashlib.sha256(b"reviewed-bun").hexdigest()
            signature = {
                "Identifier": bun_runtime.EXPECTED_IDENTIFIER,
                "TeamIdentifier": bun_runtime.EXPECTED_TEAM_ID,
                "Authority": bun_runtime.EXPECTED_AUTHORITY,
            }
            result = bun_runtime.verify(
                binary,
                expected_canonical_path=binary,
                expected_sha256=digest,
                signature_inspector=lambda _path: signature,
                version_inspector=lambda _path: bun_runtime.EXPECTED_VERSION,
                architecture_inspector=lambda _path: "Mach-O 64-bit executable arm64",
                machine="arm64",
            )
            self.assertEqual(result["sha256"], digest)

            binary.write_bytes(b"tampered-bun")
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                bun_runtime.verify(
                    binary,
                    expected_canonical_path=binary,
                    expected_sha256=digest,
                    signature_inspector=lambda _path: signature,
                    version_inspector=lambda _path: bun_runtime.EXPECTED_VERSION,
                    architecture_inspector=lambda _path: "Mach-O 64-bit executable arm64",
                    machine="arm64",
                )


class ClaudeLauncherEnvironmentTests(unittest.TestCase):
    def test_poisoned_environment_is_not_inherited(self) -> None:
        poisoned = os.environ.copy()
        poisoned.update(
            {
                "ANTHROPIC_API_KEY": "poison",
                "ANTHROPIC_BASE_URL": "https://evil.invalid",
                "BLOTATO_API_KEY": "poison",
                "CLAUDE_BIN": "/tmp/evil",
                "DISCORD_BOT_TOKEN": "poison",
                "OPENAI_API_KEY": "poison",
                "DISCOPARTY_CONFIG": "/tmp/evil",
                "DISCOPARTY_REPO_ROOT": "/tmp/evil",
                "TMUX": "/tmp/poison",
            }
        )
        result = subprocess.run(
            [str(REPO_ROOT / "cx-launcher.sh"), "--audit-environment"],
            cwd=REPO_ROOT,
            env=poisoned,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        names = {line.split("=", 1)[0] for line in result.stdout.splitlines()}
        forbidden = {
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            "BLOTATO_API_KEY",
            "CLAUDE_BIN",
            "DISCORD_BOT_TOKEN",
            "OPENAI_API_KEY",
            "TMUX",
        }
        self.assertTrue(forbidden.isdisjoint(names))
        self.assertEqual(
            dict(
                line.split("=", 1)
                for line in result.stdout.splitlines()
                if "=" in line
            )["DISCOPARTY_REPO_ROOT"],
            str(REPO_ROOT),
        )

    def test_installer_refuses_credential_files_instead_of_sourcing_them(self) -> None:
        installer = (REPO_ROOT / "install.sh").read_text()
        self.assertNotIn('source "$SCRIPT_DIR/.discoparty.env"', installer)
        self.assertIn(
            '[ -e "$SCRIPT_DIR/.discoparty.env" ]',
            installer,
        )
        self.assertIn("credential files are forbidden", installer)
        self.assertIn("transient process environment", installer)

    def test_official_plugin_egress_tools_are_cli_denied(self) -> None:
        launcher = (REPO_ROOT / "cx-launcher.sh").read_text()
        for tool in (
            "reply",
            "react",
            "fetch_messages",
            "download_attachment",
            "edit_message",
        ):
            self.assertIn(f"mcp__plugin_discord_discord__{tool}", launcher)

    def test_poisoned_settings_and_ambient_mcp_cannot_enable_bash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            poisoned_home = Path(temporary)
            (poisoned_home / ".claude").mkdir()
            (poisoned_home / ".claude/settings.json").write_text(
                json.dumps(
                    {
                        "permissions": {"defaultMode": "bypassPermissions"},
                        "enableAllProjectMcpServers": True,
                    }
                )
            )
            (poisoned_home / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"evil": {"command": "/tmp/evil"}}})
            )
            poisoned = os.environ.copy()
            poisoned.update(
                {
                    "HOME": str(poisoned_home),
                    "CLAUDE_CONFIG_DIR": str(poisoned_home / ".claude"),
                }
            )
            result = subprocess.run(
                [str(REPO_ROOT / "cx-launcher.sh"), "--audit-command"],
                cwd=REPO_ROOT,
                env=poisoned,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertIn("--restricted", arguments)
        self.assertEqual(arguments[arguments.index("--permission-mode") + 1], "dontAsk")
        self.assertEqual(arguments[arguments.index("--tools") + 1], "Read,Glob,Grep")
        self.assertIn("--strict-mcp-config", arguments)
        self.assertIn("--append-system-prompt-file", arguments)
        self.assertEqual(
            arguments[arguments.index("--append-system-prompt-file") + 1],
            str(
                discord_access.CONFIG.discord.plugin_state_dir
                / listener_contract.POLICY_DIRECTORY_NAME
                / listener_contract.RUNTIME_PROMPT_NAME
            ),
        )
        self.assertEqual(
            arguments[arguments.index("--append-subagent-system-prompt") + 1],
            listener_contract.SUBAGENT_POLICY_PROMPT,
        )
        self.assertNotIn("--disable-slash-commands", arguments)
        self.assertEqual(arguments[arguments.index("--setting-sources") + 1], "")
        self.assertNotIn("Bash", arguments[arguments.index("--tools") + 1].split(","))
        self.assertNotIn("/tmp/evil", result.stdout)
        self.assertEqual(arguments, discord_access.expected_claude_arguments())

    def test_listener_contract_is_digest_pinned_and_tamper_evident(self) -> None:
        result = listener_contract.verify()
        self.assertEqual(result["sha256"], listener_contract.EXPECTED_SHA256)
        with tempfile.TemporaryDirectory() as temporary:
            prompt_dir = Path(temporary) / "cx-chat-listener"
            prompt_dir.mkdir(mode=0o700)
            prompt = prompt_dir / "CLAUDE.md"
            prompt.write_text(
                listener_contract.READINESS_TOKEN
                + "\n"
                + listener_contract.TAKEOVER_DRAIN_TOKEN_PREFIX
            )
            prompt.chmod(0o600)
            digest = hashlib.sha256(prompt.read_bytes()).hexdigest()
            listener_contract.verify(
                prompt, expected_path=prompt, expected_sha256=digest
            )
            prompt.write_text("tampered")
            with self.assertRaisesRegex(RuntimeError, "digest"):
                listener_contract.verify(
                    prompt, expected_path=prompt, expected_sha256=digest
                )

    def test_claude_runtime_policy_seals_listener_and_worker_to_vault_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            vault = root / "vault"
            runtime = root / "state"
            bootstrap = root / "bootstrap"
            for directory in (vault, runtime, bootstrap):
                directory.mkdir(mode=0o700)
            source = "# Vault Guide\n\n" + "".join(
                f"{heading}\nTest rule for {heading}.\n\n"
                for heading in vault_policy.EXPECTED_P0_HEADINGS
            )
            source_path = vault / "CLAUDE.md"
            source_path.write_text(source)
            sealed = listener_contract.seal_runtime_policy(
                vault_root=vault,
                runtime_root=runtime,
                bootstrap_workspace=bootstrap,
            )
            self.assertEqual(sealed.prompt_path.stat().st_mode & 0o777, 0o400)
            self.assertEqual(sealed.manifest_path.stat().st_mode & 0o777, 0o400)
            self.assertIn(
                "# Canonical sealed Vault P0 policy",
                sealed.prompt_path.read_text(),
            )
            environment = {
                **sealed.environment(),
                "DISCORD_STATE_DIR": str(runtime),
            }
            checked = listener_contract.validate_runtime_policy_from_environment(
                environment
            )
            self.assertEqual(checked.seal.binding(), sealed.seal.binding())

            source_path.write_text(source + "changed after install\n")
            with self.assertRaisesRegex(RuntimeError, "changed after policy binding"):
                listener_contract.validate_runtime_policy(
                    vault_root=vault,
                    runtime_root=runtime,
                    bootstrap_workspace=bootstrap,
                )

    def test_claude_runtime_policy_rejects_snapshot_and_environment_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            vault = root / "vault"
            runtime = root / "state"
            bootstrap = root / "bootstrap"
            for directory in (vault, runtime, bootstrap):
                directory.mkdir(mode=0o700)
            (vault / "CLAUDE.md").write_text(
                "# Vault Guide\n\n"
                + "".join(
                    f"{heading}\nRule.\n\n"
                    for heading in vault_policy.EXPECTED_P0_HEADINGS
                )
            )
            sealed = listener_contract.seal_runtime_policy(
                vault_root=vault,
                runtime_root=runtime,
                bootstrap_workspace=bootstrap,
            )
            environment = {
                **sealed.environment(),
                "DISCORD_STATE_DIR": str(runtime),
            }
            environment["DISCOPARTY_VAULT_POLICY_SOURCE_SHA256"] = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "environment changed"):
                listener_contract.validate_runtime_policy_from_environment(
                    environment
                )

            sealed.seal.snapshot_path.chmod(0o600)
            sealed.seal.snapshot_path.write_text("tampered\n")
            sealed.seal.snapshot_path.chmod(0o400)
            with self.assertRaises(RuntimeError):
                listener_contract.validate_runtime_policy(
                    vault_root=vault,
                    runtime_root=runtime,
                    bootstrap_workspace=bootstrap,
                )

    def test_only_explicit_inert_vault_skill_root_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            claude_dir = root / ".claude"
            skills_root = root / "x_System" / "Skills"
            claude_dir.mkdir(mode=0o700)
            for relative in shared_skills.REQUIRED_SKILLS:
                skill = skills_root / relative
                skill.parent.mkdir(parents=True, exist_ok=True)
                skill.write_text("---\nname: reviewed\n---\n")
                skill.chmod(0o600)
            (claude_dir / "skills").symlink_to(Path("../x_System/Skills"))
            settings = claude_dir / "settings.json"
            settings.write_text(json.dumps({"enabledPlugins": {"ambient": False}}))
            settings.chmod(0o600)
            self.assertEqual(shared_skills.verify(root)["root"], str(root))

            settings.write_text(json.dumps({"enabledPlugins": {"ambient": True}}))
            with self.assertRaisesRegex(RuntimeError, "must not enable"):
                shared_skills.verify(root)

            settings.write_text(json.dumps({"enabledPlugins": {"ambient": False}}))
            websites = skills_root / "marketing" / "websites"
            redirected = root / "redirected-websites"
            websites.rename(redirected)
            websites.symlink_to(redirected, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "safe directory"):
                shared_skills.verify(root)

    def test_full_mode_is_explicit_but_keeps_configuration_isolation(self) -> None:
        launcher = (REPO_ROOT / "cx-launcher.sh").read_text()
        self.assertIn('"--dangerously-skip-permissions"', launcher)
        self.assertIn('"--permission-mode" "bypassPermissions"', launcher)
        self.assertIn('"--strict-mcp-config"', launcher)
        self.assertIn('"--setting-sources" ""', launcher)
        self.assertIn("read-only safe profile cannot service the unattended queue", launcher)
        self.assertIn('"DISABLE_UPDATES=1"', launcher)
        self.assertNotIn("FORCE_AUTOUPDATE_PLUGINS=", launcher)

    def test_launcher_uses_pinned_offline_plugin_runtime(self) -> None:
        launcher = (REPO_ROOT / "cx-launcher.sh").read_text()
        self.assertIn("ulimit -c 0", launcher)
        self.assertNotIn("TMP_ROOT=", launcher)
        self.assertIn('"$REPO_ROOT/conversations/bun_runtime.py" verify', launcher)
        self.assertIn('"$REPO_ROOT/conversations/claude_plugin.py" runtime-bin', launcher)
        self.assertIn('"$REPO_ROOT/conversations/shared_skills.py" verify', launcher)
        self.assertIn("verify-runtime-policy", launcher)
        self.assertIn("--append-subagent-system-prompt", launcher)
        self.assertIn(listener_contract.SUBAGENT_POLICY_PROMPT, launcher)
        common_args = launcher.split("CLAUDE_ARGS=(", 1)[1].split(")", 1)[0]
        self.assertIn('"--add-dir" "$WORKSPACE_ROOT"', common_args)
        self.assertIn('"$REPO_ROOT/conversations/discord_access.py" exec-claude', launcher)
        self.assertIn('--plugin-bin-dir "$PLUGIN_BIN_DIR"', launcher)
        self.assertNotIn("materialize-token", launcher)
        access_wrapper = (REPO_ROOT / "conversations/discord_access.py").read_text()
        self.assertIn('"PATH": f"{plugin_bin}:{CLEAN_PATH}"', access_wrapper)
        self.assertIn("os.execve(", access_wrapper)
        wrapper = claude_plugin._wrapper_bytes(
            Path("/reviewed/plugin"),
            Path("/private/runtime"),
            Path("/reviewed/bun"),
        ).decode()
        self.assertIn("--no-install", wrapper)
        self.assertNotIn("bun install", wrapper)

    def test_launcher_uses_the_reviewed_m5_claude_cli_verifier(self) -> None:
        launcher = (REPO_ROOT / "cx-launcher.sh").read_text()
        self.assertIn(
            'CLAUDE_BIN="$HOME_DIR/.local/share/claude/versions/2.1.251"',
            launcher,
        )
        self.assertIn('"$REPO_ROOT/conversations/claude_cli.py" verify', launcher)
        self.assertEqual(claude_cli.EXPECTED_VERSION, "2.1.251 (Claude Code)")
        self.assertEqual(
            claude_cli.EXPECTED_SHA256,
            "625869b01e0050f260b2980fac248fd9cef9e462612bded4ec9d3d49ff8969a5",
        )

    def test_healthcheck_verifies_permissions_before_liveness(self) -> None:
        healthcheck = (REPO_ROOT / "launchd/cx-chat-healthcheck.sh").read_text()
        main = healthcheck.split("main() {", 1)[1]
        self.assertLess(
            main.index("enforce_discord_permissions"),
            main.index('tmux has-session -t "=$SESSION"'),
        )
        self.assertIn("stop_cx_chat", healthcheck)
        self.assertIn("listener remains stopped", healthcheck)
        self.assertIn('current_pgid="$(/bin/ps -o pgid= -p "$$"', healthcheck)
        self.assertIn('[ "$pgid" = "$current_pgid" ]', healthcheck)
        self.assertIn('pane_start_command', healthcheck)
        self.assertIn('tmux has-session -t "=$SESSION"', healthcheck)
        self.assertIn(listener_contract.READINESS_TOKEN, healthcheck)
        self.assertIn("listener_protocol_is_ready", healthcheck)

    def test_installer_requires_full_authority_before_mutation_and_proves_ready(self) -> None:
        installer = (REPO_ROOT / "install.sh").read_text()
        main = installer.split("main() {", 1)[1]
        self.assertLess(
            main.index("confirm_config_write_and_authority"),
            main.index("remove_stale_marker_watcher"),
        )
        self.assertIn("DISCOPARTY_CLAUDE_FULL_AUTHORITY=1", installer)
        self.assertIn("Type FULL LOCAL AUTHORITY", installer)
        self.assertIn("use_dangerously_skip_permissions = true", installer)
        self.assertIn('cx-chat-healthcheck.sh" ||', installer)
        self.assertIn("did not prove exact session and protocol readiness", installer)
        self.assertIn("com.thesystem.cx-chat-queue-monitor", installer)
        self.assertIn("install_claude_vault_policy", installer)
        self.assertLess(
            main.index("install_claude_vault_policy"),
            main.index("store_token_in_keychain"),
        )
        self.assertLess(
            main.index("install_claude_discord_access"),
            main.index("install_claude_vault_policy"),
        )
        self.assertIn("com.thesystem.cx-chat-archive-sync", installer)
        self.assertIn("queue/drainer.py", installer)
        self.assertIn("sync-discord-archive-state.py", installer)


class ClaudeWorkerCompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db = Path(self.temporary.name) / "mq.sqlite3"
        self.conn = mq.connect(self.db)

    def tearDown(self) -> None:
        self.conn.close()
        self.temporary.cleanup()

    def _spawned(self, message_id: str, thread_id: str = "222222222222222222") -> None:
        mq.enqueue(self.conn, message_id=message_id, chat_id="root", body="hello")
        claimed = mq.claim_next(self.conn)
        self.assertIsNotNone(claimed)
        mq.mark_dispatched(
            self.conn, message_id, session_id="session-one", thread_id=thread_id
        )
        mq.mark_spawned(self.conn, message_id)

    def test_completion_unblocks_next_same_chat_row(self) -> None:
        root_channel = "111111111111111111"
        thread_id = "222222222222222222"
        response_id = "333333333333333333"
        for message_id in ("444444444444444444", "555555555555555555"):
            mq.enqueue(
                self.conn,
                message_id=message_id,
                chat_id=root_channel,
                body="hello",
            )
        first = mq.claim_next(self.conn)
        self.assertEqual(first["message_id"], "444444444444444444")
        mq.mark_dispatched(
            self.conn,
            first["message_id"],
            session_id="session-one",
            thread_id=thread_id,
        )
        mq.mark_spawned(self.conn, first["message_id"])
        self.assertIsNone(mq.claim_next(self.conn))
        def discord_call(method, _path, _token, payload=None, **_kwargs):
            if method == "POST":
                self.assertIsInstance(payload, dict)
                discord_call.nonce = payload["nonce"]
            return {
                "id": response_id,
                "channel_id": thread_id,
                "content": "safe response",
                "nonce": discord_call.nonce,
                "author": {"id": drainer.CONFIG.discord.bot_user_id},
            }

        discord_call.nonce = ""
        with (
            mock.patch.object(
                drainer.safe_files, "read", return_value="safe response"
            ),
            mock.patch.object(drainer.safe_files, "delete") as delete,
            mock.patch.object(drainer, "load_discord_token", return_value="token"),
            mock.patch.object(drainer, "validate_principal"),
            mock.patch.object(drainer, "validate_destination"),
            mock.patch.object(drainer.lib, "append_turn_once", return_value=True) as append,
            mock.patch.object(drainer, "json_request", side_effect=discord_call) as post,
        ):
            result = drainer.complete_response(
                self.conn,
                message_id=first["message_id"],
                session_id="session-one",
                thread_id=thread_id,
                response_exchange_id="a" * 32,
            )
        self.assertEqual(result["message_id"], response_id)
        append.assert_called_once()
        self.assertEqual(post.call_count, 2)
        delete.assert_called_once_with("response", "a" * 32)
        second = mq.claim_next(self.conn)
        self.assertEqual(second["message_id"], "555555555555555555")

    def test_exact_completed_response_replays_without_second_post(self) -> None:
        message_id = "444444444444444444"
        thread_id = "222222222222222222"
        response_id = "333333333333333333"
        mq.enqueue(self.conn, message_id=message_id, chat_id="root", body="hello")
        mq.claim_next(self.conn)
        mq.mark_dispatched(
            self.conn, message_id, session_id="session-one", thread_id=thread_id
        )
        mq.mark_spawned(self.conn, message_id)
        response_sha = hashlib.sha256(b"safe response").hexdigest()
        prepared = mq.prepare_response_completion(
            self.conn,
            message_id,
            session_id="session-one",
            thread_id=thread_id,
            response_sha256=response_sha,
            response_content="safe response",
        )
        mq.begin_response_attempt(self.conn, message_id)
        mq.confirm_response_delivery(
            self.conn,
            message_id,
            response_sha256=response_sha,
            response_nonce=prepared["response_nonce"],
            response_message_id=response_id,
        )
        mq.finish_response_completion(
            self.conn,
            message_id,
            response_sha256=response_sha,
            response_message_id=response_id,
        )
        with (
            mock.patch.object(
                drainer.safe_files, "read", return_value="safe response"
            ),
            mock.patch.object(drainer.safe_files, "delete"),
            mock.patch.object(drainer, "json_request") as post,
        ):
            result = drainer.complete_response(
                self.conn,
                message_id=message_id,
                session_id="session-one",
                thread_id=thread_id,
                response_exchange_id="a" * 32,
            )
        self.assertTrue(result["replayed"])
        post.assert_not_called()

    def test_unknown_post_outcome_reconciles_history_without_second_post(self) -> None:
        message_id = "444444444444444446"
        thread_id = "222222222222222222"
        response_id = "333333333333333334"
        self._spawned(message_id, thread_id)
        common = (
            mock.patch.object(drainer, "load_discord_token", return_value="token"),
            mock.patch.object(drainer, "validate_principal"),
            mock.patch.object(drainer, "validate_destination"),
        )
        with (
            mock.patch.object(drainer.safe_files, "read", return_value="safe response"),
            common[0],
            common[1],
            common[2],
            mock.patch.object(
                drainer, "json_request", side_effect=RuntimeError("lost POST response")
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "lost POST response"):
                drainer.complete_response(
                    self.conn,
                    message_id=message_id,
                    session_id="session-one",
                    thread_id=thread_id,
                    response_exchange_id="a" * 32,
                )
        prepared = mq.get(self.conn, message_id)
        self.assertIsNotNone(prepared["response_attempted_at"])
        self.assertEqual(prepared["response_content"], "safe response")
        self.conn.execute(
            "UPDATE messages SET response_attempted_at=? WHERE message_id=?",
            (time.time() - 1000, message_id),
        )
        history = [{
            "id": response_id,
            "channel_id": thread_id,
            "content": "safe response",
            "nonce": prepared["response_nonce"],
            "author": {"id": drainer.CONFIG.discord.bot_user_id},
        }]
        with (
            mock.patch.object(drainer, "load_discord_token", return_value="token"),
            mock.patch.object(drainer, "validate_principal"),
            mock.patch.object(drainer, "validate_destination"),
            mock.patch.object(
                drainer,
                "discord_request",
                return_value=(200, json.dumps(history).encode()),
            ) as history_get,
            mock.patch.object(drainer, "json_request") as post,
            mock.patch.object(drainer.lib, "append_turn_once", return_value=True) as append,
        ):
            result = drainer.reconcile_response(self.conn, message_id=message_id)
        self.assertEqual(result["message_id"], response_id)
        history_get.assert_called_once()
        post.assert_not_called()
        append.assert_called_once()
        self.assertEqual(mq.get(self.conn, message_id)["state"], "done")

    def test_aged_unknown_post_without_history_match_is_quarantined(self) -> None:
        message_id = "444444444444444447"
        thread_id = "222222222222222222"
        self._spawned(message_id, thread_id)
        with (
            mock.patch.object(drainer.safe_files, "read", return_value="safe response"),
            mock.patch.object(drainer, "load_discord_token", return_value="token"),
            mock.patch.object(drainer, "validate_principal"),
            mock.patch.object(drainer, "validate_destination"),
            mock.patch.object(
                drainer, "json_request", side_effect=RuntimeError("lost POST response")
            ),
        ):
            with self.assertRaises(RuntimeError):
                drainer.complete_response(
                    self.conn,
                    message_id=message_id,
                    session_id="session-one",
                    thread_id=thread_id,
                    response_exchange_id="a" * 32,
                )
        self.conn.execute(
            "UPDATE messages SET response_attempted_at=? WHERE message_id=?",
            (time.time() - 1000, message_id),
        )
        with (
            mock.patch.object(drainer, "load_discord_token", return_value="token"),
            mock.patch.object(drainer, "validate_principal"),
            mock.patch.object(drainer, "validate_destination"),
            mock.patch.object(drainer, "discord_request", return_value=(200, b"[]")),
            mock.patch.object(drainer, "json_request") as post,
        ):
            with self.assertRaises(drainer.DeliveryAmbiguousError):
                drainer.reconcile_response(self.conn, message_id=message_id)
        row = mq.get(self.conn, message_id)
        self.assertIsNotNone(row["response_ambiguous_at"])
        self.assertEqual(row["state"], "spawned")
        post.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "unresolved Discord response"):
            mq.mark_errored(self.conn, message_id, "worker stopped")

    def test_confirmed_delivery_survives_transcript_append_crash(self) -> None:
        message_id = "444444444444444448"
        thread_id = "222222222222222222"
        response_id = "333333333333333335"
        self._spawned(message_id, thread_id)
        digest = hashlib.sha256(b"safe response").hexdigest()
        prepared = mq.prepare_response_completion(
            self.conn,
            message_id,
            session_id="session-one",
            thread_id=thread_id,
            response_sha256=digest,
            response_content="safe response",
        )
        mq.begin_response_attempt(self.conn, message_id)
        mq.confirm_response_delivery(
            self.conn,
            message_id,
            response_sha256=digest,
            response_nonce=prepared["response_nonce"],
            response_message_id=response_id,
        )
        with (
            mock.patch.object(drainer, "load_discord_token", return_value="token"),
            mock.patch.object(drainer, "validate_principal"),
            mock.patch.object(drainer, "validate_destination"),
            mock.patch.object(drainer, "json_request") as post,
            mock.patch.object(
                drainer.lib, "append_turn_once", side_effect=RuntimeError("disk crash")
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "disk crash"):
                drainer.reconcile_response(self.conn, message_id=message_id)
        self.assertEqual(mq.get(self.conn, message_id)["state"], "spawned")
        post.assert_not_called()
        with (
            mock.patch.object(drainer, "load_discord_token", return_value="token"),
            mock.patch.object(drainer, "validate_principal"),
            mock.patch.object(drainer, "validate_destination"),
            mock.patch.object(drainer, "json_request") as second_post,
            mock.patch.object(drainer.lib, "append_turn_once", return_value=True),
        ):
            result = drainer.reconcile_response(self.conn, message_id=message_id)
        self.assertEqual(result["message_id"], response_id)
        second_post.assert_not_called()
        self.assertEqual(mq.get(self.conn, message_id)["state"], "done")

    def test_prepared_response_content_is_immutable(self) -> None:
        message_id = "444444444444444449"
        thread_id = "222222222222222222"
        self._spawned(message_id, thread_id)
        first_digest = hashlib.sha256(b"first response").hexdigest()
        mq.prepare_response_completion(
            self.conn,
            message_id,
            session_id="session-one",
            thread_id=thread_id,
            response_sha256=first_digest,
            response_content="first response",
        )
        with self.assertRaisesRegex(RuntimeError, "changed after preparation"):
            mq.prepare_response_completion(
                self.conn,
                message_id,
                session_id="session-one",
                thread_id=thread_id,
                response_sha256=hashlib.sha256(b"changed response").hexdigest(),
                response_content="changed response",
            )

    def test_transcript_completion_marker_is_idempotent(self) -> None:
        state = {
            "fm": {"message_count": 0},
            "body": "# Conversation\n",
        }

        def load(_session_id):
            return dict(state["fm"]), state["body"], Path("conversation.md")

        def save(fm, body, _path):
            state["fm"] = dict(fm)
            state["body"] = body

        digest = hashlib.sha256(b"response").hexdigest()
        with (
            mock.patch.object(lib, "registry_lock", return_value=nullcontext()),
            mock.patch.object(lib, "load_conversation", side_effect=load),
            mock.patch.object(lib, "save_conversation", side_effect=save),
            mock.patch.object(lib, "regen_index"),
        ):
            self.assertTrue(
                lib.append_turn_once(
                    "session",
                    "claude",
                    "response",
                    completion_token="a" * 32,
                    text_sha256=digest,
                )
            )
            self.assertFalse(
                lib.append_turn_once(
                    "session",
                    "claude",
                    "response",
                    completion_token="a" * 32,
                    text_sha256=digest,
                )
            )
        self.assertEqual(state["fm"]["message_count"], 1)


if __name__ == "__main__":
    unittest.main()
