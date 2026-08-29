"""Security tests for Claude's narrow Discord helper boundary."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("THREADKEEP_CONFIG", str(REPO_ROOT / "config.example.toml"))
os.environ.setdefault("THREADKEEP_OWNER_USER_ID", "111111111111111111")
os.environ.setdefault("THREADKEEP_DISCORD_APPLICATION_ID", "222222222222222222")
os.environ.setdefault("THREADKEEP_DISCORD_BOT_USER_ID", "333333333333333333")
os.environ.setdefault("THREADKEEP_DISCORD_GUILD_ID", "444444444444444444")
os.environ.setdefault("THREADKEEP_LISTEN_CHANNEL_ID", "555555555555555555")
os.environ.setdefault("THREADKEEP_ERRORS_CHANNEL_ID", "666666666666666666")
sys.path.insert(0, str(REPO_ROOT / "conversations"))
sys.path.insert(0, str(REPO_ROOT / "approval"))

import discord_access
import discord_destination
import discord_http
import discord_secret
import request_approval
import send_message as discord_send

OWNER_ID = "111111111111111111"
APPLICATION_ID = "222222222222222222"
BOT_ID = "333333333333333333"
GUILD_ID = "444444444444444444"
CHAT_ID = "555555555555555555"
ERRORS_ID = "666666666666666666"
THREAD_ID = "777777777777777777"
MESSAGE_ID = "888888888888888888"


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        discord=SimpleNamespace(
            owner_user_id=OWNER_ID,
            application_id=APPLICATION_ID,
            bot_user_id=BOT_ID,
            guild_id=GUILD_ID,
            chat_channel_id=CHAT_ID,
            errors_channel_id=ERRORS_ID,
        )
    )


class ClaudeKeychainCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.home = Path(self.temporary.name).resolve()
        self.home.chmod(0o700)
        self.account = SimpleNamespace(
            pw_dir=str(self.home),
            pw_name="fixture-user",
        )
        self.config = SimpleNamespace(
            discord=SimpleNamespace(
                keychain_service="threadkeep-secret",
                keychain_account="discord-bot-token",
                token_env_var="DISCORD_BOT_TOKEN",
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_default_ignores_ambient_token_and_uses_canonical_account_home(
        self,
    ) -> None:
        result = SimpleNamespace(returncode=0, stdout="keychain-token\n")
        with (
            mock.patch.object(discord_secret, "CONFIG", self.config),
            mock.patch.object(
                discord_secret.pwd, "getpwuid", return_value=self.account
            ),
            mock.patch.object(discord_secret.Path, "is_file", return_value=True),
            mock.patch.object(
                discord_secret.subprocess, "run", return_value=result
            ) as run,
            mock.patch.dict(
                os.environ,
                {
                    "HOME": "/tmp/untrusted-home",
                    "DISCORD_BOT_TOKEN": "ambient-token",
                },
                clear=False,
            ),
        ):
            self.assertEqual(discord_secret.load_discord_token(), "keychain-token")
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["HOME"], str(self.home))
        self.assertEqual(environment["USER"], "fixture-user")
        self.assertNotIn("DISCORD_BOT_TOKEN", environment)

    def test_explicit_environment_loading_is_forbidden_before_keychain(self) -> None:
        with (
            mock.patch.object(discord_secret, "CONFIG", self.config),
            mock.patch.object(discord_secret, "_keychain_token") as keychain,
            mock.patch.dict(
                os.environ,
                {"DISCORD_BOT_TOKEN": "ambient-token"},
                clear=False,
            ),
            self.assertRaisesRegex(RuntimeError, "only from Keychain"),
        ):
            discord_secret.load_discord_token(allow_environment=True)
        keychain.assert_not_called()

    def test_noncanonical_account_home_fails_before_keychain_command(self) -> None:
        target = self.home / "target"
        target.mkdir(mode=0o700)
        alias = self.home / "alias"
        alias.symlink_to(target, target_is_directory=True)
        account = SimpleNamespace(pw_dir=str(alias), pw_name="fixture-user")
        with (
            mock.patch.object(discord_secret, "CONFIG", self.config),
            mock.patch.object(
                discord_secret.pwd, "getpwuid", return_value=account
            ),
            mock.patch.object(discord_secret.Path, "is_file", return_value=True),
            mock.patch.object(discord_secret.subprocess, "run") as run,
            self.assertRaisesRegex(RuntimeError, "not canonical and private"),
        ):
            discord_secret.load_discord_token()
        run.assert_not_called()


class ClaudeCredentialCopyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name)
        self.state.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @contextmanager
    def state_descriptor(self):
        descriptor = os.open(
            self.state,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            yield self.state, descriptor
        finally:
            os.close(descriptor)

    def patch_state(self):
        return mock.patch.object(
            discord_access,
            "_private_directory_descriptor",
            side_effect=self.state_descriptor,
        )

    def write_access(self) -> Path:
        path = self.state / "access.json"
        path.write_text(
            json.dumps(discord_access.expected_access()), encoding="utf-8"
        )
        path.chmod(0o600)
        return path

    def test_remove_token_deletes_private_regular_file(self) -> None:
        token_path = self.state / ".env"
        token_path.write_text("DISCORD_BOT_TOKEN=secret\n", encoding="utf-8")
        token_path.chmod(0o600)
        with self.patch_state():
            self.assertEqual(
                discord_access.remove_legacy_token_file(), token_path
            )
        self.assertFalse(token_path.exists())

    def test_remove_token_unlinks_symlink_without_touching_target(self) -> None:
        target = self.state / "target"
        target.write_text("secret", encoding="utf-8")
        target.chmod(0o600)
        token_path = self.state / ".env"
        token_path.symlink_to(target)
        with self.patch_state():
            discord_access.remove_legacy_token_file()
        self.assertFalse(token_path.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "secret")

    def test_remove_token_deletes_permissive_retired_copy(self) -> None:
        token_path = self.state / ".env"
        token_path.write_text("secret", encoding="utf-8")
        token_path.chmod(0o644)
        with self.patch_state():
            discord_access.remove_legacy_token_file()
        self.assertFalse(token_path.exists())

    def test_remove_token_refuses_hard_linked_file(self) -> None:
        target = self.state / "target"
        target.write_text("secret", encoding="utf-8")
        token_path = self.state / ".env"
        os.link(target, token_path)
        with self.patch_state(), self.assertRaisesRegex(
            RuntimeError, "not safe to remove"
        ):
            discord_access.remove_legacy_token_file()
        self.assertTrue(token_path.exists())
        self.assertEqual(target.read_text(encoding="utf-8"), "secret")

    def test_verify_fails_closed_if_retired_plaintext_copy_exists(self) -> None:
        self.write_access()
        token_path = self.state / ".env"
        token_path.write_text("DISCORD_BOT_TOKEN=secret\n", encoding="utf-8")
        token_path.chmod(0o600)
        with self.patch_state(), self.assertRaisesRegex(
            RuntimeError, "legacy plaintext token file exists"
        ):
            discord_access.verify()

    def test_install_removes_retired_copy_before_writing_policy(self) -> None:
        token_path = self.state / ".env"
        token_path.write_text("DISCORD_BOT_TOKEN=secret\n", encoding="utf-8")
        token_path.chmod(0o600)
        with self.patch_state():
            path = discord_access.install()
        self.assertEqual(path, self.state / "access.json")
        self.assertFalse(token_path.exists())
        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8")),
            discord_access.expected_access(),
        )

    def test_runtime_tmp_refuses_symlink_without_touching_target(self) -> None:
        outside = self.state / "outside"
        outside.mkdir(mode=0o700)
        (self.state / "runtime-tmp").symlink_to(
            outside, target_is_directory=True
        )
        with (
            self.state_descriptor() as (directory, descriptor),
            self.assertRaisesRegex(RuntimeError, "cannot be opened safely"),
            discord_access._private_runtime_tmp(directory, descriptor),
        ):
            pass
        self.assertEqual(list(outside.iterdir()), [])


class ClaudeStateDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.expected = (
            self.home
            / "Library"
            / "Application Support"
            / "Threadkeep"
            / "claude-discord"
        )
        self.config = SimpleNamespace(
            paths=SimpleNamespace(
                workspace_root=self.root / "workspace",
                conversations_dir=self.root / "workspace" / "conversations",
            ),
            discord=SimpleNamespace(plugin_state_dir=self.expected),
        )
        self.account = SimpleNamespace(pw_dir=str(self.home), pw_name="tester")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_creates_each_component_descriptor_relative_and_private(self) -> None:
        with (
            mock.patch.object(discord_access, "CONFIG", self.config),
            mock.patch.object(
                discord_access, "_account", return_value=self.account
            ),
            discord_access._private_directory_descriptor() as (path, descriptor),
        ):
            self.assertEqual(path, self.expected)
            self.assertTrue(os.fstat(descriptor).st_mode)
        self.assertEqual(self.expected.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.expected.parent.stat().st_mode & 0o777, 0o700)

    def test_rejects_symlinked_ancestor_before_any_outside_write(self) -> None:
        library = self.home / "Library"
        library.mkdir(mode=0o700)
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (library / "Application Support").symlink_to(outside, target_is_directory=True)
        with (
            mock.patch.object(discord_access, "CONFIG", self.config),
            mock.patch.object(
                discord_access, "_account", return_value=self.account
            ),
            self.assertRaisesRegex(RuntimeError, "ancestry cannot be opened safely"),
            discord_access._private_directory_descriptor(),
        ):
            pass
        self.assertFalse((outside / "Threadkeep").exists())


class ExecIntercept(Exception):
    pass


class ClaudeCredentialExecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.runtime = self.root / "runtime"
        self.plugin_bin = self.runtime / "bin"
        self.plugin_bin.mkdir(parents=True, mode=0o700)
        self.binary = self.root / "claude"
        self.binary.write_bytes(b"reviewed")
        self.binary.chmod(0o500)
        account = discord_access._account()
        self.source = {
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "SHELL": "/bin/zsh",
            "PATH": discord_access.CLEAN_PATH,
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "THREADKEEP_REPO_ROOT": str(REPO_ROOT),
            "THREADKEEP_CONFIG": str(REPO_ROOT / "config.toml"),
            "PYTHONPATH": str(REPO_ROOT / "conversations"),
        }
        self.config = SimpleNamespace(
            paths=SimpleNamespace(
                workspace_root=self.workspace,
                conversations_dir=self.workspace / "conversations",
            ),
            discord=SimpleNamespace(
                owner_user_id=OWNER_ID,
                application_id=APPLICATION_ID,
                bot_user_id=BOT_ID,
                guild_id=GUILD_ID,
                chat_channel_id=CHAT_ID,
                errors_channel_id=ERRORS_ID,
                token_env_var="DISCORD_BOT_TOKEN",
                plugin_state_dir=self.state,
            ),
            runtime=SimpleNamespace(
                timezone="America/New_York",
                use_dangerously_skip_permissions=True,
            ),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @contextmanager
    def state_descriptor(self):
        descriptor = os.open(
            self.state,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            yield self.state, descriptor
        finally:
            os.close(descriptor)

    def test_execve_receives_keychain_token_only_in_final_environment(self) -> None:
        events: list[str] = []
        policy_environment = {
            "THREADKEEP_VAULT_ROOT": str(self.workspace),
            "THREADKEEP_VAULT_POLICY_BINDING": '{"version":1}',
            "THREADKEEP_VAULT_POLICY_SNAPSHOT": str(
                self.state / "policy/vault-p0.md"
            ),
            "THREADKEEP_VAULT_POLICY_SNAPSHOT_SHA256": "a" * 64,
            "THREADKEEP_VAULT_POLICY_SOURCE_SHA256": "b" * 64,
            "THREADKEEP_VAULT_POLICY_PROMPT": str(
                self.state / "policy/claude-listener-system.md"
            ),
            "THREADKEEP_VAULT_POLICY_PROMPT_SHA256": "c" * 64,
            "THREADKEEP_POLICY_BOOTSTRAP_WORKSPACE": str(
                REPO_ROOT / "cx-chat-listener"
            ),
        }
        runtime_policy = SimpleNamespace(
            prompt_path=self.state / "policy/claude-listener-system.md",
            environment=lambda: policy_environment,
        )

        def load_token(*, allow_environment: bool) -> str:
            self.assertFalse(allow_environment)
            events.append("token")
            return "private-keychain-token"

        def intercept_exec(*_args):
            events.append("exec")
            raise ExecIntercept

        with (
            mock.patch.object(discord_access, "CONFIG", self.config),
            mock.patch.object(
                discord_access, "_private_directory_descriptor",
                side_effect=self.state_descriptor,
            ),
            mock.patch.object(discord_access, "verify", side_effect=lambda: events.append("policy")),
            mock.patch.object(
                discord_access.claude_cli,
                "verify",
                side_effect=lambda _path: {
                    "canonical_path": str(self.binary)
                },
            ),
            mock.patch.object(
                discord_access.claude_plugin,
                "verify_runtime",
                return_value=self.runtime,
            ),
            mock.patch.object(discord_access, "_validate_config_file"),
            mock.patch.object(
                discord_access.listener_contract,
                "validate_runtime_policy",
                side_effect=lambda **_kwargs: (
                    events.append("vault-policy") or runtime_policy
                ),
            ),
            mock.patch.object(
                discord_access, "load_discord_token", side_effect=load_token
            ),
            mock.patch.object(
                discord_access.os, "execve", side_effect=intercept_exec
            ) as execve,
            self.assertRaises(ExecIntercept),
        ):
            discord_access.exec_reviewed_claude(
                self.binary,
                self.plugin_bin,
                source=self.source,
            )
        executable, arguments, environment = execve.call_args.args
        self.assertEqual(executable, self.binary)
        self.assertEqual(arguments[0], str(self.binary))
        self.assertNotIn("private-keychain-token", "\0".join(arguments))
        self.assertEqual(environment["DISCORD_BOT_TOKEN"], "private-keychain-token")
        self.assertEqual(environment["TMPDIR"], str(self.state / "runtime-tmp"))
        self.assertEqual((self.state / "runtime-tmp").stat().st_mode & 0o777, 0o700)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("ANTHROPIC_API_KEY", environment)
        self.assertEqual(
            environment["THREADKEEP_VAULT_POLICY_BINDING"], '{"version":1}'
        )
        self.assertEqual(events[-3:], ["vault-policy", "token", "exec"])
        self.assertFalse((self.state / ".env").exists())

    def test_unreviewed_wrapper_environment_fails_before_keychain(self) -> None:
        poisoned = dict(self.source)
        poisoned["DISCORD_BOT_TOKEN"] = "ambient-secret"
        with (
            mock.patch.object(discord_access, "CONFIG", self.config),
            mock.patch.object(discord_access, "verify"),
            mock.patch.object(
                discord_access.claude_cli,
                "verify",
                return_value={"canonical_path": str(self.binary)},
            ),
            mock.patch.object(
                discord_access.claude_plugin,
                "verify_runtime",
                return_value=self.runtime,
            ),
            mock.patch.object(discord_access, "_validate_config_file"),
            mock.patch.object(discord_access, "load_discord_token") as token,
            mock.patch.object(discord_access.os, "execve") as execve,
            self.assertRaisesRegex(RuntimeError, "forbidden secret"),
        ):
            discord_access.exec_reviewed_claude(
                self.binary,
                self.plugin_bin,
                source=poisoned,
            )
        token.assert_not_called()
        execve.assert_not_called()


class ClaudeDestinationTests(unittest.TestCase):
    def test_principal_requires_exact_bot_and_application(self) -> None:
        responses = [
            {"id": BOT_ID, "bot": True},
            {"id": APPLICATION_ID},
        ]
        with (
            mock.patch.object(discord_destination, "CONFIG", _config()),
            mock.patch.object(
                discord_destination, "json_request", side_effect=responses
            ) as request,
        ):
            discord_destination.validate_principal("token")
        self.assertEqual(
            [call.args[1] for call in request.call_args_list],
            ["/users/@me", "/oauth2/applications/@me"],
        )

    def test_unregistered_destination_is_rejected_before_network(self) -> None:
        with (
            mock.patch.object(discord_destination, "CONFIG", _config()),
            mock.patch.object(
                discord_destination.lib, "thread_to_session", return_value=None
            ),
            mock.patch.object(discord_destination, "json_request") as request,
            self.assertRaisesRegex(RuntimeError, "not a registered Threadkeep thread"),
        ):
            discord_destination.validate_destination("token", THREAD_ID)
        request.assert_not_called()

    def test_registered_thread_must_be_public_child_of_claude_channel(self) -> None:
        wrong_parent = {
            "id": THREAD_ID,
            "guild_id": GUILD_ID,
            "type": 11,
            "parent_id": ERRORS_ID,
        }
        with (
            mock.patch.object(discord_destination, "CONFIG", _config()),
            mock.patch.object(
                discord_destination.lib, "thread_to_session", return_value="session"
            ),
            mock.patch.object(
                discord_destination, "json_request", return_value=wrong_parent
            ),
            self.assertRaisesRegex(RuntimeError, "not a public child"),
        ):
            discord_destination.validate_destination("token", THREAD_ID)

    def test_thread_anchor_must_belong_to_owner(self) -> None:
        message = {"author": {"id": BOT_ID}}
        with (
            mock.patch.object(discord_destination, "CONFIG", _config()),
            mock.patch.object(
                discord_destination, "json_request", return_value=message
            ),
            self.assertRaisesRegex(RuntimeError, "was not posted by the configured owner"),
        ):
            discord_destination.validate_owner_anchor("token", CHAT_ID, MESSAGE_ID)


class DirectDiscordTransportTests(unittest.TestCase):
    def test_shared_http_rejects_ambient_https_proxy_before_network(self) -> None:
        with (
            mock.patch.object(
                discord_http.urllib.request,
                "getproxies",
                return_value={"https": "https://proxy.invalid"},
            ),
            mock.patch.object(discord_http, "direct_urlopen") as open_url,
            self.assertRaisesRegex(RuntimeError, "refuses ambient proxy"),
        ):
            discord_http.request("GET", "/users/@me", "secret")
        open_url.assert_not_called()

    def test_shared_http_uses_empty_proxy_and_redirect_denial_handlers(self) -> None:
        request = discord_http.urllib.request.Request(
            "https://discord.com/api/v10/test"
        )
        opener = mock.Mock()
        with mock.patch.object(
            discord_http.urllib.request, "build_opener", return_value=opener
        ) as build_opener:
            discord_http.direct_urlopen(request, timeout=20)
        proxy_handler, redirect_handler = build_opener.call_args.args
        self.assertIsInstance(proxy_handler, discord_http.urllib.request.ProxyHandler)
        self.assertEqual(proxy_handler.proxies, {})
        self.assertIsInstance(redirect_handler, discord_http.NoRedirectHandler)
        opener.open.assert_called_once_with(request, timeout=20)

    def test_shared_http_refuses_redirect_before_forwarding_headers(self) -> None:
        request = discord_http.urllib.request.Request(
            "https://discord.com/api/v10/test",
            headers={"Authorization": "Bot test-only-value"},
        )
        handler = discord_http.NoRedirectHandler()
        with self.assertRaises(discord_http.urllib.error.HTTPError) as raised:
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {"Location": "https://attacker.invalid/collect"},
                "https://attacker.invalid/collect",
            )
        self.assertEqual(raised.exception.url, request.full_url)
        raised.exception.close()

    def test_shared_http_never_retries_a_redirect(self) -> None:
        redirect = discord_http.urllib.error.HTTPError(
            "https://discord.com/api/v10/test",
            302,
            "Found",
            {"Location": "https://attacker.invalid/collect"},
            io.BytesIO(b"redirect refused"),
        )
        with mock.patch.object(
            discord_http, "direct_urlopen", side_effect=redirect
        ) as open_url, self.assertRaises(discord_http.DiscordHTTPError) as raised:
            discord_http.request(
                "POST",
                "/test",
                "private-bot-token",
                max_attempts=1,
            )
        self.assertEqual(raised.exception.status, 302)
        open_url.assert_called_once()

    def test_shared_http_rejects_multi_attempt_post_before_network(self) -> None:
        with (
            mock.patch.object(discord_http.urllib.request, "getproxies", return_value={}),
            mock.patch.object(discord_http, "direct_urlopen") as open_url,
            self.assertRaisesRegex(ValueError, "require max_attempts=1"),
        ):
            discord_http.request("POST", "/test", "private-bot-token")
        open_url.assert_not_called()

    def test_shared_http_quarantines_post_timeout_without_retry(self) -> None:
        with (
            mock.patch.object(discord_http.urllib.request, "getproxies", return_value={}),
            mock.patch.object(
                discord_http, "direct_urlopen", side_effect=TimeoutError("lost response")
            ) as open_url,
            self.assertRaisesRegex(
                discord_http.DiscordPOSTAmbiguousError, "outcome is unknown"
            ),
        ):
            discord_http.request(
                "POST", "/test", "private-bot-token", max_attempts=1
            )
        open_url.assert_called_once()

    def test_shared_http_quarantines_post_server_error_without_retry(self) -> None:
        unavailable = discord_http.urllib.error.HTTPError(
            "https://discord.com/api/v10/test",
            503,
            "Unavailable",
            {},
            io.BytesIO(b"temporary failure"),
        )
        with (
            mock.patch.object(discord_http.urllib.request, "getproxies", return_value={}),
            mock.patch.object(
                discord_http, "direct_urlopen", side_effect=unavailable
            ) as open_url,
            self.assertRaisesRegex(
                discord_http.DiscordPOSTAmbiguousError, "outcome is unknown"
            ),
        ):
            discord_http.request(
                "POST", "/test", "private-bot-token", max_attempts=1
            )
        open_url.assert_called_once()

    def test_gateway_websockets_explicitly_disable_proxy_discovery(self) -> None:
        source = (REPO_ROOT / "discord-gateway" / "client.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("proxy=None", source)


class ClaudeApprovalPublicationTests(unittest.TestCase):
    def test_sensitive_review_fails_before_credentials_or_network(self) -> None:
        exchange = json.dumps(
            {
                "draft": "send this to person@example.com",
                "action": "outbound send",
                "target": "public destination",
            }
        )
        argv = [
            "request_approval.py",
            "--channel-id",
            THREAD_ID,
            "--approval-exchange-id",
            "a" * 32,
        ]
        configured = _config()
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(request_approval, "CONFIG", configured),
            mock.patch.object(request_approval, "DEFAULT_APPROVER", OWNER_ID),
            mock.patch.object(
                request_approval.safe_files, "read", return_value=exchange
            ),
            mock.patch.object(request_approval, "load_discord_token") as token,
            mock.patch.object(request_approval, "send_approval_prompt") as send,
            self.assertRaisesRegex(SystemExit, "sensitive-data filter"),
        ):
            request_approval.main()
        token.assert_not_called()
        send.assert_not_called()


class GenericDiscordSendTests(unittest.TestCase):
    def test_send_is_one_attempt_and_validates_the_returned_message(self) -> None:
        response = {
            "id": MESSAGE_ID,
            "channel_id": ERRORS_ID,
            "content": "service degraded",
            "author": {"id": BOT_ID},
        }
        with (
            mock.patch.object(discord_send, "CONFIG", _config()),
            mock.patch.object(
                discord_send, "json_request", return_value=response
            ) as request,
        ):
            self.assertEqual(
                discord_send.send_message(
                    ERRORS_ID, "service degraded", "private-bot-token"
                ),
                response,
            )
        self.assertEqual(request.call_args.args[:3], (
            "POST",
            f"/channels/{ERRORS_ID}/messages",
            "private-bot-token",
        ))
        self.assertEqual(request.call_args.kwargs["max_attempts"], 1)

    def test_send_rejects_requested_retries_before_network(self) -> None:
        with (
            mock.patch.object(discord_send, "json_request") as request,
            self.assertRaisesRegex(ValueError, "retries are disabled"),
        ):
            discord_send.send_message(
                ERRORS_ID,
                "service degraded",
                "private-bot-token",
                max_retries=1,
            )
        request.assert_not_called()

    def test_send_quarantines_an_unbound_success_response(self) -> None:
        with (
            mock.patch.object(discord_send, "CONFIG", _config()),
            mock.patch.object(discord_send, "json_request", return_value={}),
            self.assertRaisesRegex(
                discord_http.DiscordPOSTAmbiguousError, "could not be bound"
            ),
        ):
            discord_send.send_message(
                ERRORS_ID, "service degraded", "private-bot-token"
            )


if __name__ == "__main__":
    unittest.main()
