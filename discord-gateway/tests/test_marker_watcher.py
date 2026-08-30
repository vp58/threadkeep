#!/usr/bin/env python3
"""Security and reliability tests for marker-watcher.py."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import logging
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
WATCHER_PATH = HERE.parent / "marker-watcher.py"

OWNER_ID = "111111111111111111"
APPLICATION_ID = "222222222222222222"
GUILD_ID = "333333333333333333"
BOT_USER_ID = "444444444444444444"
CHANNEL_ID = "555555555555555555"
MESSAGE_ID = "666666666666666666"
INTERACTION_ID = "777777777777777777"

os.environ.setdefault("DISCOPARTY_CONFIG", str(HERE.parent.parent / "config.example.toml"))
os.environ.setdefault("DISCOPARTY_OWNER_USER_ID", OWNER_ID)
os.environ.setdefault("DISCOPARTY_DISCORD_APPLICATION_ID", APPLICATION_ID)
os.environ.setdefault("DISCOPARTY_DISCORD_GUILD_ID", GUILD_ID)
os.environ.setdefault("DISCOPARTY_DISCORD_BOT_USER_ID", BOT_USER_ID)


def load_watcher_module():
    spec = importlib.util.spec_from_file_location("marker_watcher", str(WATCHER_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class MarkerWatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="marker-watcher-test-"))
        self.mod = load_watcher_module()
        self.mod.APPROVALS_DIR = self.tmpdir / "approvals"
        self.mod.PENDING_DIR = self.tmpdir / "pending"
        self.mod.COMPLETED_DIR = self.tmpdir / "completed"
        self.mod.FAILED_DIR = self.tmpdir / "failed"
        self.mod.PROCESSED_MARKERS_DIR = self.tmpdir / "processed-markers"
        self.mod.INFLIGHT_DIR = self.tmpdir / "inflight"
        self.mod.LOG_DIR = self.tmpdir / "logs"
        self.mod.LOG_PATH = self.mod.LOG_DIR / "marker-watcher.log"
        self.mod.CONFIG = SimpleNamespace(
            discord=SimpleNamespace(
                owner_user_id=OWNER_ID,
                application_id=APPLICATION_ID,
                guild_id=GUILD_ID,
                bot_user_id=BOT_USER_ID,
            )
        )
        self.mod.ensure_dirs()
        self.logger = logging.getLogger(f"marker-watcher-test-{id(self)}")
        self.logger.addHandler(logging.NullHandler())
        self.mod.ORPHAN_GRACE_SEC = 0

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def records(
        self,
        *,
        draft: str = "exact approved outbound draft",
        operation: str = "slack_post",
        target: str = "C0123456789",
        status: str = "approved",
    ) -> tuple[str, dict, dict]:
        full_sha = hashlib.sha256(draft.encode("utf-8")).hexdigest()
        sha_prefix = full_sha[:12]
        created = datetime.now(timezone.utc) - timedelta(seconds=5)
        binding = {
            "version": self.mod.BINDING_VERSION,
            "sha_prefix": sha_prefix,
            "full_sha": full_sha,
            "approver_user_id": OWNER_ID,
            "expected_application_id": APPLICATION_ID,
            "expected_guild_id": GUILD_ID,
            "expected_bot_user_id": BOT_USER_ID,
            "discord_prompt_channel_id": CHANNEL_ID,
            "discord_prompt_message_id": MESSAGE_ID,
            "request_action": operation,
            "request_target": target,
            "created_at": created.isoformat(),
            "expires_at": int(time.time()) + 3600,
        }
        binding["binding_sha256"] = self.mod._canonical_digest(binding)
        action = "approve" if status == "approved" else "reject"
        marker = {
            "version": self.mod.MARKER_VERSION,
            "status": status,
            "action": action,
            "sha_prefix": sha_prefix,
            "full_sha": full_sha,
            "interaction_id": INTERACTION_ID,
            "user_id": OWNER_ID,
            "application_id": APPLICATION_ID,
            "guild_id": GUILD_ID,
            "bot_user_id": BOT_USER_ID,
            "channel_id": CHANNEL_ID,
            "message_id": MESSAGE_ID,
            "request_action": operation,
            "request_target": target,
            "binding_sha256": binding["binding_sha256"],
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        pending = {
            "version": self.mod.PENDING_VERSION,
            "status": "pending",
            "operation": operation,
            "draft": draft,
            "binding": binding,
        }
        return sha_prefix, marker, pending

    def write_records(
        self,
        *,
        draft: str = "exact approved outbound draft",
        operation: str = "slack_post",
        target: str = "C0123456789",
        status: str = "approved",
    ) -> tuple[str, Path, Path, dict, dict]:
        sha, marker, pending = self.records(
            draft=draft,
            operation=operation,
            target=target,
            status=status,
        )
        marker_path = self.mod.APPROVALS_DIR / f"{sha}.json"
        pending_path = self.mod.PENDING_DIR / f"{sha}.json"
        self.mod.atomic_write_json(marker_path, marker)
        self.mod.atomic_write_json(pending_path, pending)
        return sha, marker_path, pending_path, marker, pending

    def rewrite_binding_digest(self, pending: dict) -> None:
        unsigned = dict(pending["binding"])
        unsigned.pop("binding_sha256", None)
        pending["binding"]["binding_sha256"] = self.mod._canonical_digest(unsigned)

    def assert_rejected_without_execution(
        self,
        sha: str,
        marker: dict,
        pending: dict,
    ) -> None:
        marker_path = self.mod.APPROVALS_DIR / f"{sha}.json"
        pending_path = self.mod.PENDING_DIR / f"{sha}.json"
        self.mod.atomic_write_json(marker_path, marker)
        self.mod.atomic_write_json(pending_path, pending)
        with mock.patch.object(self.mod, "run_outbound_command") as run, \
                mock.patch.object(self.mod, "fetch_message_content") as fetch, \
                mock.patch.object(self.mod, "edit_discord_message") as edit:
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        run.assert_not_called()
        fetch.assert_not_called()
        edit.assert_not_called()
        self.assertTrue(pending_path.exists(), "invalid approval must preserve pending state")
        self.assertTrue((self.mod.PROCESSED_MARKERS_DIR / marker_path.name).exists())

    def test_approved_marker_invokes_gate_with_sealed_execution_manifest(self) -> None:
        sha, _marker_path, pending_path, _marker, pending = self.write_records()
        captured: dict = {}

        def fake_run(cmd: list[str], _timeout: int):
            manifest_path = Path(cmd[cmd.index("--pending-json") + 1])
            captured["cmd"] = cmd
            captured["path"] = manifest_path
            captured["mode"] = stat.S_IMODE(manifest_path.stat().st_mode)
            captured["manifest"] = json.loads(manifest_path.read_text())
            return mock.Mock(returncode=0, stdout="ok", stderr="")

        with mock.patch.object(self.mod, "SLACK_GATE", "/tmp/fake-slack-gate.py"), \
                mock.patch.object(self.mod, "run_outbound_command", side_effect=fake_run), \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value=""):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)

        self.assertEqual(captured["mode"], 0o400)
        self.assertNotIn(str(pending_path), captured["cmd"])
        self.assertFalse(captured["path"].exists())
        manifest = captured["manifest"]
        digest = manifest.pop("execution_manifest_sha256")
        self.assertEqual(digest, self.mod._canonical_digest(manifest))
        self.assertEqual(manifest["draft"], pending["draft"])
        self.assertEqual(manifest["binding"], pending["binding"])
        self.assertEqual(manifest["decision"]["interaction_id"], INTERACTION_ID)
        self.assertFalse(pending_path.exists())
        self.assertTrue((self.mod.COMPLETED_DIR / f"{sha}.json").exists())

    def test_gate_failure_writes_failed_record(self) -> None:
        sha, _marker_path, pending_path, _marker, _pending = self.write_records()
        fake_proc = mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch.object(self.mod, "SLACK_GATE", "/tmp/fake-slack-gate.py"), \
                mock.patch.object(self.mod, "run_outbound_command", return_value=fake_proc), \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value="approved"):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        self.assertTrue((self.mod.FAILED_DIR / f"{sha}.json").exists())
        self.assertFalse(pending_path.exists())

    def test_exact_rejected_marker_clears_pending_without_send(self) -> None:
        sha, marker_path, pending_path, _marker, _pending = self.write_records(
            status="rejected"
        )
        with mock.patch.object(self.mod, "run_outbound_command") as run:
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        run.assert_not_called()
        self.assertFalse(marker_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertTrue((self.mod.PROCESSED_MARKERS_DIR / f"{sha}.json").exists())

    def test_forged_rejection_preserves_pending(self) -> None:
        sha, marker, pending = self.records(status="rejected")
        marker["user_id"] = "999999999999999999"
        self.assert_rejected_without_execution(sha, marker, pending)

    def test_orphan_marker_is_archived_without_send(self) -> None:
        sha, marker, _pending = self.records()
        self.mod.atomic_write_json(self.mod.APPROVALS_DIR / f"{sha}.json", marker)
        with mock.patch.object(self.mod, "run_outbound_command") as run:
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        run.assert_not_called()
        self.assertTrue((self.mod.PROCESSED_MARKERS_DIR / f"{sha}.json").exists())

    def test_known_operation_without_configured_gate_fails_closed(self) -> None:
        sha, _marker_path, pending_path, _marker, _pending = self.write_records()
        with mock.patch.object(self.mod, "SLACK_GATE", ""), \
                mock.patch.object(self.mod, "EMAIL_GATE", ""), \
                mock.patch.object(self.mod, "run_outbound_command") as run, \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value=""):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        run.assert_not_called()
        self.assertFalse(pending_path.exists())
        self.assertTrue((self.mod.FAILED_DIR / f"{sha}.json").exists())

    def test_unknown_operation_never_reaches_a_gate(self) -> None:
        sha, marker, pending = self.records()
        pending["operation"] = "slack_delete"
        self.assert_rejected_without_execution(sha, marker, pending)

    def test_operation_must_equal_frozen_request_action(self) -> None:
        sha, marker, pending = self.records()
        pending["operation"] = "gmail_send"
        self.assert_rejected_without_execution(sha, marker, pending)

    def test_pending_draft_must_match_approved_sha(self) -> None:
        sha, marker, pending = self.records()
        pending["draft"] = "substituted outbound content"
        self.assert_rejected_without_execution(sha, marker, pending)

    def test_marker_exact_schema_and_status_are_enforced(self) -> None:
        mutations = {
            "extra field": lambda marker: marker.__setitem__("extra", True),
            "missing field": lambda marker: marker.pop("guild_id"),
            "wrong version": lambda marker: marker.__setitem__("version", 1),
            "mismatched action": lambda marker: marker.__setitem__("action", "reject"),
            "unknown status": lambda marker: marker.__setitem__("status", "done"),
            "bad interaction": lambda marker: marker.__setitem__("interaction_id", "7"),
            "bad timestamp": lambda marker: marker.__setitem__("ts", "yesterday"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                sha, marker, pending = self.records(draft=f"draft for {label}")
                mutate(marker)
                self.assertIsNotNone(
                    self.mod.validate_approval_binding(sha, marker, pending)
                )

    def test_pending_exact_schema_version_and_status_are_enforced(self) -> None:
        mutations = {
            "extra field": lambda pending: pending.__setitem__("extra", True),
            "missing field": lambda pending: pending.pop("draft"),
            "wrong version": lambda pending: pending.__setitem__("version", 1),
            "wrong status": lambda pending: pending.__setitem__("status", "approved"),
            "non-object binding": lambda pending: pending.__setitem__("binding", []),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                sha, marker, pending = self.records(draft=f"draft for {label}")
                mutate(pending)
                self.assertIsNotNone(
                    self.mod.validate_approval_binding(sha, marker, pending)
                )

    def test_every_marker_binding_field_is_immutable(self) -> None:
        replacements = {
            "sha_prefix": "abcdef012345",
            "full_sha": "a" * 64,
            "user_id": "999999999999999999",
            "application_id": "999999999999999999",
            "guild_id": "999999999999999999",
            "bot_user_id": "999999999999999999",
            "channel_id": "999999999999999999",
            "message_id": "999999999999999999",
            "request_action": "gmail_send",
            "request_target": "attacker@example.com",
            "binding_sha256": "f" * 64,
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                sha, marker, pending = self.records(draft=f"marker field {field}")
                marker[field] = replacement
                error = self.mod.validate_approval_binding(sha, marker, pending)
                self.assertIsNotNone(error)
                self.assertIn(field, error)

    def test_every_pending_binding_field_is_recomputed_and_rebound(self) -> None:
        replacements = {
            "sha_prefix": "abcdef012345",
            "full_sha": None,
            "approver_user_id": "999999999999999999",
            "expected_application_id": "999999999999999999",
            "expected_guild_id": "999999999999999999",
            "expected_bot_user_id": "999999999999999999",
            "discord_prompt_channel_id": "999999999999999999",
            "discord_prompt_message_id": "999999999999999999",
            "request_action": "gmail_send",
            "request_target": "attacker@example.com",
        }
        for field, replacement in replacements.items():
            with self.subTest(field=field):
                sha, marker, pending = self.records(draft=f"binding field {field}")
                if field == "full_sha":
                    replacement = sha + ("0" * (64 - len(sha)))
                pending["binding"][field] = replacement
                self.rewrite_binding_digest(pending)
                error = self.mod.validate_approval_binding(sha, marker, pending)
                self.assertIsNotNone(error)

    def test_binding_digest_covers_created_expiry_and_all_control_fields(self) -> None:
        sha, marker, original = self.records()
        fields = set(self.mod.BINDING_KEYS) - {"binding_sha256"}
        for field in fields:
            with self.subTest(field=field):
                pending = copy.deepcopy(original)
                value = pending["binding"][field]
                if isinstance(value, int):
                    pending["binding"][field] = value + 1
                elif isinstance(value, str):
                    pending["binding"][field] = value + "x"
                else:
                    self.fail(f"unhandled binding fixture type for {field}")
                error = self.mod.validate_approval_binding(sha, marker, pending)
                if field == "version":
                    self.assertEqual(error, "pending approval binding version is invalid")
                else:
                    self.assertEqual(error, "pending approval binding digest does not match")

    def test_current_principal_configuration_is_rechecked(self) -> None:
        sha, marker, pending = self.records()
        self.mod.CONFIG = SimpleNamespace(
            discord=SimpleNamespace(
                owner_user_id=OWNER_ID,
                application_id="999999999999999999",
                guild_id=GUILD_ID,
                bot_user_id=BOT_USER_ID,
            )
        )
        error = self.mod.validate_approval_binding(sha, marker, pending)
        self.assertIn("current configuration", error)

    def test_marker_outside_binding_lifetime_is_rejected(self) -> None:
        sha, marker, pending = self.records()
        marker["ts"] = (
            datetime.fromtimestamp(pending["binding"]["expires_at"], timezone.utc)
            + timedelta(seconds=1)
        ).isoformat()
        error = self.mod.validate_approval_binding(sha, marker, pending)
        self.assertIn("outside the binding lifetime", error)

    def test_interrupted_durable_claim_is_never_reexecuted(self) -> None:
        sha, _marker_path, _pending_path, _marker, _pending = self.write_records()
        with mock.patch.object(
            self.mod, "execute_send", side_effect=SystemExit("simulated crash")
        ):
            with self.assertRaisesRegex(SystemExit, "simulated crash"):
                self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)

        self.assertTrue((self.mod.INFLIGHT_DIR / f"{sha}.json").exists())
        self.assertTrue((self.mod.INFLIGHT_DIR / f"{sha}.execution.json").exists())
        with mock.patch.object(self.mod, "execute_send") as execute, \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value=""):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        execute.assert_not_called()
        failed = json.loads((self.mod.FAILED_DIR / f"{sha}.json").read_text())
        self.assertTrue(failed["result"]["uncertain"])
        self.assertFalse((self.mod.INFLIGHT_DIR / f"{sha}.json").exists())
        self.assertFalse((self.mod.INFLIGHT_DIR / f"{sha}.execution.json").exists())

    def test_existing_durable_result_fences_duplicate_marker(self) -> None:
        draft = "durable replay fence draft"
        sha, _marker_path, _pending_path, _marker, _pending = self.write_records(
            draft=draft
        )
        fake_proc = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(self.mod, "SLACK_GATE", "/tmp/fake-slack-gate.py"), \
                mock.patch.object(self.mod, "run_outbound_command", return_value=fake_proc), \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value=""):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)

        self.write_records(draft=draft)
        with mock.patch.object(self.mod, "execute_send") as execute:
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        execute.assert_not_called()
        self.assertFalse((self.mod.APPROVALS_DIR / f"{sha}.json").exists())
        self.assertFalse((self.mod.PENDING_DIR / f"{sha}.json").exists())

    def test_world_readable_marker_is_rejected(self) -> None:
        sha, marker_path, pending_path, _marker, _pending = self.write_records()
        marker_path.chmod(0o644)
        with mock.patch.object(self.mod, "execute_send") as execute:
            processed = self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        execute.assert_not_called()
        self.assertEqual(processed, 0)
        self.assertTrue(pending_path.exists())
        self.assertTrue((self.mod.PROCESSED_MARKERS_DIR / f"{sha}.json").exists())

    def test_control_directory_symlink_is_rejected(self) -> None:
        shutil.rmtree(self.mod.APPROVALS_DIR)
        target = self.tmpdir / "redirected"
        target.mkdir(mode=0o700)
        self.mod.APPROVALS_DIR.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "directory is unsafe"):
            self.mod.ensure_dirs()

    def test_discord_redirect_is_never_followed(self) -> None:
        redirect = self.mod.urllib.error.HTTPError(
            "https://discord.com/api/v10/test",
            302,
            "Found",
            {"Location": "https://attacker.invalid/collect"},
            io.BytesIO(b"redirect refused"),
        )
        with mock.patch.object(
            self.mod, "direct_urlopen", side_effect=redirect
        ) as open_url:
            self.mod.edit_discord_message(
                CHANNEL_ID,
                MESSAGE_ID,
                "safe content",
                "private-bot-token",
                self.logger,
            )
        open_url.assert_called_once()


if __name__ == "__main__":
    unittest.main()
