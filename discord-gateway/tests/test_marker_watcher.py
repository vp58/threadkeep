#!/usr/bin/env python3
"""Unit tests for marker-watcher.py.

These tests use a tmp dir and monkeypatch the module-level dir constants and
the SLACK_GATE / EMAIL_GATE env-var-derived paths. They mock subprocess.run
so the actual outbound scripts (whatever the user wires up) never fire.

Run:
    python3 -m unittest discord-gateway.tests.test_marker_watcher -v
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
WATCHER_PATH = HERE.parent / "marker-watcher.py"

os.environ.setdefault("DISCLAWD_CONFIG", str(HERE.parent.parent / "config.example.toml"))
os.environ.setdefault("DISCLAWD_OWNER_USER_ID", "111111111111111111")


def load_watcher_module():
    spec = importlib.util.spec_from_file_location("marker_watcher", str(WATCHER_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
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
        self.mod.LOG_DIR = self.tmpdir / "logs"
        self.mod.LOG_PATH = self.mod.LOG_DIR / "marker-watcher.log"
        self.mod.ensure_dirs()
        self.logger = self.mod.setup_logging()
        self.mod.ORPHAN_GRACE_SEC = 0

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def write_marker(self, sha: str, status: str = "approved") -> Path:
        path = self.mod.APPROVALS_DIR / f"{sha}.json"
        path.write_text(json.dumps({
            "status": status,
            "sha_prefix": sha,
            "channel_id": "100000000000000001",
            "message_id": "100000000000000002",
            "ts": "2026-05-22T18:34:27Z",
        }))
        return path

    def write_pending(self, sha: str, operation: str = "slack_post",
                      extra: dict | None = None) -> Path:
        payload = {
            "sha_prefix": sha,
            "full_sha": sha + ("0" * (64 - len(sha))),
            "operation": operation,
            "approver_user_id": "111111111111111111",
            "discord_prompt_channel_id": "100000000000000001",
            "discord_prompt_message_id": "100000000000000002",
            "created_at": "2026-05-22T18:30:00Z",
        }
        if extra:
            payload.update(extra)
        path = self.mod.PENDING_DIR / f"{sha}.json"
        path.write_text(json.dumps(payload))
        return path

    def test_approved_marker_invokes_configured_slack_gate(self) -> None:
        sha = "deadbeefcafe"
        self.write_marker(sha, "approved")
        self.write_pending(sha, "slack_post")
        fake_proc = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(self.mod, "SLACK_GATE", "/tmp/fake-slack-gate.py"), \
                mock.patch.object(self.mod.subprocess, "run", return_value=fake_proc) as m_run, \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value=""):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        self.assertTrue(m_run.called, "configured slack gate should have been invoked")
        cmd = m_run.call_args[0][0]
        self.assertIn("/tmp/fake-slack-gate.py", cmd)
        self.assertIn("--pending-json", cmd)
        self.assertFalse((self.mod.APPROVALS_DIR / f"{sha}.json").exists())
        self.assertFalse((self.mod.PENDING_DIR / f"{sha}.json").exists())
        self.assertTrue((self.mod.COMPLETED_DIR / f"{sha}.json").exists())

    def test_approved_marker_failure_writes_failed_record(self) -> None:
        sha = "f00dbaadcafe"
        self.write_marker(sha, "approved")
        self.write_pending(sha, "slack_post")
        fake_proc = mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch.object(self.mod, "SLACK_GATE", "/tmp/fake-slack-gate.py"), \
                mock.patch.object(self.mod.subprocess, "run", return_value=fake_proc), \
                mock.patch.object(self.mod, "edit_discord_message") as m_edit, \
                mock.patch.object(self.mod, "fetch_message_content", return_value="[APPROVED] hello"):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        self.assertTrue((self.mod.FAILED_DIR / f"{sha}.json").exists())
        self.assertFalse((self.mod.PENDING_DIR / f"{sha}.json").exists())
        last_content = m_edit.call_args[0][2]
        self.assertIn("[SEND FAILED", last_content)

    def test_rejected_marker_clears_pending_no_send(self) -> None:
        sha = "abcdef012345"
        self.write_marker(sha, "rejected")
        self.write_pending(sha, "slack_post")
        with mock.patch.object(self.mod, "SLACK_GATE", "/tmp/fake-slack-gate.py"), \
                mock.patch.object(self.mod.subprocess, "run") as m_run, \
                mock.patch.object(self.mod, "edit_discord_message"):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        self.assertFalse(m_run.called)
        self.assertFalse((self.mod.PENDING_DIR / f"{sha}.json").exists())
        self.assertFalse((self.mod.APPROVALS_DIR / f"{sha}.json").exists())

    def test_orphan_marker_no_pending_is_archived(self) -> None:
        sha = "0000aaaaffff"
        self.write_marker(sha, "approved")
        with mock.patch.object(self.mod.subprocess, "run") as m_run, \
                mock.patch.object(self.mod, "edit_discord_message"):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        self.assertFalse(m_run.called)
        self.assertFalse((self.mod.APPROVALS_DIR / f"{sha}.json").exists())
        self.assertTrue((self.mod.PROCESSED_MARKERS_DIR / f"{sha}.json").exists())

    def test_unknown_operation_writes_failed_record(self) -> None:
        sha = "deaddead1111"
        self.write_marker(sha, "approved")
        self.write_pending(sha, "not_a_real_op")
        with mock.patch.object(self.mod.subprocess, "run") as m_run, \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value=""):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        self.assertFalse(m_run.called)
        self.assertTrue((self.mod.FAILED_DIR / f"{sha}.json").exists())

    def test_no_gate_configured_for_op_writes_failed_record(self) -> None:
        sha = "abcd11112222"
        self.write_marker(sha, "approved")
        self.write_pending(sha, "slack_post")
        with mock.patch.object(self.mod, "SLACK_GATE", ""), \
                mock.patch.object(self.mod, "EMAIL_GATE", ""), \
                mock.patch.object(self.mod.subprocess, "run") as m_run, \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value=""):
            self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        self.assertFalse(m_run.called)
        self.assertTrue((self.mod.FAILED_DIR / f"{sha}.json").exists())

    def test_marker_handling_idempotent_on_second_scan(self) -> None:
        sha = "1234567890ab"
        self.write_marker(sha, "approved")
        self.write_pending(sha, "slack_post")
        fake_proc = mock.Mock(returncode=0, stdout="ok", stderr="")
        with mock.patch.object(self.mod, "SLACK_GATE", "/tmp/fake-slack-gate.py"), \
                mock.patch.object(self.mod.subprocess, "run", return_value=fake_proc), \
                mock.patch.object(self.mod, "edit_discord_message"), \
                mock.patch.object(self.mod, "fetch_message_content", return_value=""):
            n1 = self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
            n2 = self.mod.scan_once(self.logger, "fake-token", timeout_sec=10)
        self.assertEqual(n1, 1)
        self.assertEqual(n2, 0)


if __name__ == "__main__":
    unittest.main()
