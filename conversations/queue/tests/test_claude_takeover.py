from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import pwd
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[2] / "claude_takeover.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("claude_takeover_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
takeover_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = takeover_module
SPEC.loader.exec_module(takeover_module)

LegacyInventory = takeover_module.LegacyInventory
MAINTENANCE_PHRASE = takeover_module.MAINTENANCE_PHRASE
Takeover = takeover_module.Takeover
TakeoverError = takeover_module.TakeoverError
UnsafeRollback = takeover_module.UnsafeRollback

ROOT_CHANNEL = "10000000000000001"
THREAD_CHANNEL = "10000000000000002"
OWNER = "10000000000000003"
OTHER = "10000000000000004"


def message(
    message_id: str,
    channel_id: str,
    *,
    author: str = OWNER,
    content: str = "hello",
    bot: bool = False,
) -> dict[str, Any]:
    return {
        "id": message_id,
        "channel_id": channel_id,
        "content": content,
        "timestamp": "2026-08-29T12:00:00+00:00",
        "author": {
            "id": author,
            "username": "owner" if author == OWNER else "someone",
            "bot": bot,
        },
        "attachments": [],
    }


class FakeDiscord:
    def __init__(self, by_channel: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.by_channel = by_channel or {}
        self.reactions: list[tuple[str, str]] = []
        self.fail_capture = False
        self.mutate_payload_on_reaction = False

    def capture_upper(self, channel_ids: Sequence[str], lower: str) -> str:
        if self.fail_capture:
            raise TakeoverError("synthetic Discord failure")
        values = [int(lower)]
        for channel_id in channel_ids:
            values.extend(int(value["id"]) for value in self.by_channel.get(channel_id, []))
        return str(max(values))

    def messages_between(
        self, channel_id: str, lower: str, upper: str
    ) -> list[dict[str, Any]]:
        return [
            value
            for value in self.by_channel.get(channel_id, [])
            if int(lower) < int(value["id"]) <= int(upper)
        ]

    def add_eyes(self, channel_id: str, message_id: str) -> None:
        pair = (channel_id, message_id)
        if pair not in self.reactions:
            self.reactions.append(pair)
        if self.mutate_payload_on_reaction:
            for value in self.by_channel.get(channel_id, []):
                if value.get("id") == message_id:
                    value["reactions"] = [{"emoji": {"name": "👀"}, "count": 1}]


class FakeHost:
    def __init__(
        self, plist_paths: list[Path], queue_db: Path, receipt_path: Path
    ) -> None:
        self.plist_paths = plist_paths
        self.queue_db = queue_db
        self.receipt_path = receipt_path
        self.calls: list[str] = []
        self.fail_stop_label: str | None = None
        self.fail_verify = False
        self.replacement_present = False
        self.fail_drain_before_accept = False
        self.fail_drain_after_accept = False
        self.expire_drain_response = False
        self.leave_backlog = False
        self.drain_receipt: dict[str, Any] | None = None
        self.gateway_original: bytes | None = None

    def prove_replacement_absent(
        self, *, label_prefix: str, session: str, repo_root: Path
    ) -> float:
        self.calls.append("prove:replacement-absent")
        if self.replacement_present:
            raise TakeoverError("synthetic replacement already running")

    def inspect_legacy(self, *, plist_dir: Path, workspace_root: Path) -> LegacyInventory:
        self.calls.append("inspect")
        return LegacyInventory(
            labels=takeover_module.LEGACY_LABELS,
            plist_paths=tuple(str(path) for path in self.plist_paths),
            plist_sha256s=tuple(
                hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.plist_paths
            ),
            tmux_session="cx-chat",
            pane_pid=500,
            pane_pgid=500,
            pane_command=(
                "claude --dangerously-skip-permissions --channels "
                "plugin:discord@claude-plugins-official"
            ),
            pane_cwd=str(workspace_root),
            process_ids=(500,),
            process_commands=("claude --channels plugin:discord@claude-plugins-official",),
        )

    def stop_label(self, label: str) -> None:
        self.calls.append(f"stop:{label}")
        if label == self.fail_stop_label:
            raise TakeoverError("synthetic launchctl failure")

    def stop_legacy_session(self, inventory: LegacyInventory) -> None:
        self.calls.append("stop:tmux")

    def prove_legacy_stopped(self, inventory: LegacyInventory) -> None:
        self.calls.append("prove:legacy-stopped")

    def restart_legacy(self, inventory: LegacyInventory) -> None:
        self.calls.append("restart:legacy")

    def mark_gateway_session_fresh(self, path: Path, backup_dir: Path) -> None:
        self.calls.append("gateway:fresh")
        if path.exists():
            self.gateway_original = path.read_bytes()
            path.unlink()

    def restore_gateway_state(self, path: Path, backup_dir: Path) -> None:
        self.calls.append("gateway:restore")
        source = backup_dir / "new-gateway-state" / path.name
        path.parent.mkdir(parents=True, exist_ok=True)
        if source.exists():
            path.write_bytes(source.read_bytes())
            os.chmod(path, 0o600)
        else:
            path.unlink(missing_ok=True)

    def verify_replacement(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
    ) -> None:
        self.calls.append("verify:replacement")
        if self.fail_verify:
            raise TakeoverError("synthetic readiness failure")

    def run_takeover_drain(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
        challenge: str,
        issued_at: float,
        expires_at: float,
    ) -> None:
        self.calls.append("drain:replacement")
        self.drain_receipt = takeover_module._read_private_json(self.receipt_path)
        if self.fail_drain_before_accept:
            raise TakeoverError("synthetic pre-accept drain failure")
        if not self.leave_backlog:
            connection = sqlite3.connect(self.queue_db)
            connection.execute(
                "UPDATE messages SET state='spawned',updated_at=updated_at+1 "
                "WHERE state NOT IN ('done','errored','spawned')"
            )
            connection.commit()
            connection.close()
        if self.fail_drain_after_accept:
            raise TakeoverError("synthetic post-accept drain failure")
        if self.expire_drain_response:
            return expires_at + 1
        return issued_at + 1

    def stop_replacement(
        self,
        *,
        label_prefix: str,
        session: str,
        repo_root: Path,
        workspace_root: Path,
    ) -> None:
        self.calls.append("stop:replacement")


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="discoparty-takeover-")
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "TheSystem"
        self.conversations = self.workspace / "x_System/Assistant/conversations"
        self.state = self.conversations / "state"
        self.active = self.conversations / "active"
        self.archived = self.conversations / "archived"
        for path in (self.state, self.active, self.archived):
            path.mkdir(parents=True, mode=0o700)
        self.registry = self.conversations / "_registry.json"
        self.registry.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "conversations": {"session": {"thread_id": THREAD_CHANNEL}},
                    "by_thread": {THREAD_CHANNEL: "session"},
                }
            )
            + "\n"
        )
        (self.active / "session.md").write_text("# Active\n")
        (self.archived / "old.md").write_text("# Archived\n")
        self.queue_db = self.state / "mq.sqlite3"
        self._create_queue()
        self.approvals = self.workspace / "x_System/Assistant/discord-gateway"
        (self.approvals / "approvals").mkdir(parents=True)
        (self.approvals / "approvals/legacy.json").write_text(
            json.dumps({"status": "approved", "old_schema": True}) + "\n"
        )
        self.plist_dir = self.root / "Library/LaunchAgents"
        self.plist_dir.mkdir(parents=True)
        self.plists: list[Path] = []
        for label in takeover_module.LEGACY_LABELS:
            path = self.plist_dir / f"{label}.plist"
            path.write_text(f"plist:{label}\n")
            self.plists.append(path)
        self.repo = self.root / "discoparty"
        (self.repo / "discord-gateway/state").mkdir(parents=True)
        (self.repo / "cx-chat-listener").mkdir()
        (self.repo / "cx-launcher.sh").write_text("#!/bin/sh\n")
        self.gateway_state = self.repo / "discord-gateway/state/gateway.json"
        self.gateway_state.write_text('{"session_id":"old","seq":9}\n')
        os.chmod(self.gateway_state, 0o600)
        self.backups = self.state / "takeover-backups"
        self.receipt = self.state / "takeover/receipt.json"
        self.host = FakeHost(self.plists, self.queue_db, self.receipt)

    def close(self) -> None:
        self.temporary.cleanup()

    def _create_queue(self) -> None:
        connection = sqlite3.connect(self.queue_db)
        connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                chat_id TEXT NOT NULL,
                user TEXT,
                ts TEXT,
                body TEXT NOT NULL,
                kind TEXT,
                title TEXT,
                state TEXT NOT NULL,
                session_id TEXT,
                thread_id TEXT,
                error TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                received_at REAL NOT NULL,
                acked_at REAL,
                claimed_at REAL,
                dispatched_at REAL,
                updated_at REAL NOT NULL,
                dead_letter_acked_at REAL,
                completion_token TEXT,
                response_sha256 TEXT,
                response_message_id TEXT,
                response_content TEXT,
                response_nonce TEXT,
                response_attempted_at REAL,
                response_ambiguous_at REAL,
                response_confirmed_at REAL
            );
            CREATE TABLE dispatch_operations (
                message_id TEXT PRIMARY KEY,
                state TEXT NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO messages "
            "(message_id,chat_id,user,body,state,received_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            ("10000000000000010", ROOT_CHANNEL, "owner", "old", "done", 1.0, 1.0),
        )
        connection.commit()
        connection.close()
        os.chmod(self.queue_db, 0o600)

    def add_queue(self, message_id: str, state: str, *, operation: str | None = None) -> None:
        connection = sqlite3.connect(self.queue_db)
        connection.execute(
            "INSERT INTO messages "
            "(message_id,chat_id,user,body,state,received_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (message_id, ROOT_CHANNEL, "owner", state, state, 2.0, 2.0),
        )
        if operation is not None:
            connection.execute(
                "INSERT INTO dispatch_operations(message_id,state) VALUES(?,?)",
                (message_id, operation),
            )
        connection.commit()
        connection.close()

    def prepare(self, discord: FakeDiscord | None = None) -> tuple[Takeover, dict[str, Any]]:
        engine = Takeover(self.host, discord or FakeDiscord())
        connection = sqlite3.connect(self.queue_db)
        connection.row_factory = sqlite3.Row
        plan = takeover_module.queue_takeover_plan(connection)
        connection.close()
        receipt = engine.prepare(
            explicit_opt_in=True,
            quarantine_opt_in=True,
            maintenance_phrase=MAINTENANCE_PHRASE,
            quarantine_acknowledgment=plan["acknowledgment"],
            expected_plan_sha256=plan["snapshot_sha256"],
            workspace_root=self.workspace,
            conversations_dir=self.conversations,
            queue_db=self.queue_db,
            backup_root=self.backups,
            receipt_path=self.receipt,
            plist_dir=self.plist_dir,
            legacy_approval_root=self.approvals,
            new_gateway_state=self.gateway_state,
            root_channel=ROOT_CHANNEL,
            owner_user_id=OWNER,
            new_label_prefix="com.discoparty",
            new_session="discoparty-chat",
            repo_root=self.repo,
        )
        return engine, receipt


class TakeoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_exact_phrase_and_two_opt_ins_precede_host_mutation(self) -> None:
        engine = Takeover(self.fixture.host, FakeDiscord())
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.row_factory = sqlite3.Row
        plan = takeover_module.queue_takeover_plan(connection)
        connection.close()
        common = {
            "workspace_root": self.fixture.workspace,
            "conversations_dir": self.fixture.conversations,
            "queue_db": self.fixture.queue_db,
            "backup_root": self.fixture.backups,
            "receipt_path": self.fixture.receipt,
            "plist_dir": self.fixture.plist_dir,
            "legacy_approval_root": self.fixture.approvals,
            "new_gateway_state": self.fixture.gateway_state,
            "root_channel": ROOT_CHANNEL,
            "owner_user_id": OWNER,
            "new_label_prefix": "com.discoparty",
            "new_session": "discoparty-chat",
            "repo_root": self.fixture.repo,
        }
        with self.assertRaises(TakeoverError):
            engine.prepare(
                explicit_opt_in=True,
                quarantine_opt_in=True,
                maintenance_phrase="yes",
                quarantine_acknowledgment=plan["acknowledgment"],
                expected_plan_sha256=plan["snapshot_sha256"],
                **common,
            )
        with self.assertRaises(TakeoverError):
            engine.prepare(
                explicit_opt_in=True,
                quarantine_opt_in=False,
                maintenance_phrase=MAINTENANCE_PHRASE,
                quarantine_acknowledgment=plan["acknowledgment"],
                expected_plan_sha256=plan["snapshot_sha256"],
                **common,
            )
        self.assertEqual(self.fixture.host.calls, [])

    def test_existing_replacement_blocks_before_legacy_inspection_or_stop(self) -> None:
        self.fixture.host.replacement_present = True
        with self.assertRaisesRegex(TakeoverError, "already running"):
            self.fixture.prepare()
        self.assertEqual(
            self.fixture.host.calls,
            ["prove:replacement-absent"],
        )
        self.assertFalse(self.fixture.receipt.exists())

    def test_replacement_process_contract_rejects_resume_or_wrong_prompt(self) -> None:
        repo = self.fixture.repo.resolve()
        workspace = self.fixture.workspace.resolve()
        binary = (
            Path(pwd.getpwuid(os.getuid()).pw_dir)
            / ".local/share/claude/versions/2.1.251"
        )
        runtime_prompt = (
            Path(pwd.getpwuid(os.getuid()).pw_dir)
            / "Library/Application Support/Discoparty/claude-discord"
            / takeover_module.listener_contract.POLICY_DIRECTORY_NAME
            / takeover_module.listener_contract.RUNTIME_PROMPT_NAME
        )
        common = shlex.join(
            [
                str(binary),
                "--dangerously-skip-permissions",
                "--permission-mode",
                "bypassPermissions",
                "--channels",
                "plugin:discord@claude-plugins-official",
                "--append-system-prompt-file",
                str(runtime_prompt),
                "--append-subagent-system-prompt",
                takeover_module.listener_contract.SUBAGENT_POLICY_PROMPT,
                "--add-dir",
                str(repo),
                "--add-dir",
                str(workspace),
                "--strict-mcp-config",
                "--setting-sources",
                "--no-chrome",
                "--disallowedTools",
                takeover_module.REPLACEMENT_DISCORD_EGRESS_TOOLS,
            ]
        )
        self.assertTrue(
            takeover_module._reviewed_replacement_listener(
                common, repo, workspace
            )
        )
        exact_arguments = shlex.split(common)
        exact_arguments.insert(exact_arguments.index("--setting-sources") + 1, "")
        self.assertTrue(
            takeover_module._reviewed_replacement_arguments(
                exact_arguments, repo, workspace
            )
        )
        self.assertFalse(
            takeover_module._reviewed_replacement_arguments(
                [*exact_arguments, "--resume", "attacker"], repo, workspace
            )
        )
        self.assertFalse(
            takeover_module._reviewed_replacement_listener(
                common + " --resume attacker", repo, workspace
            )
        )
        self.assertFalse(
            takeover_module._reviewed_replacement_listener(
                common.replace(
                    takeover_module.listener_contract.RUNTIME_PROMPT_NAME,
                    "other.md",
                ),
                repo,
                workspace,
            )
        )
        self.assertFalse(
            takeover_module._reviewed_replacement_listener(
                common + " --mcp-config /tmp/evil", repo, workspace
            )
        )

    @unittest.skipUnless(sys.platform == "darwin", "KERN_PROCARGS2 is macOS-only")
    def test_exact_process_argv_preserves_spaces_and_empty_values(self) -> None:
        expected_tail = (
            "-c",
            "import time; time.sleep(2)",
            "argument with spaces",
            "",
            "after",
        )
        child = subprocess.Popen([sys.executable, *expected_tail])
        try:
            observed = takeover_module.MacHost._process_arguments(child.pid)
        finally:
            child.terminate()
            child.wait(timeout=5)
        self.assertEqual(observed[1:], expected_tail)

    def test_legacy_stop_proof_blocks_captured_pid_even_after_exec(self) -> None:
        host = takeover_module.MacHost.__new__(takeover_module.MacHost)
        host.tmux = "/fake/tmux"
        host._loaded = lambda _label: False
        host._process_table = lambda: [(500, 1, 500, "/unexpected/reexec")]
        inventory = LegacyInventory(
            labels=takeover_module.LEGACY_LABELS,
            plist_paths=tuple("/unused" for _ in takeover_module.LEGACY_LABELS),
            plist_sha256s=tuple("0" * 64 for _ in takeover_module.LEGACY_LABELS),
            tmux_session="cx-chat",
            pane_pid=500,
            pane_pgid=500,
            pane_command="claude",
            pane_cwd="/workspace",
            process_ids=(500,),
            process_commands=("claude",),
        )
        absent_session = subprocess.CompletedProcess([], 1, "", "")
        with (
            mock.patch.object(takeover_module, "_run", return_value=absent_session),
            self.assertRaisesRegex(TakeoverError, "captured legacy descendants"),
        ):
            host.prove_legacy_stopped(inventory)

    def test_legacy_stop_proof_blocks_surviving_process_group(self) -> None:
        host = takeover_module.MacHost.__new__(takeover_module.MacHost)
        host.tmux = "/fake/tmux"
        host._loaded = lambda _label: False
        host._process_table = list
        inventory = LegacyInventory(
            labels=takeover_module.LEGACY_LABELS,
            plist_paths=tuple("/unused" for _ in takeover_module.LEGACY_LABELS),
            plist_sha256s=tuple("0" * 64 for _ in takeover_module.LEGACY_LABELS),
            tmux_session="cx-chat",
            pane_pid=500,
            pane_pgid=500,
            pane_command="claude",
            pane_cwd="/workspace",
            process_ids=(500,),
            process_commands=("claude",),
        )
        absent_session = subprocess.CompletedProcess([], 1, "", "")
        with (
            mock.patch.object(takeover_module, "_run", return_value=absent_session),
            mock.patch.object(takeover_module.os, "killpg", return_value=None),
            self.assertRaisesRegex(TakeoverError, "process group remains"),
        ):
            host.prove_legacy_stopped(inventory)

    def test_replacement_rollback_stops_healthcheck_first_and_proves_tree_gone(self) -> None:
        host = takeover_module.MacHost.__new__(takeover_module.MacHost)
        host.launchctl = "/fake/launchctl"
        host.tmux = "/fake/tmux"
        repo = self.fixture.repo.resolve()
        workspace = self.fixture.workspace.resolve()
        pane_pid = 900
        pane_group = 901
        events: list[str] = []
        loaded_values = iter((True, False, True, False))
        host._loaded = lambda label: (
            events.append(f"loaded:{label}") or next(loaded_values)
        )
        process_values = iter(
            (
                [(pane_pid, 1, pane_group, "flattened command")],
                [],
            )
        )
        host._process_table = lambda: next(process_values)
        host._process_arguments = lambda _pid: tuple(
            takeover_module._expected_replacement_arguments(repo, workspace)
        )

        session_checks = iter((0, 1))

        def fake_run(arguments, *, check=True, **_kwargs):
            events.append("run:" + " ".join(arguments))
            if "has-session" in arguments:
                return subprocess.CompletedProcess(
                    arguments, next(session_checks), "", ""
                )
            if "list-panes" in arguments:
                stdout = (
                    f"{pane_pid}\t{repo / 'cx-launcher.sh'}\t"
                    f"{repo / 'cx-chat-listener'}\n"
                )
                return subprocess.CompletedProcess(arguments, 0, stdout, "")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        def fake_killpg(_group, sent_signal):
            events.append(f"signal:{sent_signal}")
            if sent_signal == 0:
                raise ProcessLookupError

        with (
            mock.patch.object(takeover_module, "_run", side_effect=fake_run),
            mock.patch.object(takeover_module.os, "killpg", side_effect=fake_killpg),
        ):
            host.stop_replacement(
                label_prefix="com.discoparty",
                session="discoparty-chat",
                repo_root=repo,
                workspace_root=workspace,
            )
        health_bootout = next(
            index
            for index, event in enumerate(events)
            if "bootout" in event and "cx-chat-healthcheck" in event
        )
        gateway_bootout = next(
            index
            for index, event in enumerate(events)
            if "bootout" in event and "discord-gateway-client" in event
        )
        kill_session = next(
            index for index, event in enumerate(events) if "kill-session" in event
        )
        self.assertLess(health_bootout, gateway_bootout)
        self.assertLess(gateway_bootout, kill_session)
        self.assertIn(f"signal:{takeover_module.signal.SIGTERM}", events)

    def test_shutdown_order_backup_manifest_and_gateway_reset(self) -> None:
        _, receipt = self.fixture.prepare()
        expected = ["prove:replacement-absent", "inspect"] + [
            f"stop:{label}" for label in takeover_module.LEGACY_STOP_ORDER
        ] + ["stop:tmux", "prove:legacy-stopped", "gateway:fresh"]
        self.assertEqual(self.fixture.host.calls, expected)
        self.assertEqual(self.fixture.host.calls[2], "stop:" + takeover_module.HEALTHCHECK_LABEL)
        backup = Path(receipt["backup_dir"])
        takeover_module.verify_backup(backup)
        self.assertTrue((backup / "sqlite/mq.sqlite3.snapshot").is_file())
        self.assertTrue((backup / "sqlite/raw/mq.sqlite3").is_file())
        self.assertTrue((backup / "conversations/_registry.json").is_file())
        self.assertTrue((backup / "conversations/active/session.md").is_file())
        self.assertTrue((backup / "conversations/archived/old.md").is_file())
        self.assertTrue((backup / "legacy-plists" / self.fixture.plists[0].name).is_file())
        approval = json.loads((backup / "legacy-approval-quarantine.json").read_text())
        self.assertEqual(approval["files"][0]["disposition"], "quarantined-never-imported")
        self.assertFalse(self.fixture.gateway_state.exists())
        manifest = json.loads((backup / "manifest.json").read_text())
        for entry in manifest["files"]:
            path = backup / entry["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])

    def test_ambiguous_rows_quarantine_received_and_ledger_claim_resume(self) -> None:
        self.fixture.add_queue("10000000000000011", "received")
        self.fixture.add_queue("10000000000000012", "claimed", operation="prepared")
        self.fixture.add_queue("10000000000000013", "claimed")
        self.fixture.add_queue("10000000000000014", "dispatched")
        _, receipt = self.fixture.prepare()
        classification = receipt["classification"]
        self.assertEqual(
            classification["resumable"],
            ("10000000000000011", "10000000000000012"),
        )
        self.assertEqual(
            classification["quarantine"],
            ("10000000000000013", "10000000000000014"),
        )
        connection = sqlite3.connect(self.fixture.queue_db)
        values = dict(
            connection.execute(
                "SELECT message_id,state FROM messages WHERE message_id>=?",
                ("10000000000000011",),
            )
        )
        quarantined = connection.execute(
            "SELECT COUNT(*) FROM takeover_quarantine"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(values["10000000000000011"], "received")
        self.assertEqual(values["10000000000000012"], "claimed")
        self.assertEqual(values["10000000000000013"], "errored")
        self.assertEqual(values["10000000000000014"], "errored")
        self.assertEqual(quarantined, 2)
        frozen = json.loads(
            (
                Path(receipt["backup_dir"]) / "queue-nonterminal-snapshot.json"
            ).read_text()
        )
        frozen_by_id = {row["message_id"]: row for row in frozen["messages"]}
        self.assertEqual(frozen_by_id["10000000000000013"]["state"], "claimed")
        self.assertEqual(frozen_by_id["10000000000000014"]["state"], "dispatched")
        takeover_module.verify_backup(Path(receipt["backup_dir"]))

    def test_quarantine_requires_the_exact_acknowledged_counts(self) -> None:
        self.fixture.add_queue("10000000000000011", "claimed")
        self.fixture.add_queue("10000000000000012", "dispatched")
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.row_factory = sqlite3.Row
        plan = takeover_module.queue_takeover_plan(connection)
        connection.close()
        self.assertEqual(plan["claimed_without_ledger"], 1)
        self.assertEqual(plan["dispatched"], 1)
        engine = Takeover(self.fixture.host, FakeDiscord())
        with self.assertRaises(TakeoverError):
            engine.prepare(
                explicit_opt_in=True,
                quarantine_opt_in=True,
                maintenance_phrase=MAINTENANCE_PHRASE,
                quarantine_acknowledgment=(
                    "QUARANTINE 0 CLAIMED-WITHOUT-LEDGER AND 2 DISPATCHED "
                    "ROWS FOR MANUAL REVIEW"
                ),
                expected_plan_sha256=plan["snapshot_sha256"],
                workspace_root=self.fixture.workspace,
                conversations_dir=self.fixture.conversations,
                queue_db=self.fixture.queue_db,
                backup_root=self.fixture.backups,
                receipt_path=self.fixture.receipt,
                plist_dir=self.fixture.plist_dir,
                legacy_approval_root=self.fixture.approvals,
                new_gateway_state=self.fixture.gateway_state,
                root_channel=ROOT_CHANNEL,
                owner_user_id=OWNER,
                new_label_prefix="com.discoparty",
                new_session="discoparty-chat",
                repo_root=self.fixture.repo,
            )
        connection = sqlite3.connect(self.fixture.queue_db)
        states = dict(connection.execute("SELECT message_id,state FROM messages"))
        connection.close()
        self.assertEqual(states["10000000000000011"], "claimed")
        self.assertEqual(states["10000000000000012"], "dispatched")
        self.assertEqual(self.fixture.host.calls, [])

    def test_queue_drift_after_count_plan_fails_before_quarantine(self) -> None:
        self.fixture.add_queue("10000000000000011", "dispatched")
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.row_factory = sqlite3.Row
        plan = takeover_module.queue_takeover_plan(connection)
        connection.execute(
            "UPDATE messages SET body='changed-after-plan' "
            "WHERE message_id='10000000000000011'"
        )
        connection.commit()
        connection.close()
        engine = Takeover(self.fixture.host, FakeDiscord())
        with self.assertRaises(TakeoverError):
            engine.prepare(
                explicit_opt_in=True,
                quarantine_opt_in=True,
                maintenance_phrase=MAINTENANCE_PHRASE,
                quarantine_acknowledgment=plan["acknowledgment"],
                expected_plan_sha256=plan["snapshot_sha256"],
                workspace_root=self.fixture.workspace,
                conversations_dir=self.fixture.conversations,
                queue_db=self.fixture.queue_db,
                backup_root=self.fixture.backups,
                receipt_path=self.fixture.receipt,
                plist_dir=self.fixture.plist_dir,
                legacy_approval_root=self.fixture.approvals,
                new_gateway_state=self.fixture.gateway_state,
                root_channel=ROOT_CHANNEL,
                owner_user_id=OWNER,
                new_label_prefix="com.discoparty",
                new_session="discoparty-chat",
                repo_root=self.fixture.repo,
            )
        connection = sqlite3.connect(self.fixture.queue_db)
        state = connection.execute(
            "SELECT state FROM messages WHERE message_id='10000000000000011'"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(state, "dispatched")
        self.assertEqual(self.fixture.host.calls, [])

    def test_spawned_row_is_a_pre_mutation_hard_block(self) -> None:
        self.fixture.add_queue("10000000000000011", "spawned")
        with self.assertRaises(TakeoverError):
            self.fixture.prepare()
        self.assertEqual(self.fixture.host.calls, [])
        connection = sqlite3.connect(self.fixture.queue_db)
        state = connection.execute(
            "SELECT state FROM messages WHERE message_id='10000000000000011'"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(state, "spawned")

    def test_unknown_dispatch_operation_state_is_a_hard_block(self) -> None:
        self.fixture.add_queue(
            "10000000000000011", "claimed", operation="future-unknown"
        )
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.row_factory = sqlite3.Row
        classification = takeover_module.classify_queue(connection)
        connection.close()
        self.assertEqual(classification.blockers, ("10000000000000011",))
        self.assertIn("unknown operation state", classification.reasons["10000000000000011"])
        with self.assertRaises(TakeoverError):
            self.fixture.prepare()
        self.assertEqual(self.fixture.host.calls, [])

    def test_failure_after_quiescence_restarts_legacy(self) -> None:
        discord = FakeDiscord()
        discord.fail_capture = True
        with self.assertRaises(TakeoverError):
            self.fixture.prepare(discord)
        self.assertEqual(self.fixture.host.calls[-2:], ["gateway:restore", "restart:legacy"])

    def test_owner_only_gap_reconciliation_is_lossless_and_idempotent(self) -> None:
        discord = FakeDiscord(
            {
                ROOT_CHANNEL: [
                    message("10000000000000011", ROOT_CHANNEL, content="root"),
                    message("10000000000000012", ROOT_CHANNEL, author=OTHER),
                ],
                THREAD_CHANNEL: [
                    message("10000000000000013", THREAD_CHANNEL, content="reply"),
                    message("10000000000000014", THREAD_CHANNEL, author=OTHER),
                ],
            }
        )
        engine, receipt = self.fixture.prepare(discord)
        self.assertEqual(
            receipt["initial_reconciled"],
            ["10000000000000011", "10000000000000013"],
        )
        self.assertEqual(
            discord.reactions,
            [
                (ROOT_CHANNEL, "10000000000000011"),
                (THREAD_CHANNEL, "10000000000000013"),
            ],
        )
        engine.begin_replacement(self.fixture.receipt)
        committed = engine.finalize(self.fixture.receipt)
        self.assertEqual(committed["final_reconciled"], [])
        connection = sqlite3.connect(self.fixture.queue_db)
        rows = connection.execute(
            "SELECT message_id,chat_id,body FROM messages ORDER BY message_id"
        ).fetchall()
        raw_count = connection.execute(
            "SELECT COUNT(*) FROM takeover_reconciled_messages"
        ).fetchone()[0]
        connection.close()
        self.assertEqual([row[0] for row in rows], [
            "10000000000000010",
            "10000000000000011",
            "10000000000000013",
        ])
        self.assertEqual(rows[1][2], "root")
        self.assertEqual(rows[2][2], "reply")
        self.assertEqual(raw_count, 2)
        self.assertEqual(self.fixture.host.calls.count("verify:replacement"), 2)

    def test_global_lower_uses_quietest_registered_channel_cursor(self) -> None:
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.execute(
            "INSERT INTO messages "
            "(message_id,chat_id,user,body,state,received_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            ("10000000000000030", ROOT_CHANNEL, "owner", "root", "done", 3.0, 3.0),
        )
        connection.execute(
            "INSERT INTO messages "
            "(message_id,chat_id,user,body,state,received_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                "10000000000000020",
                THREAD_CHANNEL,
                "owner",
                "thread",
                "done",
                2.0,
                2.0,
            ),
        )
        connection.commit()
        connection.close()
        discord = FakeDiscord(
            {
                ROOT_CHANNEL: [
                    message("10000000000000035", ROOT_CHANNEL, content="new root")
                ],
                THREAD_CHANNEL: [
                    message(
                        "10000000000000025",
                        THREAD_CHANNEL,
                        content="quiet-thread gap",
                    )
                ],
            }
        )
        _, receipt = self.fixture.prepare(discord)
        self.assertEqual(receipt["maintenance_lower"], "10000000000000020")
        self.assertEqual(
            receipt["initial_reconciled"],
            ["10000000000000025", "10000000000000035"],
        )

    def test_reconciler_rejects_message_outside_closed_window(self) -> None:
        discord = FakeDiscord()
        discord.messages_between = lambda _channel, _lower, _upper: [
            message("10000000000000010", ROOT_CHANNEL)
        ]
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.row_factory = sqlite3.Row
        with self.assertRaisesRegex(TakeoverError, "captured bounds"):
            takeover_module.reconcile_window(
                connection,
                discord,
                channel_ids=[ROOT_CHANNEL],
                root_channel=ROOT_CHANNEL,
                owner_user_id=OWNER,
                lower="10000000000000010",
                upper="10000000000000020",
                takeover_id="test",
            )
        connection.close()

    def test_final_overlap_adds_each_message_once(self) -> None:
        discord = FakeDiscord()
        engine, _ = self.fixture.prepare(discord)
        engine.begin_replacement(self.fixture.receipt)
        discord.by_channel[ROOT_CHANNEL] = [
            message("10000000000000011", ROOT_CHANNEL, content="during cutover")
        ]
        result = engine.finalize(self.fixture.receipt)
        self.assertEqual(result["final_reconciled"], ["10000000000000011"])
        connection = sqlite3.connect(self.fixture.queue_db)
        count = connection.execute(
            "SELECT COUNT(*) FROM messages WHERE message_id='10000000000000011'"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(count, 1)

    def test_reaction_mutation_does_not_change_message_binding(self) -> None:
        discord = FakeDiscord(
            {ROOT_CHANNEL: [message("10000000000000011", ROOT_CHANNEL)]}
        )
        discord.mutate_payload_on_reaction = True
        engine, _ = self.fixture.prepare(discord)
        engine.begin_replacement(self.fixture.receipt)
        result = engine.finalize(self.fixture.receipt)
        self.assertEqual(result["phase"], "committed")
        self.assertEqual(result["final_reconciled"], [])

    def test_finalize_persists_fresh_single_use_drain_before_command(self) -> None:
        self.fixture.add_queue("10000000000000011", "received")
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        result = engine.finalize(self.fixture.receipt)
        observed = self.fixture.host.drain_receipt
        self.assertIsNotNone(observed)
        assert observed is not None
        self.assertEqual(observed["phase"], "replacement-draining")
        handshake = observed["drain_handshake"]
        self.assertEqual(handshake["status"], "issued")
        self.assertRegex(handshake["challenge"], r"^[a-f0-9]{64}$")
        self.assertEqual(
            handshake["expires_at"] - handshake["issued_at"],
            takeover_module.TAKEOVER_DRAIN_TTL_SECONDS,
        )
        self.assertEqual(result["drain_handshake"]["status"], "consumed")
        self.assertEqual(result["phase"], "committed")
        self.assertEqual(self.fixture.receipt.stat().st_mode & 0o777, 0o600)
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.row_factory = sqlite3.Row
        self.assertEqual(takeover_module.safe_pre_dispatch_backlog(connection), [])
        connection.close()
        with self.assertRaises(TakeoverError):
            engine.finalize(self.fixture.receipt)

    def test_post_prepare_transitions_refuse_a_competing_process(self) -> None:
        engine, _ = self.fixture.prepare()
        lock_path = self.fixture.receipt.parent / ".takeover.lock"
        descriptor = os.open(lock_path, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(TakeoverError, "holds the lock"):
                engine.begin_replacement(self.fixture.receipt)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertEqual(
            takeover_module._read_private_json(self.fixture.receipt)["phase"],
            "prepared",
        )

    def test_false_drain_completion_cannot_commit_with_safe_backlog(self) -> None:
        self.fixture.add_queue("10000000000000011", "received")
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        self.fixture.host.leave_backlog = True
        with self.assertRaisesRegex(TakeoverError, "safe pre-dispatch work"):
            engine.finalize(self.fixture.receipt)
        receipt = takeover_module._read_private_json(self.fixture.receipt)
        self.assertEqual(receipt["phase"], "replacement-draining")
        self.assertEqual(receipt["drain_handshake"]["status"], "responded")

    def test_drain_completion_after_deadline_cannot_commit(self) -> None:
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        self.fixture.host.expire_drain_response = True
        with self.assertRaisesRegex(TakeoverError, "freshness window"):
            engine.finalize(self.fixture.receipt)
        receipt = takeover_module._read_private_json(self.fixture.receipt)
        self.assertEqual(receipt["phase"], "replacement-draining")
        self.assertEqual(
            receipt["drain_handshake"]["status"], "expired-response"
        )
        rolled_back = engine.abort(self.fixture.receipt)
        self.assertEqual(rolled_back["phase"], "rolled-back")

    def test_drain_failure_before_acceptance_rolls_legacy_back(self) -> None:
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        self.fixture.host.fail_drain_before_accept = True
        with self.assertRaisesRegex(TakeoverError, "pre-accept"):
            engine.finalize(self.fixture.receipt)
        rolled_back = engine.abort(self.fixture.receipt)
        self.assertEqual(rolled_back["phase"], "rolled-back")
        self.assertIn("stop:replacement", self.fixture.host.calls)
        self.assertIn("restart:legacy", self.fixture.host.calls)

    def test_drain_failure_after_acceptance_forbids_legacy_restart(self) -> None:
        self.fixture.add_queue("10000000000000011", "received")
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        self.fixture.host.fail_drain_after_accept = True
        with self.assertRaisesRegex(TakeoverError, "post-accept"):
            engine.finalize(self.fixture.receipt)
        with self.assertRaises(UnsafeRollback):
            engine.abort(self.fixture.receipt)
        self.assertNotIn("stop:replacement", self.fixture.host.calls)
        self.assertNotIn("restart:legacy", self.fixture.host.calls)
        receipt = takeover_module._read_private_json(self.fixture.receipt)
        self.assertEqual(receipt["phase"], "manual-recovery-required")

    def test_discord_history_paginates_backward_without_a_hundred_message_gap(self) -> None:
        client = takeover_module.DiscordREST.__new__(takeover_module.DiscordREST)
        all_messages = [
            message(str(10000000000000000 + offset), ROOT_CHANNEL)
            for offset in range(11, 162)
        ]

        def fake_list(path: str) -> list[dict[str, Any]]:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            before = int(query["before"][0])
            limit = int(query["limit"][0])
            eligible = [item for item in all_messages if int(item["id"]) < before]
            return sorted(eligible, key=lambda item: int(item["id"]), reverse=True)[:limit]

        client._list = fake_list
        values = client.messages_between(
            ROOT_CHANNEL, "10000000000000010", "10000000000000161"
        )
        self.assertEqual(len(values), 151)
        self.assertEqual(values[0]["id"], "10000000000000011")
        self.assertEqual(values[-1]["id"], "10000000000000161")

    def test_rollback_before_acceptance_restores_quarantine_and_gateway(self) -> None:
        self.fixture.add_queue("10000000000000011", "dispatched")
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        result = engine.abort(self.fixture.receipt)
        self.assertEqual(result["phase"], "rolled-back")
        self.assertIn("stop:replacement", self.fixture.host.calls)
        self.assertEqual(self.fixture.host.calls[-1], "restart:legacy")
        self.assertEqual(
            self.fixture.gateway_state.read_text(),
            '{"session_id":"old","seq":9}\n',
        )
        connection = sqlite3.connect(self.fixture.queue_db)
        state = connection.execute(
            "SELECT state FROM messages WHERE message_id='10000000000000011'"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(state, "dispatched")

    def test_interrupted_prestart_phase_remains_safely_rollbackable(self) -> None:
        self.fixture.add_queue("10000000000000011", "dispatched")
        engine, _ = self.fixture.prepare()
        receipt = takeover_module._read_private_json(self.fixture.receipt)
        receipt["phase"] = "gateway-resetting"
        takeover_module._save_receipt(self.fixture.receipt, receipt)
        result = engine.abort(self.fixture.receipt)
        self.assertEqual(result["phase"], "rolled-back")
        self.assertEqual(self.fixture.host.calls[-1], "restart:legacy")
        connection = sqlite3.connect(self.fixture.queue_db)
        state = connection.execute(
            "SELECT state FROM messages WHERE message_id='10000000000000011'"
        ).fetchone()[0]
        connection.close()
        self.assertEqual(state, "dispatched")

    def test_rollback_is_forbidden_after_new_row_acceptance(self) -> None:
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.execute(
            "INSERT INTO messages "
            "(message_id,chat_id,user,body,state,received_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            ("10000000000000011", ROOT_CHANNEL, "owner", "new", "received", 9.0, 9.0),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(UnsafeRollback):
            engine.abort(self.fixture.receipt)
        self.assertNotIn("stop:replacement", self.fixture.host.calls)
        self.assertNotIn("restart:legacy", self.fixture.host.calls)
        receipt = takeover_module._read_private_json(self.fixture.receipt)
        self.assertEqual(receipt["phase"], "manual-recovery-required")

    def test_rollback_is_forbidden_after_existing_row_transition(self) -> None:
        self.fixture.add_queue("10000000000000011", "received")
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        connection = sqlite3.connect(self.fixture.queue_db)
        connection.execute(
            "UPDATE messages SET state='claimed',updated_at=99 "
            "WHERE message_id='10000000000000011'"
        )
        connection.commit()
        connection.close()
        with self.assertRaises(UnsafeRollback):
            engine.abort(self.fixture.receipt)
        self.assertNotIn("restart:legacy", self.fixture.host.calls)

    def test_committed_takeover_can_never_auto_rollback(self) -> None:
        engine, _ = self.fixture.prepare()
        engine.begin_replacement(self.fixture.receipt)
        engine.finalize(self.fixture.receipt)
        with self.assertRaises(UnsafeRollback):
            engine.abort(self.fixture.receipt)
        self.assertNotIn("restart:legacy", self.fixture.host.calls)

    def test_receipt_tampering_fails_closed(self) -> None:
        engine, _ = self.fixture.prepare()
        value = json.loads(self.fixture.receipt.read_text())
        value["phase"] = "committed"
        self.fixture.receipt.write_text(json.dumps(value) + "\n")
        os.chmod(self.fixture.receipt, 0o600)
        with self.assertRaises(TakeoverError):
            engine.begin_replacement(self.fixture.receipt)

    def test_wrong_conversation_root_is_refused_before_inspection(self) -> None:
        wrong = self.fixture.workspace / "conversations"
        wrong.mkdir()
        engine = Takeover(self.fixture.host, FakeDiscord())
        with self.assertRaises(TakeoverError):
            engine.prepare(
                explicit_opt_in=True,
                quarantine_opt_in=True,
                maintenance_phrase=MAINTENANCE_PHRASE,
                quarantine_acknowledgment="QUARANTINE 0 CLAIMED-WITHOUT-LEDGER AND 0 DISPATCHED ROWS FOR MANUAL REVIEW",
                expected_plan_sha256="0" * 64,
                workspace_root=self.fixture.workspace,
                conversations_dir=wrong,
                queue_db=self.fixture.queue_db,
                backup_root=self.fixture.backups,
                receipt_path=self.fixture.receipt,
                plist_dir=self.fixture.plist_dir,
                legacy_approval_root=self.fixture.approvals,
                new_gateway_state=self.fixture.gateway_state,
                root_channel=ROOT_CHANNEL,
                owner_user_id=OWNER,
                new_label_prefix="com.discoparty",
                new_session="discoparty-chat",
                repo_root=self.fixture.repo,
            )
        self.assertEqual(self.fixture.host.calls, [])


if __name__ == "__main__":
    unittest.main()
