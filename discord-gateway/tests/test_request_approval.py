#!/usr/bin/env python3
"""Tests for frozen approval manifests and immutable decision markers."""
from __future__ import annotations

import json
import io
import os
import stat
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(REPO_ROOT / "approval"))
os.environ.setdefault("THREADKEEP_CONFIG", str(REPO_ROOT / "config.example.toml"))
os.environ.setdefault("THREADKEEP_OWNER_USER_ID", "111111111111111111")

import request_approval as approval  # noqa: E402
import request_approval_responder as responder  # noqa: E402

SHA_PREFIX = "abcdef012345"
FULL_SHA = SHA_PREFIX + ("0" * (64 - len(SHA_PREFIX)))
OWNER_ID = "111111111111111111"
APPLICATION_ID = "222222222222222222"
GUILD_ID = "333333333333333333"
BOT_USER_ID = "444444444444444444"
CHANNEL_ID = "555555555555555555"
MESSAGE_ID = "666666666666666666"
INTERACTION_ID = "777777777777777777"


class ApprovalBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.bindings_dir = root / "approval-bindings"
        self.approvals_dir = root / "approvals"
        self.binding_patcher = mock.patch.object(
            approval, "APPROVAL_BINDINGS_DIR", self.bindings_dir
        )
        self.approval_patcher = mock.patch.object(
            approval, "APPROVALS_DIR", self.approvals_dir
        )
        self.responder_patcher = mock.patch.object(
            responder, "APPROVALS_DIR", self.approvals_dir
        )
        self.binding_patcher.start()
        self.approval_patcher.start()
        self.responder_patcher.start()
        self.binding = self.build_binding()

    def tearDown(self) -> None:
        self.binding_patcher.stop()
        self.approval_patcher.stop()
        self.responder_patcher.stop()
        self.temporary.cleanup()

    def build_binding(self, **updates) -> dict:
        values = {
            "sha_prefix": SHA_PREFIX,
            "full_sha": FULL_SHA,
            "approver_user_id": OWNER_ID,
            "expected_application_id": APPLICATION_ID,
            "expected_guild_id": GUILD_ID,
            "expected_bot_user_id": BOT_USER_ID,
            "channel_id": CHANNEL_ID,
            "message_id": MESSAGE_ID,
            "request_action": "outbound send",
            "request_target": "person@example.com",
            "expires_at": int(time.time()) + 600,
        }
        values.update(updates)
        return approval.build_approval_binding(**values)

    def marker(self, action: str = "approve") -> dict:
        return {
            "version": approval.MARKER_VERSION,
            "status": "approved" if action == "approve" else "rejected",
            "action": action,
            "sha_prefix": SHA_PREFIX,
            "full_sha": FULL_SHA,
            "interaction_id": INTERACTION_ID,
            "user_id": OWNER_ID,
            "application_id": APPLICATION_ID,
            "guild_id": GUILD_ID,
            "bot_user_id": BOT_USER_ID,
            "channel_id": CHANNEL_ID,
            "message_id": MESSAGE_ID,
            "request_action": "outbound send",
            "request_target": "person@example.com",
            "binding_sha256": self.binding["binding_sha256"],
            "ts": "2026-08-29T12:00:00+00:00",
        }

    def test_action_and_target_are_covered_by_binding_digest(self) -> None:
        changed_action = self.build_binding(request_action="gmail send")
        changed_target = self.build_binding(request_target="other@example.com")
        self.assertNotEqual(
            self.binding["binding_sha256"], changed_action["binding_sha256"]
        )
        self.assertNotEqual(
            self.binding["binding_sha256"], changed_target["binding_sha256"]
        )

    def test_exact_marker_binding_is_accepted(self) -> None:
        self.assertEqual(
            approval.validate_button_marker(self.marker(), self.binding), "approved"
        )

    def test_missing_fallback_field_is_rejected(self) -> None:
        marker = self.marker()
        marker.pop("message_id")
        with self.assertRaisesRegex(ValueError, "unexpected schema"):
            approval.validate_button_marker(marker, self.binding)

    def test_application_guild_and_bot_are_exactly_bound(self) -> None:
        for key in ("application_id", "guild_id", "bot_user_id"):
            marker = self.marker()
            marker[key] = "888888888888888888"
            with self.assertRaisesRegex(ValueError, key):
                approval.validate_button_marker(marker, self.binding)

    def test_action_status_mismatch_is_rejected(self) -> None:
        marker = self.marker()
        marker["status"] = "rejected"
        with self.assertRaisesRegex(ValueError, "action and status"):
            approval.validate_button_marker(marker, self.binding)

    def test_manifest_file_is_private_and_no_replace(self) -> None:
        path = approval.write_approval_binding(self.binding)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        with self.assertRaisesRegex(RuntimeError, "already active"):
            approval.write_approval_binding(self.binding)

    def test_prompt_uses_stable_enforced_nonce_and_one_post_attempt(self) -> None:
        content = approval.build_attachment_review(
            "outbound send", "person@example.com", FULL_SHA
        )
        draft = "hello"
        nonce = approval.approval_prompt_nonce(CHANNEL_ID, content, draft)
        response = {
            "id": MESSAGE_ID,
            "channel_id": CHANNEL_ID,
            "nonce": nonce,
        }
        with (
            mock.patch.object(
                approval,
                "multipart_message",
                return_value=(b"multipart", "multipart/form-data; boundary=test"),
            ) as multipart,
            mock.patch.object(
                approval,
                "request",
                return_value=(200, json.dumps(response).encode("utf-8")),
            ) as post,
        ):
            self.assertEqual(
                approval.send_approval_prompt(CHANNEL_ID, content, draft, "token"),
                MESSAGE_ID,
            )

        payload = multipart.call_args.args[0]
        self.assertEqual(payload["nonce"], nonce)
        self.assertTrue(payload["enforce_nonce"])
        self.assertNotIn("components", payload)
        self.assertLessEqual(len(nonce), 25)
        self.assertEqual(
            nonce, approval.approval_prompt_nonce(CHANNEL_ID, content, draft)
        )
        self.assertNotEqual(
            nonce,
            approval.approval_prompt_nonce(CHANNEL_ID, content + " changed", draft),
        )
        self.assertEqual(post.call_args.kwargs["max_attempts"], 1)

    def test_prompt_quarantines_unbound_success_response(self) -> None:
        with (
            mock.patch.object(
                approval,
                "multipart_message",
                return_value=(b"multipart", "multipart/form-data; boundary=test"),
            ),
            mock.patch.object(
                approval,
                "request",
                return_value=(200, json.dumps({"id": MESSAGE_ID}).encode("utf-8")),
            ),
            self.assertRaisesRegex(
                approval.DiscordPOSTAmbiguousError, "no approval was armed"
            ),
        ):
            approval.send_approval_prompt(CHANNEL_ID, "review", "hello", "token")

    def test_responder_marker_contains_every_immutable_field(self) -> None:
        path = responder.write_marker(
            "approve",
            "approved",
            SHA_PREFIX,
            FULL_SHA,
            CHANNEL_ID,
            MESSAGE_ID,
            INTERACTION_ID,
            OWNER_ID,
            APPLICATION_ID,
            GUILD_ID,
            BOT_USER_ID,
            "outbound send",
            "person@example.com",
            self.binding["binding_sha256"],
        )
        marker = json.loads(path.read_text())
        self.assertEqual(set(marker), approval.MARKER_KEYS)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(
            approval.validate_button_marker(marker, self.binding), "approved"
        )

    def test_opposite_click_cannot_replace_first_immutable_marker(self) -> None:
        responder.write_marker(
            "approve",
            "approved",
            SHA_PREFIX,
            FULL_SHA,
            CHANNEL_ID,
            MESSAGE_ID,
            INTERACTION_ID,
            OWNER_ID,
            APPLICATION_ID,
            GUILD_ID,
            BOT_USER_ID,
            "outbound send",
            "person@example.com",
            self.binding["binding_sha256"],
        )
        with self.assertRaises(responder.ConflictingDecisionError):
            responder.write_marker(
                "reject",
                "rejected",
                SHA_PREFIX,
                FULL_SHA,
                CHANNEL_ID,
                MESSAGE_ID,
                "888888888888888888",
                OWNER_ID,
                APPLICATION_ID,
                GUILD_ID,
                BOT_USER_ID,
                "outbound send",
                "person@example.com",
                self.binding["binding_sha256"],
            )

    def test_responder_reports_opposite_click_as_explicit_terminal_conflict(self) -> None:
        responder.write_marker(
            "approve",
            "approved",
            SHA_PREFIX,
            FULL_SHA,
            CHANNEL_ID,
            MESSAGE_ID,
            INTERACTION_ID,
            OWNER_ID,
            APPLICATION_ID,
            GUILD_ID,
            BOT_USER_ID,
            "outbound send",
            "person@example.com",
            self.binding["binding_sha256"],
        )
        payload = {
            "action": "reject",
            "sha": SHA_PREFIX,
            "channel_id": CHANNEL_ID,
            "message_id": MESSAGE_ID,
            "interaction_id": "888888888888888888",
            "user_id": OWNER_ID,
            "application_id": APPLICATION_ID,
            "guild_id": GUILD_ID,
            "bot_user_id": BOT_USER_ID,
            "full_sha": FULL_SHA,
            "request_action": "outbound send",
            "request_target": "person@example.com",
            "binding_sha256": self.binding["binding_sha256"],
        }
        stdin = SimpleNamespace(
            buffer=io.BytesIO(json.dumps(payload).encode("utf-8"))
        )
        with (
            mock.patch.object(responder.sys, "argv", ["responder.py", "--from-stdin"]),
            mock.patch.object(responder.sys, "stdin", stdin),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(responder.main(), responder.CONFLICT_EXIT_CODE)

    def test_responder_stdin_schema_has_no_argv_binding_fields(self) -> None:
        payload = {
            "action": "approve",
            "sha": SHA_PREFIX,
            "channel_id": CHANNEL_ID,
            "message_id": MESSAGE_ID,
            "interaction_id": INTERACTION_ID,
            "user_id": OWNER_ID,
            "application_id": APPLICATION_ID,
            "guild_id": GUILD_ID,
            "bot_user_id": BOT_USER_ID,
            "full_sha": FULL_SHA,
            "request_action": "outbound send",
            "request_target": "person@example.com",
            "binding_sha256": self.binding["binding_sha256"],
        }
        stdin = SimpleNamespace(
            buffer=io.BytesIO(json.dumps(payload).encode("utf-8"))
        )
        marker_path = self.approvals_dir / f"{SHA_PREFIX}.json"
        with (
            mock.patch.object(responder.sys, "argv", ["responder.py", "--from-stdin"]),
            mock.patch.object(responder.sys, "stdin", stdin),
            mock.patch.object(responder, "write_marker", return_value=marker_path) as write,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(responder.main(), 0)
        self.assertEqual(write.call_args.args[0], "approve")
        self.assertEqual(write.call_args.args[11], "outbound send")
        self.assertEqual(write.call_args.args[12], "person@example.com")

    def test_responder_rejects_sensitive_legacy_argv_fields(self) -> None:
        with (
            mock.patch.object(
                responder.sys,
                "argv",
                [
                    "responder.py",
                    "--from-stdin",
                    "--request-target",
                    "person@example.com",
                ],
            ),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as raised:
                responder.main()
        self.assertEqual(raised.exception.code, 2)

    def test_main_freezes_binding_before_buttons_become_clickable(self) -> None:
        events: list[str] = []
        written: list[dict] = []

        def write_binding(binding: dict) -> Path:
            events.append("binding")
            written.append(binding)
            return self.bindings_dir / f"{SHA_PREFIX}.json"

        def attach(*_args, **_kwargs) -> None:
            events.append("attach")

        def marker(*_args) -> dict:
            binding = written[0]
            return {
                "version": approval.MARKER_VERSION,
                "status": "approved",
                "action": "approve",
                "sha_prefix": binding["sha_prefix"],
                "full_sha": binding["full_sha"],
                "interaction_id": INTERACTION_ID,
                "user_id": OWNER_ID,
                "application_id": APPLICATION_ID,
                "guild_id": GUILD_ID,
                "bot_user_id": BOT_USER_ID,
                "channel_id": CHANNEL_ID,
                "message_id": MESSAGE_ID,
                "request_action": binding["request_action"],
                "request_target": binding["request_target"],
                "binding_sha256": binding["binding_sha256"],
                "ts": "2026-08-29T12:00:00+00:00",
            }

        configured = SimpleNamespace(
            discord=SimpleNamespace(
                application_id=APPLICATION_ID,
                guild_id=GUILD_ID,
                bot_user_id=BOT_USER_ID,
            )
        )
        argv = [
            "request_approval.py",
            "--channel-id",
            CHANNEL_ID,
            "--approval-exchange-id",
            "exchange-id",
            "--timeout-sec",
            "10",
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(approval, "CONFIG", configured),
            mock.patch.object(approval, "ensure_binding_slot_available"),
            mock.patch.object(approval, "clear_button_marker"),
            mock.patch.object(
                approval.safe_files,
                "read",
                return_value=json.dumps(
                    {
                        "draft": "hello",
                        "action": "outbound send",
                        "target": "public-destination",
                    }
                ),
            ),
            mock.patch.object(
                approval, "send_approval_prompt", return_value=MESSAGE_ID
            ) as send,
            mock.patch.object(approval, "load_discord_token", return_value="token"),
            mock.patch.object(approval, "validate_principal"),
            mock.patch.object(approval, "validate_destination"),
            mock.patch.object(approval, "write_approval_binding", side_effect=write_binding),
            mock.patch.object(approval, "attach_components", side_effect=attach),
            mock.patch.object(approval, "check_button_marker", side_effect=marker),
            mock.patch.object(approval, "clear_approval_binding"),
            mock.patch.object(approval, "remove_components_best_effort"),
        ):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(approval.main(), 0)

        self.assertLess(events.index("binding"), events.index("attach"))
        self.assertEqual(send.call_args.args[0], CHANNEL_ID)

    def test_ambiguous_prompt_never_creates_a_future_approval_capability(self) -> None:
        configured = SimpleNamespace(
            discord=SimpleNamespace(
                application_id=APPLICATION_ID,
                guild_id=GUILD_ID,
                bot_user_id=BOT_USER_ID,
            )
        )
        argv = [
            "request_approval.py",
            "--channel-id",
            CHANNEL_ID,
            "--approval-exchange-id",
            "exchange-id",
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(approval, "CONFIG", configured),
            mock.patch.object(approval, "ensure_binding_slot_available"),
            mock.patch.object(approval, "clear_button_marker"),
            mock.patch.object(
                approval.safe_files,
                "read",
                return_value=json.dumps(
                    {
                        "draft": "hello",
                        "action": "outbound send",
                        "target": "public-destination",
                    }
                ),
            ),
            mock.patch.object(approval, "load_discord_token", return_value="token"),
            mock.patch.object(approval, "validate_principal"),
            mock.patch.object(approval, "validate_destination"),
            mock.patch.object(
                approval,
                "send_approval_prompt",
                side_effect=approval.DiscordPOSTAmbiguousError("unknown"),
            ) as send,
            mock.patch.object(approval, "write_approval_binding") as write_binding,
            mock.patch.object(approval, "attach_components") as attach,
            self.assertRaisesRegex(SystemExit, "No approval binding or buttons"),
        ):
            approval.main()

        send.assert_called_once()
        write_binding.assert_not_called()
        attach.assert_not_called()


if __name__ == "__main__":
    unittest.main()
