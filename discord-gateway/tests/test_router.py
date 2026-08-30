#!/usr/bin/env python3
"""Focused tests for interaction binding, ACK-first routing, and PATCH gating."""
from __future__ import annotations

import io
import json
import logging
import os
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

os.environ.setdefault("DISCOPARTY_CONFIG", str(HERE.parent.parent / "config.example.toml"))
os.environ.setdefault("DISCOPARTY_OWNER_USER_ID", "111111111111111111")
os.environ.setdefault("DISCOPARTY_DISCORD_APPLICATION_ID", "222222222222222222")
os.environ.setdefault("DISCOPARTY_DISCORD_BOT_USER_ID", "333333333333333333")
os.environ.setdefault("DISCOPARTY_DISCORD_GUILD_ID", "444444444444444444")

import router  # noqa: E402

APPROVER = router.APPROVER_USER_ID
INTRUDER = "999999999999999999"
APPLICATION_ID = "222222222222222222"
BOT_USER_ID = "333333333333333333"
GUILD_ID = "444444444444444444"
CHANNEL_ID = "555555555555555555"
MESSAGE_ID = "666666666666666666"
INTERACTION_ID = "777777777777777777"
SHA_PREFIX = "abcdef012345"
FULL_SHA = SHA_PREFIX + ("0" * (64 - len(SHA_PREFIX)))
REQUEST_ACTION = "outbound send"
REQUEST_TARGET = "person@example.com"


def make_interaction(custom_id: str, user_id: str = APPROVER) -> dict:
    return {
        "id": INTERACTION_ID,
        "token": "interaction-token-abc",
        "type": 3,
        "application_id": APPLICATION_ID,
        "guild_id": GUILD_ID,
        "channel_id": CHANNEL_ID,
        "data": {"custom_id": custom_id, "component_type": 2},
        "member": {"user": {"id": user_id}},
        "message": {
            "id": MESSAGE_ID,
            "content": "Original draft content",
            "author": {"id": BOT_USER_ID},
            "components": [
                {"type": 1, "components": [{"type": 2, "custom_id": custom_id}]}
            ],
        },
    }


class RouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logger = logging.getLogger("test-router")
        self.logger.handlers = []
        self.temporary = tempfile.TemporaryDirectory()
        self.bindings_dir = Path(self.temporary.name) / "approval-bindings"
        self.pending_dir = Path(self.temporary.name) / "pending"
        self.bindings_dir.mkdir(mode=0o700)
        self.pending_dir.mkdir(mode=0o700)
        self.binding_dir_patcher = mock.patch.object(
            router, "APPROVAL_BINDINGS_DIR", self.bindings_dir
        )
        self.binding_dir_patcher.start()
        self.token_patcher = mock.patch.object(router, "load_token", return_value="fake-token")
        self.token_patcher.start()
        self.discord_post_patcher = mock.patch.object(
            router, "discord_post", return_value=(204, "")
        )
        self.discord_post = self.discord_post_patcher.start()
        self.discord_patch_patcher = mock.patch.object(
            router, "discord_patch", return_value=(200, "{}")
        )
        self.discord_patch = self.discord_patch_patcher.start()
        self.binding = self.write_binding()

    def test_rest_rejects_ambient_proxy_before_network(self) -> None:
        with (
            mock.patch.object(
                router.urllib.request,
                "getproxies",
                return_value={"https": "https://proxy.invalid"},
            ),
            mock.patch.object(router, "direct_urlopen") as open_url,
            self.assertRaisesRegex(RuntimeError, "refuses ambient proxy"),
        ):
            router.discord_request(
                "POST", "/channels/1/messages", {}, "secret", timeout=1
            )
        open_url.assert_not_called()

    def tearDown(self) -> None:
        self.token_patcher.stop()
        self.discord_post_patcher.stop()
        self.discord_patch_patcher.stop()
        self.binding_dir_patcher.stop()
        self.temporary.cleanup()

    def write_private_json(self, path: Path, payload: dict) -> None:
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)

    def write_binding(self, **updates) -> router.ApprovalBinding:
        payload = {
            "version": router.BINDING_VERSION,
            "sha_prefix": SHA_PREFIX,
            "full_sha": FULL_SHA,
            "approver_user_id": APPROVER,
            "expected_application_id": APPLICATION_ID,
            "expected_guild_id": GUILD_ID,
            "expected_bot_user_id": BOT_USER_ID,
            "discord_prompt_channel_id": CHANNEL_ID,
            "discord_prompt_message_id": MESSAGE_ID,
            "request_action": REQUEST_ACTION,
            "request_target": REQUEST_TARGET,
            "created_at": "2026-08-29T12:00:00+00:00",
            "expires_at": int(time.time()) + 600,
        }
        payload.update(updates)
        payload["binding_sha256"] = router.hashlib.sha256(
            router._canonical_json(payload)
        ).hexdigest()
        self.write_private_json(self.bindings_dir / f"{SHA_PREFIX}.json", payload)
        return router.ApprovalBinding(
            full_sha=payload["full_sha"],
            request_action=payload["request_action"],
            request_target=payload["request_target"],
            binding_sha256=payload["binding_sha256"],
        )

    def handle(self, interaction: dict, *, preacknowledged: bool = False) -> int:
        return router.handle_interaction(
            interaction,
            self.logger,
            expected_application_id=APPLICATION_ID,
            expected_bot_user_id=BOT_USER_ID,
            expected_guild_id=GUILD_ID,
            interaction_preacknowledged=preacknowledged,
        )

    def callback_bodies(self) -> list[dict]:
        return [
            call.args[1]
            for call in self.discord_post.call_args_list
            if "/interactions/" in call.args[0] and "/callback" in call.args[0]
        ]

    def test_rejects_non_owner_only_when_error_ack_succeeds(self) -> None:
        rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}", user_id=INTRUDER))
        self.assertEqual(rc, router.ROUTER_REJECTED)
        self.assertEqual(
            self.callback_bodies()[0]["type"],
            router.INTERACTION_RESPONSE_CHANNEL_MESSAGE_WITH_SOURCE,
        )
        self.assertIn("Not authorized", self.callback_bodies()[0]["data"]["content"])

        self.discord_post.return_value = (500, "failed")
        rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}", user_id=INTRUDER))
        self.assertEqual(rc, router.ROUTER_RETRY)

    def test_discord_transport_error_does_not_expose_callback_token(self) -> None:
        callback_token = "private-interaction-token"
        with mock.patch.object(
            router,
            "direct_urlopen",
            side_effect=router.urllib.error.URLError(
                f"upstream included {callback_token} in its exception"
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "Discord REST transport failed"
            ) as raised:
                router.discord_request(
                    "POST",
                    f"/interactions/{INTERACTION_ID}/{callback_token}/callback",
                    {"type": 6},
                    "private-bot-token",
                    timeout=1,
                )
        self.assertNotIn(callback_token, str(raised.exception))

    def test_discord_redirect_is_terminal_and_never_followed(self) -> None:
        redirect = router.urllib.error.HTTPError(
            "https://discord.com/api/v10/test",
            302,
            "Found",
            {"Location": "https://attacker.invalid/collect"},
            io.BytesIO(b"redirect refused"),
        )
        with mock.patch.object(
            router, "direct_urlopen", side_effect=redirect
        ) as open_url:
            status, body = router.discord_request(
                "POST", "/test", {}, "private-bot-token", timeout=1
            )
        self.assertEqual((status, body), (302, "redirect refused"))
        open_url.assert_called_once()

    def test_approve_defers_before_responder_and_requires_patch(self) -> None:
        interaction = make_interaction(f"approve:{SHA_PREFIX}")
        events: list[str] = []

        def responder(*_args):
            events.append("responder")
            return 0, "approved"

        def post(path, body, token):
            del token
            if "/callback" in path:
                events.append(f"ack:{body['type']}")
            return 204, ""

        def patch(path, body, token):
            del path, body, token
            events.append("patch")
            return 200, "{}"

        with (
            mock.patch.object(router, "run_responder", side_effect=responder) as run,
            mock.patch.object(router, "discord_post", side_effect=post),
            mock.patch.object(router, "discord_patch", side_effect=patch),
        ):
            rc = self.handle(interaction)

        self.assertEqual(rc, router.ROUTER_OK)
        self.assertEqual(events[:3], ["ack:6", "responder", "patch"])
        run.assert_called_once_with(
            "approve",
            SHA_PREFIX,
            CHANNEL_ID,
            MESSAGE_ID,
            INTERACTION_ID,
            APPROVER,
            APPLICATION_ID,
            GUILD_ID,
            BOT_USER_ID,
            self.binding,
            self.logger,
        )

    def test_expired_ack_can_complete_through_authenticated_patch(self) -> None:
        self.discord_post.return_value = (404, "expired")
        with mock.patch.object(router, "run_responder", return_value=(0, "approved")):
            rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_OK)
        self.discord_patch.assert_called_once()

    def test_preacknowledged_token_free_interaction_skips_callback(self) -> None:
        interaction = make_interaction(f"approve:{SHA_PREFIX}")
        interaction.pop("token")
        with mock.patch.object(router, "run_responder", return_value=(0, "approved")):
            rc = self.handle(interaction, preacknowledged=True)
        self.assertEqual(rc, router.ROUTER_OK)
        self.discord_post.assert_not_called()
        self.discord_patch.assert_called_once()

    def test_preacknowledged_payload_rejects_persisted_callback_token(self) -> None:
        rc = self.handle(
            make_interaction(f"approve:{SHA_PREFIX}"), preacknowledged=True
        )
        self.assertEqual(rc, router.ROUTER_REJECTED)
        self.discord_post.assert_not_called()

    def test_responder_receives_binding_over_stdin_with_sanitized_environment(self) -> None:
        completed = mock.Mock(returncode=0, stdout="approved", stderr="")
        with (
            mock.patch.object(router.subprocess, "run", return_value=completed) as run,
            mock.patch.dict(
                os.environ,
                {
                    "DISCORD_BOT_TOKEN": "do-not-inherit",
                    "OPENAI_API_KEY": "do-not-inherit",
                },
            ),
        ):
            rc, _out = router.run_responder(
                "approve",
                SHA_PREFIX,
                CHANNEL_ID,
                MESSAGE_ID,
                INTERACTION_ID,
                APPROVER,
                APPLICATION_ID,
                GUILD_ID,
                BOT_USER_ID,
                self.binding,
                self.logger,
            )
        self.assertEqual(rc, 0)
        command = run.call_args.args[0]
        self.assertEqual(command[-1], "--from-stdin")
        for sensitive in (
            REQUEST_ACTION,
            REQUEST_TARGET,
            APPROVER,
            APPLICATION_ID,
            GUILD_ID,
            BOT_USER_ID,
        ):
            self.assertNotIn(sensitive, command)
        responder_input = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(responder_input["request_action"], REQUEST_ACTION)
        self.assertEqual(responder_input["request_target"], REQUEST_TARGET)
        environment = run.call_args.kwargs["env"]
        self.assertNotIn("DISCORD_BOT_TOKEN", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)

    def test_patch_failure_is_retryable_even_after_successful_ack(self) -> None:
        self.discord_patch.return_value = (500, "failed")
        with mock.patch.object(router, "run_responder", return_value=(0, "approved")):
            rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_RETRY)

    def test_permanent_patch_failure_is_terminal_after_decision(self) -> None:
        self.discord_patch.return_value = (404, "deleted")
        with mock.patch.object(router, "run_responder", return_value=(0, "approved")):
            rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_REJECTED)

    def test_opposite_click_after_immutable_decision_is_terminal(self) -> None:
        with mock.patch.object(
            router,
            "run_responder",
            return_value=(router.RESPONDER_ALREADY_DECIDED, ""),
        ):
            rc = self.handle(make_interaction(f"reject:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_REJECTED)
        patch_body = self.discord_patch.call_args.args[1]
        self.assertEqual(patch_body["components"], [])
        self.assertNotIn("content", patch_body)

    def test_responder_failure_is_retryable(self) -> None:
        with mock.patch.object(router, "run_responder", return_value=(2, "boom")):
            rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_RETRY)
        self.discord_patch.assert_not_called()

    def test_reject_action_patches_message(self) -> None:
        with mock.patch.object(router, "run_responder", return_value=(0, "rejected")) as run:
            rc = self.handle(make_interaction(f"reject:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_OK)
        run.assert_called_once_with(
            "reject",
            SHA_PREFIX,
            CHANNEL_ID,
            MESSAGE_ID,
            INTERACTION_ID,
            APPROVER,
            APPLICATION_ID,
            GUILD_ID,
            BOT_USER_ID,
            self.binding,
            self.logger,
        )
        patch_body = self.discord_patch.call_args.args[1]
        self.assertTrue(patch_body["content"].startswith("[REJECTED"))
        self.assertEqual(patch_body["components"], [])

    def test_strict_sha_rejects_traversal_without_responder(self) -> None:
        with mock.patch.object(router, "run_responder") as responder:
            rc = self.handle(make_interaction("approve:../../etc/passwd"))
        self.assertEqual(rc, router.ROUTER_REJECTED)
        responder.assert_not_called()

    def test_principal_binding_mismatch_is_not_checkpointable(self) -> None:
        interaction = make_interaction(f"approve:{SHA_PREFIX}")
        interaction["application_id"] = "888888888888888888"
        rc = self.handle(interaction)
        self.assertEqual(rc, router.ROUTER_RETRY)
        self.discord_post.assert_not_called()

    def test_durable_principal_must_still_match_current_configuration(self) -> None:
        stale_config = SimpleNamespace(
            discord=replace(
                router.CONFIG.discord,
                application_id="888888888888888888",
            )
        )
        with mock.patch.object(router, "CONFIG", stale_config):
            rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_RETRY)
        self.discord_post.assert_not_called()

    def test_legacy_pending_record_is_never_an_approval_binding(self) -> None:
        interaction = make_interaction(f"approve:{SHA_PREFIX}")
        (self.bindings_dir / f"{SHA_PREFIX}.json").unlink()
        self.write_private_json(
            self.pending_dir / f"{SHA_PREFIX}.json",
            {
                "sha_prefix": SHA_PREFIX,
                "full_sha": FULL_SHA,
                "operation": "slack_post",
                "target": "public-destination",
                "discord_prompt_channel_id": CHANNEL_ID,
                "discord_prompt_message_id": MESSAGE_ID,
                "approver_user_id": APPROVER,
            },
        )
        rc = self.handle(interaction)
        self.assertEqual(rc, router.ROUTER_REJECTED)

    def test_missing_frozen_binding_never_invokes_responder(self) -> None:
        (self.bindings_dir / f"{SHA_PREFIX}.json").unlink()
        with mock.patch.object(router, "run_responder") as responder:
            rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_REJECTED)
        responder.assert_not_called()

    def test_request_target_tamper_is_rejected(self) -> None:
        path = self.bindings_dir / f"{SHA_PREFIX}.json"
        payload = json.loads(path.read_text())
        payload["request_target"] = "attacker@example.com"
        self.write_private_json(path, payload)
        with mock.patch.object(router, "run_responder") as responder:
            rc = self.handle(make_interaction(f"approve:{SHA_PREFIX}"))
        self.assertEqual(rc, router.ROUTER_REJECTED)
        responder.assert_not_called()

    def test_unknown_custom_id_rejected_only_after_successful_ack(self) -> None:
        rc = self.handle(make_interaction("bogus:abcdef012345"))
        self.assertEqual(rc, router.ROUTER_REJECTED)
        self.discord_post.return_value = (503, "unavailable")
        rc = self.handle(make_interaction("bogus:abcdef012345"))
        self.assertEqual(rc, router.ROUTER_RETRY)


if __name__ == "__main__":
    unittest.main()
