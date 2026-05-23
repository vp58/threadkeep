#!/usr/bin/env python3
"""Unit tests for the Discord interaction router.

Mocks Discord HTTP calls and the responder subprocess. Verifies:

  1. Auth: non-owner user_id is rejected with an ephemeral ACK type 4.
  2. Dispatch: approve / reject custom_ids invoke the responder script.
  3. Success ACK is type 7 (UPDATE_MESSAGE) carrying new content and
     cleared components. This is the regression test for the
     "this interaction failed" overlay caused by the older type 6 +
     channels.messages PATCH pattern.
  4. Unknown custom_id is rejected with an ephemeral ACK.
"""
from __future__ import annotations

import logging
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

# The router imports config.CONFIG at module load. Point it at the example
# config so tests don't depend on a local config.toml being present.
os.environ.setdefault("DISCLAWD_CONFIG", str(HERE.parent.parent / "config.example.toml"))
os.environ.setdefault("DISCLAWD_OWNER_USER_ID", "111111111111111111")

import router  # noqa: E402

APPROVER = router.APPROVER_USER_ID
INTRUDER = "999999999999999999"


def make_interaction(custom_id: str, user_id: str = APPROVER) -> dict:
    return {
        "id": "interaction-id-123",
        "token": "interaction-token-abc",
        "application_id": "app-id-456",
        "channel_id": "channel-789",
        "data": {"custom_id": custom_id},
        "member": {"user": {"id": user_id}},
        "message": {"id": "msg-id-111", "content": "Original draft content"},
    }


class RouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logger = logging.getLogger("test")
        self.logger.handlers = []
        self.token_patcher = mock.patch.object(router, "load_token", return_value="fake-token")
        self.token_patcher.start()
        self.discord_post_patcher = mock.patch.object(
            router, "discord_post", return_value=(204, "")
        )
        self.discord_post = self.discord_post_patcher.start()

    def tearDown(self) -> None:
        self.token_patcher.stop()
        self.discord_post_patcher.stop()

    def test_rejects_non_owner_user(self) -> None:
        interaction = make_interaction("approve:abcdef012345", user_id=INTRUDER)
        rc = router.handle_interaction(interaction, self.logger)
        self.assertEqual(rc, 1)
        call = self.discord_post.call_args_list[0]
        body = call.args[1] if len(call.args) > 1 else call.kwargs.get("body")
        self.assertEqual(body["type"], router.INTERACTION_RESPONSE_CHANNEL_MESSAGE_WITH_SOURCE)
        self.assertIn("Not authorized", body["data"]["content"])

    def test_dispatch_approve_uses_type_7_update_message(self) -> None:
        """Regression: success ACK must be type 7 UPDATE_MESSAGE with
        components cleared. The old type 6 DEFERRED_UPDATE + channels.messages
        PATCH pattern triggers the "this interaction failed" client overlay.
        """
        interaction = make_interaction("approve:abc123def456")
        with mock.patch.object(router, "run_responder", return_value=(0, "approved")) as resp:
            rc = router.handle_interaction(interaction, self.logger)
        self.assertEqual(rc, 0)
        resp.assert_called_once()
        args, _ = resp.call_args
        self.assertEqual(args[0], "approve")
        self.assertEqual(args[1], "abc123def456")
        ack_calls = [c for c in self.discord_post.call_args_list
                     if "/interactions/" in c.args[0] and "/callback" in c.args[0]]
        self.assertTrue(ack_calls, "expected an interaction callback POST")
        ack_body = ack_calls[0].args[1]
        self.assertEqual(ack_body["type"], router.INTERACTION_RESPONSE_UPDATE_MESSAGE)
        self.assertTrue(ack_body["data"]["content"].startswith("[APPROVED"))
        self.assertIn("Original draft content", ack_body["data"]["content"])
        self.assertEqual(ack_body["data"]["components"], [])

    def test_dispatch_reject_uses_type_7_update_message(self) -> None:
        interaction = make_interaction("reject:abc123def456")
        with mock.patch.object(router, "run_responder", return_value=(0, "rejected")) as resp:
            rc = router.handle_interaction(interaction, self.logger)
        self.assertEqual(rc, 0)
        resp.assert_called_once_with("reject", "abc123def456", "channel-789", "msg-id-111", self.logger)
        ack_calls = [c for c in self.discord_post.call_args_list
                     if "/interactions/" in c.args[0] and "/callback" in c.args[0]]
        ack_body = ack_calls[0].args[1]
        self.assertEqual(ack_body["type"], router.INTERACTION_RESPONSE_UPDATE_MESSAGE)
        self.assertTrue(ack_body["data"]["content"].startswith("[REJECTED"))

    def test_responder_failure_acks_ephemeral_error(self) -> None:
        interaction = make_interaction("approve:abc123def456")
        with mock.patch.object(router, "run_responder", return_value=(1, "boom")):
            rc = router.handle_interaction(interaction, self.logger)
        self.assertEqual(rc, 1)
        ack_calls = [c for c in self.discord_post.call_args_list
                     if "/interactions/" in c.args[0] and "/callback" in c.args[0]]
        ack_body = ack_calls[0].args[1]
        self.assertEqual(ack_body["type"], router.INTERACTION_RESPONSE_CHANNEL_MESSAGE_WITH_SOURCE)
        self.assertEqual(ack_body["data"]["flags"], router.EPHEMERAL)

    def test_unknown_custom_id_rejected(self) -> None:
        interaction = make_interaction("bogus:xxx")
        rc = router.handle_interaction(interaction, self.logger)
        self.assertEqual(rc, 1)

    def test_missing_sha_prefix_rejected(self) -> None:
        interaction = make_interaction("approve:")
        rc = router.handle_interaction(interaction, self.logger)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
