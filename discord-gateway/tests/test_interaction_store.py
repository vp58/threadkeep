#!/usr/bin/env python3
"""Durability and replay tests for the Discord interaction inbox."""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import interaction_store  # noqa: E402

APPLICATION_ID = "222222222222222222"
BOT_USER_ID = "333333333333333333"
GUILD_ID = "444444444444444444"
INTERACTION_ID = "777777777777777777"


def interaction() -> dict:
    return {"id": INTERACTION_ID, "token": "private-token", "data": {"custom_id": "approve:abcdef012345"}}


class InteractionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "state" / "interactions.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def enqueue(self, payload: dict | None = None) -> bool:
        return interaction_store.enqueue(
            self.path,
            interaction() if payload is None else payload,
            expected_application_id=APPLICATION_ID,
            expected_bot_user_id=BOT_USER_ID,
            expected_guild_id=GUILD_ID,
            now=100.0,
        )

    def test_enqueue_is_durable_private_and_replay_idempotent(self) -> None:
        self.assertTrue(self.enqueue())
        self.assertFalse(self.enqueue())
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        row = interaction_store.get(self.path, INTERACTION_ID)
        self.assertEqual(row["status"], "received")
        self.assertNotIn("token", json.loads(row["payload_json"]))
        changed_token = interaction()
        changed_token["token"] = "replayed-token"
        self.assertFalse(self.enqueue(changed_token))

    def test_same_id_with_changed_payload_fails_closed(self) -> None:
        self.enqueue()
        changed = interaction()
        changed["data"] = {"custom_id": "reject:abcdef012345"}
        with self.assertRaises(interaction_store.InteractionConflictError):
            self.enqueue(changed)

    def test_claim_retry_and_completion_state_machine(self) -> None:
        self.enqueue()
        self.assertIsNone(interaction_store.claim_next(self.path, now=100.0))
        interaction_store.mark_ready(self.path, INTERACTION_ID)
        job = interaction_store.claim_next(self.path, now=100.0)
        self.assertEqual(job.interaction_id, INTERACTION_ID)
        self.assertEqual(job.attempts, 1)
        delay = interaction_store.release_for_retry(
            self.path, INTERACTION_ID, "router rc=2", attempts=job.attempts, now=100.0
        )
        self.assertEqual(delay, 1.0)
        self.assertIsNone(interaction_store.claim_next(self.path, now=100.5))
        job = interaction_store.claim_next(self.path, now=101.0)
        self.assertEqual(job.attempts, 2)
        interaction_store.mark_done(self.path, INTERACTION_ID, now=102.0)
        self.assertEqual(interaction_store.get(self.path, INTERACTION_ID)["status"], "done")
        self.assertIsNone(interaction_store.claim_next(self.path, now=200.0))

    def test_attempt_ceiling_dead_letters_and_releases_active_capacity(self) -> None:
        self.enqueue()
        interaction_store.mark_ready(self.path, INTERACTION_ID)
        job = interaction_store.claim_next(self.path, now=100.0)
        with mock.patch.object(interaction_store, "MAX_DELIVERY_ATTEMPTS", 1):
            delay = interaction_store.release_for_retry(
                self.path,
                INTERACTION_ID,
                "permanent failure",
                attempts=job.attempts,
                now=101.0,
            )
        self.assertIsNone(delay)
        row = interaction_store.get(self.path, INTERACTION_ID)
        self.assertEqual(row["status"], "done")
        self.assertIn("dead-letter after 1 attempts", row["last_error"])
        self.assertEqual(row["completed_at"], 101.0)

    def test_unknown_ack_outcome_activates_only_after_deadline(self) -> None:
        self.enqueue()
        self.assertEqual(
            interaction_store.activate_stale_received(
                self.path,
                now=100.0 + interaction_store.RECEIVED_ACK_GRACE_SECONDS - 0.1,
            ),
            0,
        )
        self.assertEqual(
            interaction_store.activate_stale_received(
                self.path,
                now=100.0 + interaction_store.RECEIVED_ACK_GRACE_SECONDS,
            ),
            1,
        )
        self.assertIsNotNone(interaction_store.claim_next(self.path, now=104.0))

    def test_restart_recovers_only_processing_claims(self) -> None:
        self.enqueue()
        interaction_store.mark_ready(self.path, INTERACTION_ID)
        interaction_store.claim_next(self.path, now=100.0)
        self.assertEqual(interaction_store.recover_processing(self.path), 1)
        job = interaction_store.claim_next(self.path, now=100.0)
        self.assertEqual(job.attempts, 2)

    def test_active_row_cap_fails_closed(self) -> None:
        self.enqueue()
        second = interaction()
        second["id"] = "888888888888888888"
        with (
            mock.patch.object(interaction_store, "MAX_ACTIVE_INTERACTIONS", 1),
            self.assertRaisesRegex(
                interaction_store.InteractionStoreError, "active-row cap"
            ),
        ):
            self.enqueue(second)

    def test_completed_rows_are_retained_then_expired(self) -> None:
        self.enqueue()
        interaction_store.mark_ready(self.path, INTERACTION_ID)
        interaction_store.claim_next(self.path, now=100.0)
        interaction_store.mark_done(self.path, INTERACTION_ID, now=100.0)
        second = interaction()
        second["id"] = "888888888888888888"
        interaction_store.enqueue(
            self.path,
            second,
            expected_application_id=APPLICATION_ID,
            expected_bot_user_id=BOT_USER_ID,
            expected_guild_id=GUILD_ID,
            now=100.0 + interaction_store.DONE_RETENTION_SECONDS + 1,
        )
        self.assertIsNone(interaction_store.get(self.path, INTERACTION_ID))

    def test_rejects_symlink_database(self) -> None:
        target = Path(self.temporary.name) / "target.sqlite3"
        target.write_text("not sqlite", encoding="utf-8")
        self.path.parent.mkdir(mode=0o700)
        os.symlink(target, self.path)
        with self.assertRaises(interaction_store.InteractionStoreError):
            self.enqueue()


if __name__ == "__main__":
    unittest.main()
