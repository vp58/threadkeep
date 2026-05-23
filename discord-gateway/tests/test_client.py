#!/usr/bin/env python3
"""Unit tests for the gateway client.

A live websocket session is out of scope here. These tests cover:

  - Token loading from the configured env var
  - State save / load round-trip
  - dispatch_interaction invokes router.py via subprocess with the JSON payload
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

os.environ.setdefault("THREADKEEP_CONFIG", str(HERE.parent.parent / "config.example.toml"))
os.environ.setdefault("THREADKEEP_OWNER_USER_ID", "111111111111111111")

import client  # noqa: E402


class ClientTests(unittest.TestCase):
    def test_load_token_env(self) -> None:
        with mock.patch.dict(os.environ, {"DISCORD_BOT_TOKEN": "envtoken"}):
            self.assertEqual(client.load_token(), "envtoken")

    def test_state_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(client, "STATE_PATH", Path(td) / "client_state.json"):
                client.save_state({"session_id": "abc", "last_seq": 42})
                loaded = client.load_state()
                self.assertEqual(loaded, {"session_id": "abc", "last_seq": 42})

    def test_dispatch_interaction_invokes_router(self) -> None:
        captured: dict = {}

        class FakeProc:
            returncode = 0

            async def communicate(self, input=None):
                captured["input"] = input
                return (b"ok", b"")

        async def fake_create_subprocess_exec(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return FakeProc()

        logger = mock.MagicMock()
        with mock.patch.object(asyncio, "create_subprocess_exec", side_effect=fake_create_subprocess_exec):
            asyncio.run(client.dispatch_interaction(
                {"id": "i1", "data": {"custom_id": "approve:xxx"}}, logger
            ))

        self.assertIn("--from-stdin", captured["args"])
        payload = json.loads(captured["input"].decode("utf-8"))
        self.assertEqual(payload["id"], "i1")
        self.assertEqual(payload["data"]["custom_id"], "approve:xxx")


if __name__ == "__main__":
    unittest.main()
