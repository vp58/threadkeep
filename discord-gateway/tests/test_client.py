#!/usr/bin/env python3
"""Unit tests for the gateway client.

A live websocket session is out of scope here. These tests cover:

  - Token loading through the Keychain-only shared credential boundary
  - State save / load round-trip
  - dispatch_interaction invokes router.py via subprocess with the JSON payload
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus
from websockets.http11 import Response

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

os.environ.setdefault("THREADKEEP_CONFIG", str(HERE.parent.parent / "config.example.toml"))
os.environ.setdefault("THREADKEEP_OWNER_USER_ID", "111111111111111111")
os.environ.setdefault("THREADKEEP_DISCORD_APPLICATION_ID", "222222222222222222")
os.environ.setdefault("THREADKEEP_DISCORD_BOT_USER_ID", "333333333333333333")
os.environ.setdefault("THREADKEEP_DISCORD_GUILD_ID", "444444444444444444")

import client  # noqa: E402

APPLICATION_ID = "222222222222222222"
BOT_USER_ID = "333333333333333333"
GUILD_ID = "444444444444444444"
CHANNEL_ID = "555555555555555555"
MESSAGE_ID = "666666666666666666"
INTERACTION_ID = "777777777777777777"
CUSTOM_ID = "approve:abcdef012345"


def valid_interaction() -> dict:
    return {
        "id": INTERACTION_ID,
        "token": "interaction-token",
        "type": 3,
        "application_id": APPLICATION_ID,
        "guild_id": GUILD_ID,
        "channel_id": CHANNEL_ID,
        "data": {"custom_id": CUSTOM_ID, "component_type": 2},
        "member": {"user": {"id": "111111111111111111"}},
        "message": {
            "id": MESSAGE_ID,
            "author": {"id": BOT_USER_ID},
            "components": [
                {"type": 1, "components": [{"type": 2, "custom_id": CUSTOM_ID}]}
            ],
        },
    }


def durable_interaction() -> dict:
    value = valid_interaction()
    value.pop("token")
    return value


def resume_state(last_seq: int = 42) -> dict:
    return {
        "session_id": "session-1",
        "resume_gateway_url": "wss://gateway.discord.gg",
        "last_seq": last_seq,
        "application_id": APPLICATION_ID,
        "bot_user_id": BOT_USER_ID,
        "guild_ids": [GUILD_ID],
    }


class ClientTests(unittest.TestCase):
    def test_load_token_uses_keychain_only_boundary(self) -> None:
        with (
            mock.patch.dict(
                os.environ, {"DISCORD_BOT_TOKEN": "ambient-token"}
            ),
            mock.patch.object(
                client, "load_discord_token", return_value="keychain-token"
            ) as load,
        ):
            self.assertEqual(client.load_token(), "keychain-token")
        load.assert_called_once_with()

    def test_callback_rejects_ambient_proxy_before_network(self) -> None:
        with (
            mock.patch.object(
                client.urllib.request,
                "getproxies",
                return_value={"https": "https://proxy.invalid"},
            ),
            mock.patch.object(client, "direct_urlopen") as open_url,
            self.assertRaisesRegex(RuntimeError, "refuses ambient proxy"),
        ):
            client._post_interaction_callback(valid_interaction(), {"type": 6})
        open_url.assert_not_called()

    def test_callback_transport_error_does_not_expose_callback_token(self) -> None:
        interaction = valid_interaction()
        callback_token = interaction["token"]
        with mock.patch.object(
            client,
            "direct_urlopen",
            side_effect=client.urllib.error.URLError(
                f"upstream included {callback_token} in its exception"
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "callback transport failed"
            ) as raised:
                client._post_interaction_callback(interaction, {"type": 6})
        self.assertNotIn(callback_token, str(raised.exception))

    def test_gateway_refuses_cross_origin_redirects(self) -> None:
        connector = client._NoRedirectWebSocketConnect(
            client.GATEWAY_URL,
            proxy=None,
        )
        redirect = InvalidStatus(
            Response(
                302,
                "Found",
                Headers({"Location": "wss://attacker.invalid/gateway"}),
            )
        )
        self.assertIs(connector.process_redirect(redirect), redirect)

    def test_callback_redirect_is_terminal_and_never_followed(self) -> None:
        redirect = client.urllib.error.HTTPError(
            "https://discord.com/api/v10/callback",
            302,
            "Found",
            {"Location": "https://attacker.invalid/collect"},
            io.BytesIO(b"redirect refused"),
        )
        with mock.patch.object(
            client, "direct_urlopen", side_effect=redirect
        ) as open_url:
            status, body = client._post_interaction_callback(
                valid_interaction(), {"type": 6}
            )
        self.assertEqual((status, body), (302, "redirect refused"))
        open_url.assert_called_once()

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
        with (
            mock.patch.object(
                asyncio, "create_subprocess_exec", side_effect=fake_create_subprocess_exec
            ),
            mock.patch.dict(
                os.environ,
                {
                    "DISCORD_BOT_TOKEN": "do-not-inherit",
                    "ANTHROPIC_API_KEY": "do-not-inherit",
                },
            ),
        ):
            asyncio.run(client.dispatch_interaction(
                durable_interaction(),
                logger,
                expected_application_id=APPLICATION_ID,
                expected_bot_user_id=BOT_USER_ID,
                expected_guild_id=GUILD_ID,
            ))

        self.assertIn("--from-stdin", captured["args"])
        self.assertNotIn("--interaction-preacknowledged", captured["args"])
        self.assertNotIn(APPLICATION_ID, captured["args"])
        self.assertNotIn(BOT_USER_ID, captured["args"])
        self.assertNotIn(GUILD_ID, captured["args"])
        self.assertTrue(captured["kwargs"]["start_new_session"])
        payload = json.loads(captured["input"].decode("utf-8"))
        self.assertEqual(payload["interaction"]["id"], INTERACTION_ID)
        self.assertEqual(payload["interaction"]["data"]["custom_id"], CUSTOM_ID)
        self.assertNotIn("token", payload["interaction"])
        self.assertNotIn("DISCORD_BOT_TOKEN", captured["kwargs"]["env"])
        self.assertNotIn("ANTHROPIC_API_KEY", captured["kwargs"]["env"])

    def test_dispatch_interaction_propagates_router_failure(self) -> None:
        class FakeProc:
            returncode = 7

            async def communicate(self, input=None):
                return (b"", b"failed")

        logger = mock.MagicMock()
        with mock.patch.object(
            asyncio,
            "create_subprocess_exec",
            new=mock.AsyncMock(return_value=FakeProc()),
        ):
            with self.assertRaisesRegex(RuntimeError, "exit 7"):
                asyncio.run(
                    client.dispatch_interaction(
                        durable_interaction(),
                        logger,
                        expected_application_id=APPLICATION_ID,
                        expected_bot_user_id=BOT_USER_ID,
                        expected_guild_id=GUILD_ID,
                    )
                )

    def test_dispatch_refuses_callback_token_before_spawning_child(self) -> None:
        with mock.patch.object(asyncio, "create_subprocess_exec") as spawn:
            with self.assertRaisesRegex(RuntimeError, "callback token"):
                asyncio.run(
                    client.dispatch_interaction(
                        valid_interaction(),
                        mock.MagicMock(),
                        expected_application_id=APPLICATION_ID,
                        expected_bot_user_id=BOT_USER_ID,
                        expected_guild_id=GUILD_ID,
                    )
                )
        spawn.assert_not_called()

    def test_dispatch_timeout_kills_and_reaps_complete_process_group(self) -> None:
        class HangingProc:
            def __init__(self) -> None:
                self.returncode = None
                self.pid = 43210
                self.reaped = asyncio.Event()

            async def communicate(self, input=None):
                del input
                await asyncio.Future()

            async def wait(self):
                await self.reaped.wait()
                return self.returncode

        proc = HangingProc()
        signals: list[int] = []

        def killpg(_pgid: int, sent_signal: int) -> None:
            signals.append(sent_signal)
            if sent_signal == client.signal.SIGKILL:
                proc.returncode = -sent_signal
                proc.reaped.set()

        logger = mock.MagicMock()
        with (
            mock.patch.object(
                asyncio,
                "create_subprocess_exec",
                new=mock.AsyncMock(return_value=proc),
            ),
            mock.patch.object(client.os, "killpg", side_effect=killpg),
            mock.patch.object(client, "ROUTER_TIMEOUT_SECONDS", 0.001),
            mock.patch.object(client, "ROUTER_TERMINATE_GRACE_SECONDS", 0.001),
        ):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                asyncio.run(
                    client.dispatch_interaction(
                        durable_interaction(),
                        logger,
                        expected_application_id=APPLICATION_ID,
                        expected_bot_user_id=BOT_USER_ID,
                        expected_guild_id=GUILD_ID,
                    )
                )

        self.assertEqual(signals, [client.signal.SIGTERM, client.signal.SIGKILL])
        self.assertIsNotNone(proc.returncode)

    def test_dispatch_cancellation_terminates_group_before_propagating(self) -> None:
        class HangingProc:
            def __init__(self) -> None:
                self.returncode = None
                self.pid = 43211
                self.started = asyncio.Event()
                self.reaped = asyncio.Event()

            async def communicate(self, input=None):
                del input
                self.started.set()
                await asyncio.Future()

            async def wait(self):
                await self.reaped.wait()
                return self.returncode

        proc = HangingProc()
        signals: list[int] = []

        def killpg(_pgid: int, sent_signal: int) -> None:
            signals.append(sent_signal)
            proc.returncode = -sent_signal
            proc.reaped.set()

        async def scenario() -> None:
            task = asyncio.create_task(
                client.dispatch_interaction(
                    durable_interaction(),
                    mock.MagicMock(),
                    expected_application_id=APPLICATION_ID,
                    expected_bot_user_id=BOT_USER_ID,
                    expected_guild_id=GUILD_ID,
                )
            )
            await proc.started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        with (
            mock.patch.object(
                asyncio,
                "create_subprocess_exec",
                new=mock.AsyncMock(return_value=proc),
            ),
            mock.patch.object(client.os, "killpg", side_effect=killpg),
        ):
            asyncio.run(scenario())

        self.assertEqual(signals, [client.signal.SIGTERM])
        self.assertIsNotNone(proc.returncode)

    def test_cancellation_during_spawn_still_reaps_new_process_group(self) -> None:
        class SpawnedProc:
            def __init__(self) -> None:
                self.returncode = None
                self.pid = 43212
                self.reaped = asyncio.Event()

            async def wait(self):
                await self.reaped.wait()
                return self.returncode

        proc = SpawnedProc()
        spawn_started = asyncio.Event()
        allow_spawn = asyncio.Event()
        signals: list[int] = []

        async def spawn(*_args, **_kwargs):
            spawn_started.set()
            await allow_spawn.wait()
            return proc

        def killpg(_pgid: int, sent_signal: int) -> None:
            signals.append(sent_signal)
            proc.returncode = -sent_signal
            proc.reaped.set()

        async def scenario() -> None:
            task = asyncio.create_task(
                client.dispatch_interaction(
                    durable_interaction(),
                    mock.MagicMock(),
                    expected_application_id=APPLICATION_ID,
                    expected_bot_user_id=BOT_USER_ID,
                    expected_guild_id=GUILD_ID,
                )
            )
            await spawn_started.wait()
            task.cancel()
            allow_spawn.set()
            with self.assertRaises(asyncio.CancelledError):
                await task

        with (
            mock.patch.object(asyncio, "create_subprocess_exec", side_effect=spawn),
            mock.patch.object(client.os, "killpg", side_effect=killpg),
        ):
            asyncio.run(scenario())

        self.assertEqual(signals, [client.signal.SIGTERM])
        self.assertIsNotNone(proc.returncode)

    def test_interaction_guild_must_match_configured_guild(self) -> None:
        interaction = valid_interaction()
        interaction["guild_id"] = "888888888888888888"
        state = resume_state()
        state["guild_ids"].append(interaction["guild_id"])
        with self.assertRaisesRegex(RuntimeError, "configured guild"):
            client.validate_interaction_ingress(interaction, state)

    def test_router_failure_requeues_durable_row_instead_of_completing(self) -> None:
        logger = mock.MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "interactions.sqlite3"
            client.interaction_store.enqueue(
                path,
                valid_interaction(),
                expected_application_id=APPLICATION_ID,
                expected_bot_user_id=BOT_USER_ID,
                expected_guild_id=GUILD_ID,
                now=100.0,
            )
            client.interaction_store.mark_ready(path, INTERACTION_ID)
            with (
                mock.patch.object(client, "INTERACTION_STORE_PATH", path),
                mock.patch.object(
                    client,
                    "dispatch_interaction",
                    new=mock.AsyncMock(side_effect=RuntimeError("router exit 2")),
                ),
                mock.patch.object(client.interaction_store.time, "time", return_value=100.0),
            ):
                self.assertTrue(asyncio.run(client.drain_interaction_once(logger)))
            row = client.interaction_store.get(path, INTERACTION_ID)
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["attempts"], 1)
            self.assertIn("router exit 2", row["last_error"])

    def test_retry_ceiling_dead_letters_and_emits_critical_alert(self) -> None:
        logger = mock.MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "interactions.sqlite3"
            client.interaction_store.enqueue(
                path,
                valid_interaction(),
                expected_application_id=APPLICATION_ID,
                expected_bot_user_id=BOT_USER_ID,
                expected_guild_id=GUILD_ID,
                now=100.0,
            )
            client.interaction_store.mark_ready(path, INTERACTION_ID)
            with (
                mock.patch.object(client, "INTERACTION_STORE_PATH", path),
                mock.patch.object(
                    client,
                    "dispatch_interaction",
                    new=mock.AsyncMock(side_effect=RuntimeError("router exit 2")),
                ),
                mock.patch.object(client.interaction_store, "MAX_DELIVERY_ATTEMPTS", 1),
                mock.patch.object(client.interaction_store.time, "time", return_value=100.0),
            ):
                self.assertTrue(asyncio.run(client.drain_interaction_once(logger)))
            row = client.interaction_store.get(path, INTERACTION_ID)
            self.assertEqual(row["status"], "done")
            self.assertIn("dead-letter after 1 attempts", row["last_error"])
            logger.critical.assert_called_once()

    def test_identify_budget_persists_and_waits_after_hourly_limit(self) -> None:
        logger = mock.MagicMock()
        now = 10_000.0
        with tempfile.TemporaryDirectory() as td:
            ledger_path = Path(td) / "state" / "identify_budget.json"
            with mock.patch.object(client, "IDENTIFY_LEDGER_PATH", ledger_path):
                for _ in range(client.IDENTIFY_HOURLY_LIMIT):
                    reserved, delay, reason = client.reserve_identify_slot(now, logger)
                    self.assertTrue(reserved)
                    self.assertEqual(delay, 0.0)
                    self.assertEqual(reason, "reserved")

                reserved, delay, reason = client.reserve_identify_slot(now, logger)

                self.assertFalse(reserved)
                self.assertEqual(delay, client.IDENTIFY_HOURLY_WINDOW_SECONDS)
                self.assertEqual(reason, "hourly budget")
                persisted = json.loads(ledger_path.read_text())
                self.assertEqual(
                    len(persisted["identify_timestamps"]),
                    client.IDENTIFY_HOURLY_LIMIT,
                )
                self.assertEqual(stat.S_IMODE(ledger_path.stat().st_mode), 0o600)

    def test_identify_budget_waits_in_process_then_reserves(self) -> None:
        logger = mock.MagicMock()
        clock = [20_000.0]
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)
            clock[0] += delay

        with tempfile.TemporaryDirectory() as td:
            ledger_path = Path(td) / "state" / "identify_budget.json"
            with mock.patch.object(client, "IDENTIFY_LEDGER_PATH", ledger_path):
                for _ in range(client.IDENTIFY_HOURLY_LIMIT):
                    reserved, _, _ = client.reserve_identify_slot(clock[0], logger)
                    self.assertTrue(reserved)

                with (
                    mock.patch.object(client.time, "time", side_effect=lambda: clock[0]),
                    mock.patch.object(client.asyncio, "sleep", side_effect=fake_sleep),
                ):
                    asyncio.run(client.wait_for_identify_budget(logger))

                self.assertEqual(sleeps, [client.IDENTIFY_HOURLY_WINDOW_SECONDS])
                persisted = json.loads(ledger_path.read_text())
                self.assertEqual(
                    persisted["identify_timestamps"][-1],
                    20_000.0 + client.IDENTIFY_HOURLY_WINDOW_SECONDS,
                )

    def test_identify_budget_enforces_daily_limit(self) -> None:
        logger = mock.MagicMock()
        now = 100_000.0
        prior_identify = now - (2 * client.IDENTIFY_HOURLY_WINDOW_SECONDS)
        with tempfile.TemporaryDirectory() as td:
            ledger_path = Path(td) / "state" / "identify_budget.json"
            client._atomic_write_private_json(
                ledger_path,
                {
                    "version": client.IDENTIFY_LEDGER_VERSION,
                    "identify_timestamps": [prior_identify]
                    * client.IDENTIFY_DAILY_LIMIT,
                    "blocked_until": 0.0,
                },
            )
            with mock.patch.object(client, "IDENTIFY_LEDGER_PATH", ledger_path):
                reserved, delay, reason = client.reserve_identify_slot(now, logger)

            self.assertFalse(reserved)
            self.assertEqual(
                delay,
                client.IDENTIFY_DAILY_WINDOW_SECONDS
                - (2 * client.IDENTIFY_HOURLY_WINDOW_SECONDS),
            )
            self.assertEqual(reason, "daily budget")

    def test_corrupt_identify_ledger_fails_closed_across_restart(self) -> None:
        logger = mock.MagicMock()
        now = 50_000.0
        with tempfile.TemporaryDirectory() as td:
            ledger_path = Path(td) / "state" / "identify_budget.json"
            ledger_path.parent.mkdir()
            ledger_path.write_text("{not-json")
            with mock.patch.object(client, "IDENTIFY_LEDGER_PATH", ledger_path):
                reserved, delay, reason = client.reserve_identify_slot(now, logger)
                self.assertFalse(reserved)
                self.assertEqual(delay, client.IDENTIFY_DAILY_WINDOW_SECONDS)
                self.assertEqual(reason, "corrupt ledger")

                recovered = json.loads(ledger_path.read_text())
                self.assertEqual(
                    recovered["blocked_until"],
                    now + client.IDENTIFY_DAILY_WINDOW_SECONDS,
                )
                self.assertEqual(recovered["identify_timestamps"], [])
                self.assertEqual(stat.S_IMODE(ledger_path.stat().st_mode), 0o600)

                # A second call simulates a new process reading the recovered
                # ledger. It must preserve the original fail-closed deadline.
                reserved, delay, reason = client.reserve_identify_slot(now + 1, logger)
                self.assertFalse(reserved)
                self.assertEqual(delay, client.IDENTIFY_DAILY_WINDOW_SECONDS - 1)
                self.assertEqual(reason, "fail-closed recovery")

    def test_gateway_identify_is_budget_gated(self) -> None:
        logger = mock.MagicMock()
        ws = _FakeWebSocket()
        budget_gate = mock.AsyncMock()
        with (
            mock.patch.object(client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)),
            mock.patch.object(client, "wait_for_identify_budget", budget_gate),
        ):
            asyncio.run(client.gateway_session("token", {}, logger))

        budget_gate.assert_awaited_once_with(logger)
        self.assertEqual(json.loads(ws.sent[0])["op"], client.OP_IDENTIFY)
        self.assertEqual(json.loads(ws.sent[0])["d"]["intents"], 1)

    def test_gateway_resume_bypasses_identify_budget(self) -> None:
        logger = mock.MagicMock()
        ws = _FakeWebSocket()
        budget_gate = mock.AsyncMock()
        state = resume_state()
        state["resume_gateway_url"] = "wss://resume.example"
        with (
            mock.patch.object(client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)),
            mock.patch.object(client, "wait_for_identify_budget", budget_gate),
        ):
            asyncio.run(client.gateway_session("token", state, logger))

        budget_gate.assert_not_awaited()
        self.assertEqual(json.loads(ws.sent[0])["op"], client.OP_RESUME)

    def test_gateway_reconnects_when_heartbeat_ack_is_missing(self) -> None:
        class Transport:
            def __init__(self, stopped: asyncio.Event) -> None:
                self.stopped = stopped
                self.abort_count = 0

            def abort(self) -> None:
                self.abort_count += 1
                self.stopped.set()

        class MissingAckWebSocket:
            def __init__(self) -> None:
                self.sent: list[str] = []
                self.stopped = asyncio.Event()
                self.transport = Transport(self.stopped)

            async def recv(self) -> str:
                return json.dumps(
                    {
                        "op": client.OP_HELLO,
                        "d": {"heartbeat_interval": 1},
                    }
                )

            async def send(self, payload: str) -> None:
                self.sent.append(payload)

            def __aiter__(self):
                return self

            async def __anext__(self):
                await self.stopped.wait()
                raise StopAsyncIteration

        async def exercise() -> MissingAckWebSocket:
            ws = MissingAckWebSocket()
            with (
                mock.patch.object(
                    client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)
                ),
                mock.patch.object(
                    client, "wait_for_identify_budget", new=mock.AsyncMock()
                ),
                mock.patch.object(client.random, "random", return_value=0.0),
            ):
                with self.assertRaisesRegex(RuntimeError, "heartbeat ACK timeout"):
                    await client.gateway_session("token", {}, mock.MagicMock())
            return ws

        ws = asyncio.run(exercise())
        self.assertEqual(ws.transport.abort_count, 1)
        self.assertEqual(
            [json.loads(payload)["op"] for payload in ws.sent].count(
                client.OP_HEARTBEAT
            ),
            1,
        )

    def test_gateway_continues_when_each_heartbeat_is_acknowledged(self) -> None:
        class Transport:
            def __init__(self) -> None:
                self.abort_count = 0

            def abort(self) -> None:
                self.abort_count += 1

        class AckingWebSocket:
            def __init__(self) -> None:
                self.sent: list[str] = []
                self.transport = Transport()
                self.first_heartbeat = asyncio.Event()
                self.second_heartbeat = asyncio.Event()
                self.event_index = 0
                self.heartbeat_count = 0

            async def recv(self) -> str:
                return json.dumps(
                    {
                        "op": client.OP_HELLO,
                        "d": {"heartbeat_interval": 5},
                    }
                )

            async def send(self, payload: str) -> None:
                self.sent.append(payload)
                if json.loads(payload).get("op") == client.OP_HEARTBEAT:
                    self.heartbeat_count += 1
                    if self.heartbeat_count == 1:
                        self.first_heartbeat.set()
                    elif self.heartbeat_count == 2:
                        self.second_heartbeat.set()

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self.event_index == 0:
                    await self.first_heartbeat.wait()
                    self.event_index += 1
                    return json.dumps({"op": client.OP_HEARTBEAT_ACK, "d": None})
                if self.event_index == 1:
                    await self.second_heartbeat.wait()
                    self.event_index += 1
                    return json.dumps({"op": client.OP_RECONNECT, "d": None})
                raise StopAsyncIteration

        async def exercise() -> AckingWebSocket:
            ws = AckingWebSocket()
            with (
                mock.patch.object(
                    client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)
                ),
                mock.patch.object(
                    client, "wait_for_identify_budget", new=mock.AsyncMock()
                ),
                mock.patch.object(client.random, "random", return_value=0.0),
            ):
                await client.gateway_session("token", {}, mock.MagicMock())
            return ws

        ws = asyncio.run(exercise())
        self.assertEqual(ws.heartbeat_count, 2)
        self.assertEqual(ws.transport.abort_count, 0)

    def test_gateway_does_not_resume_with_a_different_application(self) -> None:
        logger = mock.MagicMock()
        ws = _FakeWebSocket()
        budget_gate = mock.AsyncMock()
        state = resume_state()
        state["application_id"] = "888888888888888888"
        with (
            mock.patch.object(client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)),
            mock.patch.object(client, "wait_for_identify_budget", budget_gate),
        ):
            asyncio.run(client.gateway_session("token", state, logger))

        budget_gate.assert_awaited_once_with(logger)
        self.assertEqual(json.loads(ws.sent[0])["op"], client.OP_IDENTIFY)

    def test_ready_identity_must_match_configured_principals(self) -> None:
        logger = mock.MagicMock()
        event = {
            "op": client.OP_DISPATCH,
            "s": 1,
            "t": "READY",
            "d": {
                "session_id": "session-1",
                "resume_gateway_url": "wss://gateway.discord.gg",
                "application": {"id": "888888888888888888"},
                "user": {"id": BOT_USER_ID, "username": "bot"},
                "guilds": [{"id": GUILD_ID}],
            },
        }
        ws = _FakeWebSocket(events=[event])
        with (
            mock.patch.object(
                client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)
            ),
            mock.patch.object(client, "wait_for_identify_budget", new=mock.AsyncMock()),
            mock.patch.object(client, "save_state") as save,
        ):
            with self.assertRaisesRegex(RuntimeError, "configured application"):
                asyncio.run(client.gateway_session("token", {}, logger))
        save.assert_not_called()

    def test_ready_rejects_extra_guild_membership_for_dedicated_bot(self) -> None:
        event = {
            "op": client.OP_DISPATCH,
            "s": 1,
            "t": "READY",
            "d": {
                "session_id": "session-1",
                "resume_gateway_url": "wss://gateway.discord.gg",
                "application": {"id": APPLICATION_ID},
                "user": {"id": BOT_USER_ID, "username": "bot"},
                "guilds": [
                    {"id": GUILD_ID},
                    {"id": "888888888888888888"},
                ],
            },
        }
        ws = _FakeWebSocket(events=[event])
        with (
            mock.patch.object(
                client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)
            ),
            mock.patch.object(client, "wait_for_identify_budget", new=mock.AsyncMock()),
            mock.patch.object(client, "save_state") as save,
        ):
            with self.assertRaisesRegex(RuntimeError, "exactly the configured guild"):
                asyncio.run(client.gateway_session("token", {}, mock.MagicMock()))
        save.assert_not_called()

    def test_invalid_hello_does_not_consume_identify_budget(self) -> None:
        logger = mock.MagicMock()
        ws = _FakeWebSocket(hello={"op": client.OP_RECONNECT, "d": None})
        budget_gate = mock.AsyncMock()
        with (
            mock.patch.object(client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)),
            mock.patch.object(client, "wait_for_identify_budget", budget_gate),
        ):
            asyncio.run(client.gateway_session("token", {}, logger))

        budget_gate.assert_not_awaited()
        self.assertEqual(ws.sent, [])

    def test_failed_durable_enqueue_does_not_advance_resume_checkpoint(self) -> None:
        logger = mock.MagicMock()
        event = {
            "op": client.OP_DISPATCH,
            "s": 43,
            "t": "INTERACTION_CREATE",
            "d": valid_interaction(),
        }
        ws = _FakeWebSocket(events=[event])
        state = resume_state()
        with (
            mock.patch.object(client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)),
            mock.patch.object(
                client.interaction_store,
                "enqueue",
                side_effect=RuntimeError("inbox failed"),
            ),
            mock.patch.object(client, "save_state") as save,
        ):
            with self.assertRaisesRegex(RuntimeError, "inbox failed"):
                asyncio.run(client.gateway_session("token", state, logger))

        self.assertEqual(state["last_seq"], 42)
        save.assert_not_called()
        self.assertEqual(json.loads(ws.sent[0])["d"]["seq"], 42)

    def test_interaction_is_enqueued_before_receive_checkpoint(self) -> None:
        logger = mock.MagicMock()
        event = {
            "op": client.OP_DISPATCH,
            "s": 43,
            "t": "INTERACTION_CREATE",
            "d": valid_interaction(),
        }
        ws = _FakeWebSocket(events=[event])
        state = resume_state()
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state" / "client_state.json"
            inbox_path = Path(td) / "state" / "interactions.sqlite3"
            wakeup = asyncio.Event()
            with (
                mock.patch.object(client, "STATE_PATH", state_path),
                mock.patch.object(client, "INTERACTION_STORE_PATH", inbox_path),
                mock.patch.object(client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)),
                mock.patch.object(
                    client,
                    "acknowledge_approval_interaction",
                    new=mock.AsyncMock(),
                ),
            ):
                asyncio.run(
                    client.gateway_session(
                        "token", state, logger, interaction_wakeup=wakeup
                    )
                )
            self.assertEqual(json.loads(state_path.read_text())["last_seq"], 43)
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
            row = client.interaction_store.get(inbox_path, INTERACTION_ID)
            self.assertEqual(row["status"], "pending")
            self.assertNotIn("token", json.loads(row["payload_json"]))
            self.assertTrue(wakeup.is_set())

    def test_unrelated_and_plugin_interactions_checkpoint_without_validation(self) -> None:
        logger = mock.MagicMock()
        for custom_id in ("perm:allow:123", "some-plugin-action"):
            event = {
                "op": client.OP_DISPATCH,
                "s": 43,
                "t": "INTERACTION_CREATE",
                "d": {"data": {"custom_id": custom_id}},
            }
            state = resume_state()
            ws = _FakeWebSocket(events=[event])
            with (
                mock.patch.object(
                    client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)
                ),
                mock.patch.object(client.interaction_store, "enqueue") as enqueue,
                mock.patch.object(
                    client, "acknowledge_approval_interaction", new=mock.AsyncMock()
                ) as acknowledge,
                mock.patch.object(client, "save_state"),
            ):
                asyncio.run(client.gateway_session("token", state, logger))
            self.assertEqual(state["last_seq"], 43)
            enqueue.assert_not_called()
            acknowledge.assert_not_awaited()

    def test_malformed_approval_checkpoints_without_poisoning_cursor(self) -> None:
        logger = mock.MagicMock()
        event = {
            "op": client.OP_DISPATCH,
            "s": 43,
            "t": "INTERACTION_CREATE",
            "d": {"data": {"custom_id": "approve:../../etc/passwd"}},
        }
        state = resume_state()
        ws = _FakeWebSocket(events=[event])
        with (
            mock.patch.object(
                client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)
            ),
            mock.patch.object(client.interaction_store, "enqueue") as enqueue,
            mock.patch.object(client, "save_state"),
        ):
            asyncio.run(client.gateway_session("token", state, logger))
        self.assertEqual(state["last_seq"], 43)
        enqueue.assert_not_called()

    def test_non_owner_approval_is_rejected_before_durable_enqueue(self) -> None:
        logger = mock.MagicMock()
        interaction = valid_interaction()
        interaction["member"]["user"]["id"] = "888888888888888888"
        event = {
            "op": client.OP_DISPATCH,
            "s": 43,
            "t": "INTERACTION_CREATE",
            "d": interaction,
        }
        state = resume_state()
        ws = _FakeWebSocket(events=[event])
        rejection = mock.AsyncMock()
        with (
            mock.patch.object(
                client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)
            ),
            mock.patch.object(client.interaction_store, "enqueue") as enqueue,
            mock.patch.object(client, "reject_unauthorized_interaction", rejection),
            mock.patch.object(client, "save_state"),
        ):
            asyncio.run(client.gateway_session("token", state, logger))
        self.assertEqual(state["last_seq"], 43)
        enqueue.assert_not_called()
        rejection.assert_awaited_once_with(interaction, logger)

    def test_ack_failure_keeps_sequence_uncommitted_and_row_unready(self) -> None:
        logger = mock.MagicMock()
        event = {
            "op": client.OP_DISPATCH,
            "s": 43,
            "t": "INTERACTION_CREATE",
            "d": valid_interaction(),
        }
        state = resume_state()
        ws = _FakeWebSocket(events=[event])
        with (
            mock.patch.object(
                client, "_GATEWAY_CONNECT", return_value=_FakeConnect(ws)
            ),
            mock.patch.object(client.interaction_store, "enqueue") as enqueue,
            mock.patch.object(
                client,
                "acknowledge_approval_interaction",
                new=mock.AsyncMock(side_effect=RuntimeError("ACK unavailable")),
            ),
            mock.patch.object(client.interaction_store, "mark_ready") as mark_ready,
            mock.patch.object(client, "save_state") as save,
        ):
            with self.assertRaisesRegex(RuntimeError, "ACK unavailable"):
                asyncio.run(client.gateway_session("token", state, logger))
        self.assertEqual(state["last_seq"], 42)
        enqueue.assert_called_once()
        mark_ready.assert_not_called()
        save.assert_not_called()


class _FakeWebSocket:
    def __init__(
        self, hello: dict | None = None, events: list[dict] | None = None
    ) -> None:
        self.sent: list[str] = []
        self.hello = hello or {
            "op": client.OP_HELLO,
            "d": {"heartbeat_interval": 45_000},
        }
        self.events = [json.dumps(event) for event in (events or [])]

    async def recv(self) -> str:
        return json.dumps(self.hello)

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.events:
            return self.events.pop(0)
        raise StopAsyncIteration


class _FakeConnect:
    def __init__(self, ws: _FakeWebSocket) -> None:
        self.ws = ws

    async def __aenter__(self) -> _FakeWebSocket:
        return self.ws

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None


if __name__ == "__main__":
    unittest.main()
