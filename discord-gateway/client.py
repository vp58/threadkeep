#!/usr/bin/env python3
"""Persistent Discord gateway WebSocket client.

Connects to the Discord gateway, identifies with the configured bot token, runs
the heartbeat loop, and dispatches every INTERACTION_CREATE event to the
interaction router (router.py).

This client never exits on its own. It reconnects on disconnect using the
documented gateway resume/identify protocol and exponential backoff.

Run via launchd, systemd, or directly:

    python3 client.py
"""
from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import random
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

import websockets

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "conversations"))
from config import CONFIG  # noqa: E402

HERE = Path(__file__).resolve().parent
LOG_DIR = HERE / "logs"
LOG_PATH = LOG_DIR / "client.log"
STATE_PATH = HERE / "state" / "client_state.json"
GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"

# Minimal intents. Button interactions arrive regardless on INTERACTION_CREATE.
INTENTS = 1 | 512 | 4096 | 32768

OP_DISPATCH = 0
OP_HEARTBEAT = 1
OP_IDENTIFY = 2
OP_RESUME = 6
OP_RECONNECT = 7
OP_INVALID_SESSION = 9
OP_HELLO = 10
OP_HEARTBEAT_ACK = 11


def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("threadkeep-gateway")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=2_000_000, backupCount=5
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    stderr = logging.StreamHandler()
    stderr.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(stderr)
    return logger


def load_token() -> str:
    token = os.environ.get(CONFIG.discord.token_env_var, "")
    if token:
        return token
    if CONFIG.discord.token_file and CONFIG.discord.token_file.exists():
        return CONFIG.discord.token_file.read_text().strip()
    raise SystemExit(
        f"No Discord bot token found. Set {CONFIG.discord.token_env_var} "
        "or configure discord.token_file in config.toml."
    )


def save_state(state: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2))


def load_state() -> dict[str, Any]:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            return {}
    return {}


async def dispatch_interaction(interaction: dict[str, Any], logger: logging.Logger) -> None:
    """Hand the interaction payload to router.py via subprocess."""
    payload = json.dumps(interaction)
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            str(HERE / "router.py"),
            "--from-stdin",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=payload.encode("utf-8")),
            timeout=20,
        )
        if proc.returncode != 0:
            logger.warning(
                "router exit=%s stdout=%s stderr=%s",
                proc.returncode,
                stdout.decode("utf-8", errors="replace")[:500],
                stderr.decode("utf-8", errors="replace")[:500],
            )
        else:
            out = stdout.decode("utf-8", errors="replace").strip()
            if out:
                logger.info("router ok: %s", out[:500])
    except asyncio.TimeoutError:
        logger.error("router timed out after 20s")
    except Exception as exc:  # noqa: BLE001
        logger.exception("router invocation failed: %s", exc)


async def heartbeat_loop(ws: Any, interval_ms: int, state: dict[str, Any], logger: logging.Logger) -> None:
    """Send heartbeat at the interval Discord requested."""
    await asyncio.sleep((interval_ms / 1000.0) * random.random())
    while True:
        try:
            await ws.send(json.dumps({"op": OP_HEARTBEAT, "d": state.get("last_seq")}))
            logger.debug("heartbeat sent seq=%s", state.get("last_seq"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("heartbeat send failed: %s", exc)
            return
        await asyncio.sleep(interval_ms / 1000.0)


async def gateway_session(token: str, state: dict[str, Any], logger: logging.Logger) -> None:
    """One gateway session. Returns on disconnect so caller can reconnect."""
    async with websockets.connect(GATEWAY_URL, max_size=4_000_000) as ws:
        logger.info("connected to gateway")
        hello_raw = await ws.recv()
        hello = json.loads(hello_raw)
        if hello.get("op") != OP_HELLO:
            logger.error("expected HELLO, got %s", hello)
            return
        heartbeat_interval = hello["d"]["heartbeat_interval"]
        logger.info("hello: heartbeat_interval=%sms", heartbeat_interval)

        if state.get("session_id") and state.get("resume_gateway_url"):
            payload = {
                "op": OP_RESUME,
                "d": {
                    "token": token,
                    "session_id": state["session_id"],
                    "seq": state.get("last_seq"),
                },
            }
            logger.info("attempting resume session_id=%s seq=%s", state["session_id"], state.get("last_seq"))
        else:
            payload = {
                "op": OP_IDENTIFY,
                "d": {
                    "token": token,
                    "intents": INTENTS,
                    "properties": {
                        "os": sys.platform,
                        "browser": "ThreadkeepGatewayClient",
                        "device": "ThreadkeepGatewayClient",
                    },
                },
            }
            logger.info("identifying with gateway intents=%s", INTENTS)
        await ws.send(json.dumps(payload))

        hb_task = asyncio.create_task(heartbeat_loop(ws, heartbeat_interval, state, logger))

        try:
            async for raw in ws:
                msg = json.loads(raw)
                op = msg.get("op")
                if msg.get("s") is not None:
                    state["last_seq"] = msg["s"]
                if op == OP_DISPATCH:
                    event = msg.get("t")
                    data = msg.get("d") or {}
                    if event == "READY":
                        state["session_id"] = data.get("session_id")
                        state["resume_gateway_url"] = data.get("resume_gateway_url")
                        save_state(state)
                        user = (data.get("user") or {}).get("username", "?")
                        logger.info("READY user=%s session_id=%s", user, state["session_id"])
                    elif event == "RESUMED":
                        logger.info("RESUMED ok")
                    elif event == "INTERACTION_CREATE":
                        logger.info(
                            "INTERACTION_CREATE type=%s custom_id=%s user_id=%s",
                            data.get("type"),
                            (data.get("data") or {}).get("custom_id"),
                            ((data.get("member") or {}).get("user") or data.get("user") or {}).get("id"),
                        )
                        await dispatch_interaction(data, logger)
                    else:
                        logger.debug("dispatch event=%s", event)
                elif op == OP_HEARTBEAT:
                    await ws.send(json.dumps({"op": OP_HEARTBEAT, "d": state.get("last_seq")}))
                elif op == OP_HEARTBEAT_ACK:
                    logger.debug("heartbeat ack")
                elif op == OP_RECONNECT:
                    logger.info("gateway requested reconnect")
                    return
                elif op == OP_INVALID_SESSION:
                    resumable = bool(msg.get("d"))
                    logger.warning("invalid session, resumable=%s", resumable)
                    if not resumable:
                        state.pop("session_id", None)
                        state.pop("resume_gateway_url", None)
                        save_state(state)
                    await asyncio.sleep(1 + random.random() * 4)
                    return
                else:
                    logger.debug("opcode %s ignored", op)
        finally:
            hb_task.cancel()
            try:
                await hb_task
            except asyncio.CancelledError:
                pass


async def run_forever() -> None:
    logger = setup_logging()
    token = load_token()
    state = load_state()
    backoff = 1.0
    while True:
        try:
            await gateway_session(token, state, logger)
            backoff = 1.0
            logger.info("session ended cleanly, reconnecting")
        except Exception as exc:  # noqa: BLE001
            logger.exception("session error: %s", exc)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60.0)
        await asyncio.sleep(1)


def main() -> int:
    def _shutdown(_sig: int, _frame: Any) -> None:
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        asyncio.run(run_forever())
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
