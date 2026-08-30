from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import textwrap
import time
import unicodedata
from datetime import datetime
from pathlib import Path

from conversations.public_output import public_safe_output

from .config import Config


def _terminal_safe(text: object) -> str:
    """Make untrusted ledger text inert before writing it to a terminal."""

    normalized = []
    for character in str(text):
        if character.isspace():
            normalized.append(" ")
            continue
        if unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
            continue
        normalized.append(character)
    return "".join(normalized)


def _compact(
    text: object,
    limit: int = 1200,
    *,
    channel_trust: str = "public",
) -> str:
    raw = public_safe_output(
        str(text),
        agent_name="Disco Party monitor",
        channel_trust=channel_trust,
    )
    cleaned = " ".join(_terminal_safe(raw).split())
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return textwrap.fill(cleaned, width=110, subsequent_indent="    ")


def _ready_workers(path: Path, configured_workers: int) -> int:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            return 0
        data = json.loads(path.read_text())
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return 0
    workers_ready = data.get("workers_ready", 1 if data.get("ready") is True else 0)
    workers_configured = data.get("workers_configured", configured_workers)
    if (
        data.get("version") != 1
        or data.get("ready") is not True
        or type(workers_ready) is not int
        or type(workers_configured) is not int
        or workers_configured != configured_workers
        or not 0 <= workers_ready <= workers_configured
    ):
        return 0
    return workers_ready


def render(
    path: Path,
    channel_name: str = "configured channel",
    configured_workers: int = 1,
    channel_trust: str = "public",
) -> str:
    safe_channel_name = _compact(channel_name, 100)
    ready_workers = _ready_workers(path.parent / "ready.json", configured_workers)
    if not path.exists():
        return (
            f"Codex Discord {safe_channel_name} monitor\n\n"
            f"Workers: configured={configured_workers} ready={ready_workers} running=0\n\n"
            "Waiting for the private job ledger to be created."
        )
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
    try:
        jobs = db.execute(
            "SELECT event_id,channel_id,state,content,updated_at,result_message_id "
            "FROM jobs ORDER BY updated_at DESC,event_id DESC LIMIT 12"
        ).fetchall()
        delivery_rows = db.execute(
            "SELECT event_id,chunk_index,content,state,ambiguous_at "
            "FROM deliveries ORDER BY event_id,chunk_index"
        ).fetchall()
        deliveries: dict[str, tuple[int, int, list[str]]] = {}
        for event_id, _chunk_index, content, state, ambiguous_at in delivery_rows:
            sent, ambiguous, chunks = deliveries.get(event_id, (0, 0, []))
            deliveries[event_id] = (
                sent + (1 if state == "sent" else 0),
                ambiguous + (1 if ambiguous_at is not None else 0),
                [*chunks, str(content)],
            )
        manifests = {
            row[0]: (row[1], row[2])
            for row in db.execute(
                "SELECT event_id,state,chunk_count FROM delivery_manifests"
            )
        }
        running_workers = int(
            db.execute("SELECT COUNT(*) FROM jobs WHERE state='running'").fetchone()[0]
        )
    finally:
        db.close()

    lines = [
        f"Codex Discord {safe_channel_name} monitor (local Mac only)",
        "The LaunchAgent runs the bridge. This tmux window is observation only.",
        f"Updated {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        (
            f"Workers: configured={configured_workers} ready={ready_workers} "
            f"running={running_workers}"
        ),
        "",
    ]
    if not jobs:
        lines.append("No jobs recorded yet.")
        return "\n".join(lines)
    for event_id, channel_id, state, content, updated_at, result_message_id in jobs:
        timestamp = datetime.fromtimestamp(updated_at).astimezone().strftime("%m-%d %H:%M:%S")
        manifest_state, expected_chunks = manifests.get(event_id, ("none", 0))
        sent_chunks, ambiguous_chunks, output_chunks = deliveries.get(
            event_id, (0, 0, [])
        )
        safe_state = _compact(state, 20).upper()
        safe_event_id = _compact(event_id, 40)
        safe_channel_id = _compact(channel_id, 40)
        safe_manifest_state = _compact(manifest_state, 20)
        safe_result_id = _compact(result_message_id or "-", 40)
        lines.append(
            f"[{timestamp}] {safe_state:9} event={safe_event_id} source={safe_channel_id} "
            f"output={safe_manifest_state}:{sent_chunks}/{expected_chunks} "
            f"ambiguous={ambiguous_chunks} result={safe_result_id}"
        )
        lines.append(
            f"    Owner: {_compact(content, channel_trust=channel_trust)}"
        )
        if output_chunks:
            lines.append(
                f"    Codex: {_compact(''.join(output_chunks), channel_trust=channel_trust)}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only local monitor for the Codex Discord bridge")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = Config.from_discoparty()
    path = config.state_dir / "jobs.sqlite3"
    while True:
        output = render(
            path,
            config.channel_id,
            config.max_concurrent_workers,
            config.channel_trust,
        )
        if args.once:
            print(output)
            return
        print("\033[2J\033[H" + output, end="", flush=True)
        time.sleep(1)


if __name__ == "__main__":
    main()
