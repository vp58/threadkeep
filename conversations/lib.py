"""Shared library for conversation management.

All conversation .md files live under conversations_dir/active/ or
conversations_dir/archived/. Filename = session_id + ".md" (UUID format).

The .md file is the source of truth. _registry.json is a derived cache built
from frontmatter on demand. If they drift, regen the registry from .md scan.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from config import CONFIG, configured_timezone

WORKSPACE_ROOT = CONFIG.paths.workspace_root
BASE = CONFIG.paths.conversations_dir
ACTIVE = BASE / "active"
ARCHIVED = BASE / "archived"
REGISTRY = BASE / "_registry.json"
INDEX = BASE / "INDEX.md"
TEMPLATE = BASE / "_TEMPLATE.md"

DISCORD_CHAT_CHANNEL = CONFIG.discord.chat_channel_id


# ----- timestamps -----

def now_iso() -> str:
    """ISO-8601 in configured local time, suitable for frontmatter."""
    return datetime.now(configured_timezone()).isoformat(timespec="seconds")


def now_human() -> str:
    """Human-readable configured local timestamp for transcripts."""
    return datetime.now(configured_timezone()).strftime("%Y-%m-%d %H:%M %Z")


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


def days_since(iso: str) -> float:
    return (datetime.now(configured_timezone()) - parse_iso(iso)).total_seconds() / 86400.0


# ----- frontmatter -----

FM_RE = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.DOTALL)


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Return (frontmatter_dict, body). Frontmatter parsed as simple YAML
    (key: value lines, list values supported as [a, b, c])."""
    m = FM_RE.match(text)
    if not m:
        return {}, text
    fm_text, body = m.group(1), m.group(2)
    fm: dict[str, Any] = {}
    for line in fm_text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            fm[k] = [x.strip().strip("'\"") for x in inner.split(",") if x.strip()] if inner else []
        elif v.lower() in ("true", "false"):
            fm[k] = v.lower() == "true"
        elif v.isdigit():
            fm[k] = int(v)
        elif v in ("null", "~", ""):
            fm[k] = None
        else:
            fm[k] = v.strip("'\"")
    return fm, body


def write_frontmatter(fm: dict[str, Any]) -> str:
    """Render frontmatter dict back to YAML text (between --- markers)."""
    lines = ["---"]
    canonical = [
        "id", "title", "discord_channel_id", "discord_thread_id",
        "claude_session_id", "status", "created", "last_message_at",
        "message_count", "last_action_by", "tags",
    ]
    seen = set()
    for k in canonical:
        if k in fm:
            lines.append(_render_kv(k, fm[k]))
            seen.add(k)
    for k, v in fm.items():
        if k in seen:
            continue
        lines.append(_render_kv(k, v))
    lines.append("---")
    return "\n".join(lines) + "\n"


def _render_kv(k: str, v: Any) -> str:
    if isinstance(v, list):
        if not v:
            return f"{k}: []"
        return f"{k}: [{', '.join(str(x) for x in v)}]"
    if v is None:
        return f"{k}: null"
    if isinstance(v, bool):
        return f"{k}: {'true' if v else 'false'}"
    return f"{k}: {v}"


# ----- file paths -----

def conversation_path(session_id: str, status: str | None = None) -> Path:
    """Return path for a conversation file. If status is None, search active then archived."""
    if status == "active":
        return ACTIVE / f"{session_id}.md"
    if status == "archived":
        return ARCHIVED / f"{session_id}.md"
    for folder in (ACTIVE, ARCHIVED):
        p = folder / f"{session_id}.md"
        if p.exists():
            return p
    return ACTIVE / f"{session_id}.md"


def load_conversation(session_id: str) -> tuple[dict[str, Any], str, Path]:
    """Load (frontmatter, body, path). Raises FileNotFoundError if missing."""
    p = conversation_path(session_id)
    if not p.exists():
        raise FileNotFoundError(f"conversation {session_id} not found in active/ or archived/")
    text = p.read_text()
    fm, body = parse_frontmatter(text)
    return fm, body, p


def save_conversation(fm: dict[str, Any], body: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(write_frontmatter(fm) + body)


# ----- registry -----

def load_registry() -> dict[str, Any]:
    if not REGISTRY.exists():
        return {"schema_version": 1, "conversations": {}, "by_thread": {}, "last_regenerated": None}
    return json.loads(REGISTRY.read_text())


def save_registry(reg: dict[str, Any]) -> None:
    reg["last_regenerated"] = now_iso()
    REGISTRY.write_text(json.dumps(reg, indent=2) + "\n")


def regen_registry_from_disk() -> dict[str, Any]:
    """Walk active/ and archived/ and rebuild _registry.json from frontmatter."""
    reg = {"schema_version": 1, "conversations": {}, "by_thread": {}, "last_regenerated": now_iso()}
    for folder, status in ((ACTIVE, "active"), (ARCHIVED, "archived")):
        if not folder.exists():
            continue
        for path in sorted(folder.glob("*.md")):
            text = path.read_text()
            fm, _ = parse_frontmatter(text)
            sid = fm.get("claude_session_id") or path.stem
            entry = {
                "session_id": sid,
                "thread_id": fm.get("discord_thread_id"),
                "channel_id": fm.get("discord_channel_id"),
                "status": fm.get("status", status),
                "title": fm.get("title", ""),
                "created": fm.get("created"),
                "last_message_at": fm.get("last_message_at"),
                "message_count": fm.get("message_count", 0),
                "tags": fm.get("tags", []),
                "path": _display_path(path),
            }
            reg["conversations"][sid] = entry
            if entry["thread_id"]:
                reg["by_thread"][str(entry["thread_id"])] = sid
    save_registry(reg)
    return reg


# ----- index -----

def regen_index() -> None:
    """Regenerate INDEX.md from active/ and archived/ folders."""
    reg = regen_registry_from_disk()
    convos = list(reg["conversations"].values())

    active = [c for c in convos if c["status"] != "archived"]
    archived = [c for c in convos if c["status"] == "archived"]

    active.sort(key=lambda c: c.get("last_message_at") or c.get("created") or "", reverse=True)
    archived.sort(key=lambda c: c.get("last_message_at") or c.get("created") or "", reverse=True)

    archived_recent = []
    for c in archived:
        ts = c.get("last_message_at") or c.get("created")
        if ts and days_since(ts) <= 30:
            archived_recent.append(c)

    lines = [
        "---",
        "auto_generated: true",
        f"last_regenerated: {now_iso()}",
        "---",
        "",
        "# Conversation Index",
        "",
        "Auto-generated. Do not edit by hand.",
        "",
        "## Active",
        "",
    ]
    if not active:
        lines.append("_No active conversations._")
    else:
        lines.append("| Title | Status | Tags | Last activity | ID |")
        lines.append("|---|---|---|---|---|")
        for c in active:
            tags = ", ".join(c.get("tags", []) or [])
            last = c.get("last_message_at") or c.get("created") or ""
            title = (c.get("title") or "(untitled)")[:60]
            sid = c.get("session_id", "")[:8]
            lines.append(f"| {title} | {c['status']} | {tags} | {last} | `{sid}` |")
    lines.append("")
    lines.append("## Archived (last 30 days)")
    lines.append("")
    if not archived_recent:
        lines.append("_No recently archived conversations._")
    else:
        lines.append("| Title | Tags | Archived | ID |")
        lines.append("|---|---|---|---|")
        for c in archived_recent:
            tags = ", ".join(c.get("tags", []) or [])
            last = c.get("last_message_at") or c.get("created") or ""
            title = (c.get("title") or "(untitled)")[:60]
            sid = c.get("session_id", "")[:8]
            lines.append(f"| {title} | {tags} | {last} | `{sid}` |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"**Counts:** active {len(active)} | archived {len(archived)} | total {len(convos)}")
    lines.append("")

    INDEX.parent.mkdir(parents=True, exist_ok=True)
    INDEX.write_text("\n".join(lines))


# ----- operations -----

def create_conversation(
    title: str,
    thread_id: str | None = None,
    channel_id: str | None = None,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Create a new conversation .md. Returns frontmatter dict."""
    sid = session_id or str(uuid.uuid4())
    now = now_iso()
    fm = {
        "id": sid,
        "title": title,
        "discord_channel_id": channel_id or DISCORD_CHAT_CHANNEL,
        "discord_thread_id": thread_id,
        "claude_session_id": sid,
        "status": "active",
        "created": now,
        "last_message_at": now,
        "message_count": 0,
        "last_action_by": "system",
        "tags": tags or [],
    }
    body = f"\n# {title}\n\n## Summary\n\n## Open loops\n\n## Transcript\n\n"
    ACTIVE.mkdir(parents=True, exist_ok=True)
    save_conversation(fm, body, ACTIVE / f"{sid}.md")
    regen_index()
    return fm


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(WORKSPACE_ROOT))
    except ValueError:
        return str(path)


def append_turn(session_id: str, speaker: str, text: str) -> None:
    """Append a transcript turn and update last_message_at + counters."""
    fm, body, path = load_conversation(session_id)
    fm["last_message_at"] = now_iso()
    fm["last_action_by"] = speaker
    fm["message_count"] = int(fm.get("message_count", 0) or 0) + 1
    entry = f"\n### {now_human()}, {speaker}\n\n{text}\n"
    body = body.rstrip() + "\n" + entry
    save_conversation(fm, body, path)
    regen_index()


def set_status(session_id: str, status: str) -> None:
    """Update status frontmatter. If transitioning to/from archived, move file."""
    fm, body, path = load_conversation(session_id)
    fm["status"] = status
    target_dir = ARCHIVED if status == "archived" else ACTIVE
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{session_id}.md"
    if path != target:
        save_conversation(fm, body, target)
        path.unlink()
    else:
        save_conversation(fm, body, path)
    regen_index()


def archive(session_id: str, reason: str | None = None) -> None:
    fm, body, path = load_conversation(session_id)
    if reason:
        body = body.rstrip() + f"\n\n### {now_human()}, system\nArchived. Reason: {reason}\n"
    fm["status"] = "archived"
    ARCHIVED.mkdir(parents=True, exist_ok=True)
    target = ARCHIVED / f"{session_id}.md"
    save_conversation(fm, body, target)
    if path != target:
        path.unlink()
    regen_index()


def reopen(session_id: str) -> None:
    fm, body, path = load_conversation(session_id)
    fm["status"] = "active"
    fm["last_message_at"] = now_iso()
    ACTIVE.mkdir(parents=True, exist_ok=True)
    target = ACTIVE / f"{session_id}.md"
    save_conversation(fm, body, target)
    if path != target:
        path.unlink()
    regen_index()


def gc(days: int = 14) -> list[str]:
    """Auto-archive active conversations idle for `days` or more."""
    archived_ids = []
    if not ACTIVE.exists():
        return archived_ids
    for path in sorted(ACTIVE.glob("*.md")):
        text = path.read_text()
        fm, body = parse_frontmatter(text)
        last = fm.get("last_message_at") or fm.get("created")
        if not last:
            continue
        if days_since(last) >= days:
            sid = fm.get("claude_session_id") or path.stem
            archive(sid, reason=f"auto-archived after {int(days_since(last))} days idle")
            archived_ids.append(sid)
    return archived_ids


# ----- query -----

def list_conversations(status: str | None = None, tag: str | None = None) -> list[dict[str, Any]]:
    """List conversations, optionally filtered. Returns dicts from registry."""
    reg = load_registry()
    out = []
    for c in reg["conversations"].values():
        if status and c.get("status") != status:
            continue
        if tag and tag not in (c.get("tags") or []):
            continue
        out.append(c)
    out.sort(key=lambda c: c.get("last_message_at") or c.get("created") or "", reverse=True)
    return out


def thread_to_session(thread_id: str) -> str | None:
    """Look up which session_id owns a given Discord thread."""
    reg = load_registry()
    return reg.get("by_thread", {}).get(str(thread_id))


def find_by_prefix(id_prefix: str) -> str | None:
    """Resolve a short id prefix to a full session_id."""
    reg = load_registry()
    matches = [sid for sid in reg["conversations"] if sid.startswith(id_prefix)]
    if len(matches) == 1:
        return matches[0]
    return None
