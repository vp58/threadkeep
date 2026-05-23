#!/usr/bin/env python3
"""Conversation CLI. Single entry point for all conversation operations.

Usage:
    cli.py new --title "..." [--thread-id N] [--tags a,b] [--session-id UUID]
    cli.py list [--status active|archived|working|blocked] [--tag X]
    cli.py show <id-or-prefix>
    cli.py archive <id-or-prefix> [--reason "..."]
    cli.py reopen <id-or-prefix>
    cli.py status <id-or-prefix> <new-status>
    cli.py append-turn <id-or-prefix> --speaker user|claude|system --text "..."
    cli.py thread-lookup <thread_id>
    cli.py regen-index
    cli.py gc [--days N]
    cli.py search "<query>"
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import lib


def _resolve(id_or_prefix: str) -> str:
    if len(id_or_prefix) == 36:
        return id_or_prefix
    full = lib.find_by_prefix(id_or_prefix)
    if not full:
        print(f"error: id prefix '{id_or_prefix}' does not match exactly one conversation", file=sys.stderr)
        sys.exit(2)
    return full


def cmd_new(args: argparse.Namespace) -> None:
    tags = [t.strip() for t in args.tags.split(",")] if args.tags else []
    fm = lib.create_conversation(
        title=args.title,
        thread_id=args.thread_id,
        tags=tags,
        session_id=args.session_id,
    )
    print(json.dumps(fm, indent=2))


def cmd_list(args: argparse.Namespace) -> None:
    rows = lib.list_conversations(status=args.status, tag=args.tag)
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("(no conversations)")
        return
    for r in rows:
        sid = r.get("session_id", "")[:8]
        title = (r.get("title") or "(untitled)")[:60]
        tags = ",".join(r.get("tags", []) or [])
        last = r.get("last_message_at") or r.get("created") or "?"
        print(f"{sid}  {r['status']:<8}  {last[:16]}  [{tags}]  {title}")


def cmd_show(args: argparse.Namespace) -> None:
    sid = _resolve(args.id)
    fm, body, path = lib.load_conversation(sid)
    print(f"# {fm.get('title')}")
    print(f"id: {sid}")
    print(f"status: {fm.get('status')}")
    print(f"thread: {fm.get('discord_thread_id')}")
    print(f"created: {fm.get('created')}")
    print(f"last_message_at: {fm.get('last_message_at')}")
    print(f"messages: {fm.get('message_count')}")
    print(f"tags: {fm.get('tags')}")
    print(f"path: {path}")
    print()
    print(body)


def cmd_archive(args: argparse.Namespace) -> None:
    sid = _resolve(args.id)
    lib.archive(sid, reason=args.reason)
    print(f"archived {sid}")


def cmd_reopen(args: argparse.Namespace) -> None:
    sid = _resolve(args.id)
    lib.reopen(sid)
    print(f"reopened {sid}")


def cmd_status(args: argparse.Namespace) -> None:
    sid = _resolve(args.id)
    lib.set_status(sid, args.new_status)
    print(f"status of {sid} set to {args.new_status}")


def cmd_append_turn(args: argparse.Namespace) -> None:
    sid = _resolve(args.id)
    lib.append_turn(sid, speaker=args.speaker, text=args.text)
    print(f"appended {args.speaker} turn to {sid}")


def cmd_thread_lookup(args: argparse.Namespace) -> None:
    sid = lib.thread_to_session(args.thread_id)
    if sid:
        print(sid)
    else:
        sys.exit(1)


def cmd_regen_index(_: argparse.Namespace) -> None:
    lib.regen_index()
    print("regenerated")


def cmd_gc(args: argparse.Namespace) -> None:
    ids = lib.gc(days=args.days)
    if not ids:
        print("nothing to archive")
        return
    print(f"archived {len(ids)} conversation(s):")
    for sid in ids:
        print(f"  {sid}")


def cmd_search(args: argparse.Namespace) -> None:
    """Fall back to ripgrep against active/ and archived/."""
    query = args.query
    cmd = ["rg", "-l", "-i", query, str(lib.ACTIVE), str(lib.ARCHIVED)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        files = [Path(f).stem for f in result.stdout.strip().splitlines()]
        if not files:
            print("(no matches)")
            return
        for f in files:
            print(f)
    except FileNotFoundError:
        print("error: rg is not installed. Install ripgrep to enable search.", file=sys.stderr)
        sys.exit(3)


def main() -> None:
    p = argparse.ArgumentParser(prog="convo")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_new = sub.add_parser("new")
    p_new.add_argument("--title", required=True)
    p_new.add_argument("--thread-id", default=None)
    p_new.add_argument("--tags", default="")
    p_new.add_argument("--session-id", default=None)
    p_new.set_defaults(func=cmd_new)

    p_list = sub.add_parser("list")
    p_list.add_argument("--status", default=None)
    p_list.add_argument("--tag", default=None)
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show")
    p_show.add_argument("id")
    p_show.set_defaults(func=cmd_show)

    p_arch = sub.add_parser("archive")
    p_arch.add_argument("id")
    p_arch.add_argument("--reason", default=None)
    p_arch.set_defaults(func=cmd_archive)

    p_reo = sub.add_parser("reopen")
    p_reo.add_argument("id")
    p_reo.set_defaults(func=cmd_reopen)

    p_stat = sub.add_parser("status")
    p_stat.add_argument("id")
    p_stat.add_argument("new_status")
    p_stat.set_defaults(func=cmd_status)

    p_app = sub.add_parser("append-turn")
    p_app.add_argument("id")
    p_app.add_argument("--speaker", required=True, choices=["user", "claude", "system"])
    p_app.add_argument("--text", required=True)
    p_app.set_defaults(func=cmd_append_turn)

    p_th = sub.add_parser("thread-lookup")
    p_th.add_argument("thread_id")
    p_th.set_defaults(func=cmd_thread_lookup)

    p_idx = sub.add_parser("regen-index")
    p_idx.set_defaults(func=cmd_regen_index)

    p_gc = sub.add_parser("gc")
    p_gc.add_argument("--days", type=int, default=14)
    p_gc.set_defaults(func=cmd_gc)

    p_s = sub.add_parser("search")
    p_s.add_argument("query")
    p_s.set_defaults(func=cmd_search)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
