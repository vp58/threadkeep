#!/usr/bin/env python3
"""Private exchange files for text that must never be interpolated into a shell."""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path

from config import CONFIG


KINDS = {"approval", "intake", "response", "title", "query"}
EXCHANGE_ID = re.compile(r"[a-f0-9]{32}\Z")
MAX_BYTES = {
    "approval": 256_000,
    "intake": 256_000,
    "response": 256_000,
    "title": 500,
    "query": 10_000,
}


def exchange_dir() -> Path:
    path = CONFIG.paths.conversations_dir / "state" / "exchange"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError("Threadkeep exchange directory is not private and owned")
    return path


def _validate(kind: str, exchange_id: str) -> Path:
    if kind not in KINDS:
        raise ValueError("unsupported Threadkeep exchange kind")
    if not EXCHANGE_ID.fullmatch(exchange_id):
        raise ValueError("invalid Threadkeep exchange ID")
    return exchange_dir() / f"{kind}-{exchange_id}.txt"


def allocate(kind: str) -> tuple[str, Path]:
    directory = exchange_dir()
    while True:
        exchange_id = secrets.token_hex(16)
        path = directory / f"{kind}-{exchange_id}.txt"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            continue
        os.close(descriptor)
        return exchange_id, path


def read(kind: str, exchange_id: str, *, consume: bool = False) -> str:
    path = _validate(kind, exchange_id)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        # A structured editor may preserve or broaden the pre-created file mode.
        # The private 0700 directory contains that brief state; narrow it before
        # reading and require one stable, current-user-owned inode.
        os.fchmod(descriptor, 0o600)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_BYTES[kind]
        ):
            raise RuntimeError("Threadkeep exchange file is unsafe or too large")
        chunks = bytearray()
        while chunk := os.read(
            descriptor, min(65_536, MAX_BYTES[kind] + 1 - len(chunks))
        ):
            chunks.extend(chunk)
            if len(chunks) > MAX_BYTES[kind]:
                raise RuntimeError("Threadkeep exchange file exceeds its size limit")
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or after.st_nlink != 1
        ):
            raise RuntimeError("Threadkeep exchange file changed while reading")
        try:
            text = bytes(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("Threadkeep exchange file is not UTF-8") from exc
        if "\x00" in text:
            raise RuntimeError("Threadkeep exchange file contains a NUL byte")
    finally:
        os.close(descriptor)
    if consume:
        path.unlink()
    return text


def delete(kind: str, exchange_id: str) -> None:
    _validate(kind, exchange_id).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(prog="safe-files")
    sub = parser.add_subparsers(dest="command", required=True)
    alloc = sub.add_parser("allocate")
    alloc.add_argument("kind", choices=sorted(KINDS))
    remove = sub.add_parser("delete")
    remove.add_argument("kind", choices=sorted(KINDS))
    remove.add_argument("exchange_id")
    args = parser.parse_args()
    if args.command == "allocate":
        exchange_id, path = allocate(args.kind)
        print(json.dumps({"exchange_id": exchange_id, "path": str(path)}))
    else:
        delete(args.kind, args.exchange_id)
        print(json.dumps({"deleted": True}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
