from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path


GROUP_POLL_SECONDS = 0.05
PS_PATH = Path("/bin/ps")


def supervisor_command(command: Sequence[str | os.PathLike[str]]) -> list[str]:
    """Wrap one command with the stable Disco Party process-group leader."""

    child = [os.fspath(argument) for argument in command]
    if not child:
        raise ValueError("supervised command must not be empty")
    python = Path(sys.executable)
    if not python.is_absolute() or not python.is_file():
        raise RuntimeError("current Python executable is unavailable")
    supervisor = Path(__file__).resolve(strict=True)
    return [str(python), str(supervisor), "--", *child]


def _detach_standard_streams() -> None:
    """Let only the supervised command retain the bridge's protocol pipes."""

    null_descriptor = os.open(os.devnull, os.O_RDWR)
    try:
        for descriptor in (0, 1, 2):
            os.dup2(null_descriptor, descriptor)
    finally:
        if null_descriptor > 2:
            os.close(null_descriptor)


def _group_members(process_group: int, supervisor_pid: int) -> set[int] | None:
    """Return live members, excluding this supervisor, or None on probe failure."""

    try:
        probe = subprocess.run(
            [str(PS_PATH), "-axo", "pid=,pgid="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            start_new_session=True,
        )
    except OSError:
        return None
    if probe.returncode != 0:
        return None
    members: set[int] = set()
    try:
        for line in probe.stdout.splitlines():
            fields = line.split()
            if len(fields) != 2:
                if fields:
                    return None
                continue
            pid, group = (int(field) for field in fields)
            if group == process_group and pid != supervisor_pid:
                members.add(pid)
    except ValueError:
        return None
    return members


def _child_exit_status(returncode: int) -> int:
    if returncode < 0:
        return min(255, 128 - returncode)
    return min(255, returncode)


def main(arguments: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if arguments is None else arguments)
    if len(argv) < 2 or argv[0] != "--":
        sys.stderr.write("usage: process_supervisor.py -- command [args...]\n")
        return 64
    if os.getpgrp() != os.getpid() or os.getsid(0) != os.getpid():
        sys.stderr.write(
            "Disco Party process supervisor requires a dedicated new session\n"
        )
        return 70

    # Outer cleanup signals the complete process group. Catching these signals
    # keeps the leader alive while ordinary descendants handle the same signal.
    def retain_group_leadership(_signum: int, _frame: object) -> None:
        return

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, retain_group_leadership)
    try:
        child = subprocess.Popen(argv[1:])
    except OSError:
        sys.stderr.write("Disco Party process supervisor could not start its child\n")
        return 126

    _detach_standard_streams()
    returncode = child.wait()
    process_group = os.getpgrp()
    supervisor_pid = os.getpid()
    while True:
        members = _group_members(process_group, supervisor_pid)
        if members == set():
            return _child_exit_status(returncode)
        time.sleep(GROUP_POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
