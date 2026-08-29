from __future__ import annotations

import asyncio
from contextlib import contextmanager
import fcntl
import json
import math
import os
import tempfile
import time
from pathlib import Path
from typing import Iterator


LEDGER_VERSION = 1
HOUR_SECONDS = 3_600.0
DAY_SECONDS = 86_400.0


class IdentifyLedgerError(RuntimeError):
    pass


class IdentifyBudget:
    """Persistent limit for Discord Gateway IDENTIFY operations.

    Discord RESUME operations do not consume the budget. The ledger survives
    launchd restarts, which prevents a crash loop from resetting an in-memory
    counter and eventually forcing Discord to rotate the bot token.
    """

    def __init__(
        self,
        path: Path,
        *,
        per_hour: int = 20,
        per_day: int = 400,
        clock=time.time,
        sleeper=asyncio.sleep,
    ) -> None:
        self.path = path
        self.per_hour = per_hour
        self.per_day = per_day
        self.clock = clock
        self.sleeper = sleeper

    @staticmethod
    def _empty() -> dict[str, object]:
        return {"version": LEDGER_VERSION, "timestamps": [], "blocked_until": 0.0}

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        lock_path = self.path.with_name(self.path.name + ".lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _load(self) -> dict[str, object]:
        if not self.path.exists():
            return self._empty()
        try:
            raw = json.loads(self.path.read_text())
            if not isinstance(raw, dict) or raw.get("version") != LEDGER_VERSION:
                raise TypeError("invalid ledger envelope")
            values = raw.get("timestamps")
            blocked_until = raw.get("blocked_until", 0.0)
            if not isinstance(values, list):
                raise TypeError("timestamps is not a list")
            timestamps = [float(value) for value in values]
            block = float(blocked_until)
            if (
                any(value < 0 or not math.isfinite(value) for value in timestamps)
                or block < 0
                or not math.isfinite(block)
            ):
                raise ValueError("invalid ledger value")
            return {
                "version": LEDGER_VERSION,
                "timestamps": sorted(timestamps),
                "blocked_until": block,
            }
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdentifyLedgerError("Discord IDENTIFY ledger is unreadable") from exc

    def _save(self, payload: dict[str, object]) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path.parent.chmod(0o700)
        descriptor, name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w") as handle:
                os.fchmod(handle.fileno(), 0o600)
                json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def reserve(self) -> float:
        """Reserve one IDENTIFY and return zero, or return seconds to wait."""

        now = float(self.clock())
        with self._lock():
            try:
                ledger = self._load()
            except IdentifyLedgerError:
                # Unknown prior usage is never treated as zero. Persist a full
                # daily fail-closed window before allowing another IDENTIFY.
                recovery = self._empty()
                recovery["blocked_until"] = now + DAY_SECONDS
                self._save(recovery)
                return DAY_SECONDS
            blocked_until = float(ledger["blocked_until"])
            if blocked_until > now:
                return blocked_until - now
            timestamps = [
                float(stamp)
                for stamp in ledger["timestamps"]  # type: ignore[union-attr]
                if now - float(stamp) < DAY_SECONDS
            ]
            hourly = [stamp for stamp in timestamps if now - stamp < HOUR_SECONDS]
            ready_at: list[float] = []
            if len(hourly) >= self.per_hour:
                ready_at.append(hourly[-self.per_hour] + HOUR_SECONDS)
            if len(timestamps) >= self.per_day:
                ready_at.append(timestamps[-self.per_day] + DAY_SECONDS)
            if ready_at:
                ledger["timestamps"] = timestamps
                ledger["blocked_until"] = 0.0
                self._save(ledger)
                return max(1.0, max(ready_at) - now)
            timestamps.append(now)
            self._save(
                {
                    "version": LEDGER_VERSION,
                    "timestamps": timestamps,
                    "blocked_until": 0.0,
                }
            )
            return 0.0

    async def acquire(self) -> None:
        while wait := self.reserve():
            await self.sleeper(min(wait, HOUR_SECONDS))
