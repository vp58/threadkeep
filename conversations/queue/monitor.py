#!/usr/bin/env python3
"""Backlog observability + alerting for the cx-chat queue.

Emits the real measured numbers and alerts when they cross thresholds:

    oldest_unacked_age      PAGE  -> intake is down / the human is being ignored
    oldest_undispatched_age WARN  -> the drainer is falling behind
    queue_depth / errored   context

Designed to run from launchd/systemd/cron on a short interval (like the existing
healthcheck). Alerts go to the errors Discord channel via approval/send_message.py.
Fail-open: a monitor that cannot read the DB warns to stderr but never crashes
the box.

The undispatched-age WARN fires ONLY for a message the drainer could dispatch
right now (its thread has nothing in flight). A message correctly serialized
behind an in-flight same-thread predecessor (one-in-flight-per-thread) is not
the drainer falling behind, so it does not count (mq.metrics enforces this). A
genuinely STUCK in-flight worker is caught separately by oldest_inflight_age at
a much higher threshold, so normal long tasks (renders) don't false-alarm.

Configuration (env vars):
    THREADKEEP_ERRORS_CHANNEL_ID     Discord channel id alerts are posted to
    THREADKEEP_DISCORD_SCRIPTS       dir holding send_message.py (default approval/)
    THREADKEEP_CONVERSATIONS_DIR     where logs/ live (default <repo>/conversations)
    THREADKEEP_PAGE_UNACKED_SEC      (default 120)
    THREADKEEP_WARN_UNDISPATCHED_SEC (default 180)
    THREADKEEP_WARN_INFLIGHT_SEC     (default 5400)
    THREADKEEP_WARN_DEPTH            (default 25)
    THREADKEEP_REALERT_INFLIGHT_SEC  (default 21600)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import mq  # noqa: E402

_REPO_ROOT = _HERE.parents[1]
_DISCORD_SCRIPTS = Path(
    os.environ.get("THREADKEEP_DISCORD_SCRIPTS", str(_REPO_ROOT / "approval"))
).expanduser()
SEND = _DISCORD_SCRIPTS / "send_message.py"
ERRORS_CHANNEL = os.environ.get("THREADKEEP_ERRORS_CHANNEL_ID", "")

_conv = os.environ.get("THREADKEEP_CONVERSATIONS_DIR")
_LOG_DIR = (Path(_conv).expanduser() if _conv else _HERE.parent) / "logs"
METRICS_LOG = _LOG_DIR / "queue-metrics.jsonl"
# Sidecar de-dupe state for the in-flight WARN so one stuck row alerts once (and
# then only every RE_ALERT_INFLIGHT_SEC) instead of re-posting every run for the
# row's entire life.
ALERT_STATE = _LOG_DIR / "queue-monitor-alert-state.json"

PAGE_UNACKED = float(os.environ.get("THREADKEEP_PAGE_UNACKED_SEC", "120"))
WARN_UNDISPATCHED = float(os.environ.get("THREADKEEP_WARN_UNDISPATCHED_SEC", "180"))
WARN_INFLIGHT = float(os.environ.get("THREADKEEP_WARN_INFLIGHT_SEC", "5400"))
WARN_DEPTH = int(os.environ.get("THREADKEEP_WARN_DEPTH", "25"))
# How often to RE-alert on the SAME still-stuck in-flight row (seconds). A
# genuinely hung worker still nags at this cadence; it just no longer spams the
# identical WARN every run. Default 6h.
RE_ALERT_INFLIGHT = float(os.environ.get("THREADKEEP_REALERT_INFLIGHT_SEC", "21600"))


def _alert(text: str) -> None:
    if not ERRORS_CHANNEL:
        print(f"[monitor] no errors channel configured, alert dropped: {text}",
              file=sys.stderr)
        return
    try:
        subprocess.run(
            ["python3", str(SEND), "--channel-id", ERRORS_CHANNEL, "--message", text],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except Exception as e:  # pragma: no cover
        print(f"alert send failed: {e}", file=sys.stderr)


def _log_metrics(m: dict) -> None:
    try:
        METRICS_LOG.parent.mkdir(parents=True, exist_ok=True)
        rec = dict(m)
        rec["at"] = time.time()
        with METRICS_LOG.open("a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass


def _load_alert_state() -> dict:
    try:
        return json.loads(ALERT_STATE.read_text())
    except Exception:
        return {}


def _save_alert_state(state: dict) -> None:
    try:
        ALERT_STATE.parent.mkdir(parents=True, exist_ok=True)
        ALERT_STATE.write_text(json.dumps(state))
    except Exception:
        pass


def _oldest_inflight_id(conn) -> "str | None":
    """message_id of the oldest still-in-flight row (the one metrics ages).

    Same source of truth mq.metrics uses for oldest_inflight_age, so the identity
    always matches the age we alert on. Returns None if nothing is in flight.
    """
    r = conn.execute(
        "SELECT message_id FROM messages "
        "WHERE state IN ('claimed','dispatched','spawned') AND claimed_at IS NOT NULL "
        "ORDER BY claimed_at ASC LIMIT 1"
    ).fetchone()
    return r["message_id"] if r else None


def _inflight_suppression(prev: "dict | None", inflight_id: "str | None",
                          now: float) -> "tuple[bool, dict | None]":
    """Decide whether to suppress the in-flight WARN and return the new state.

    prev is the last recorded {"id", "last_alert_at"} (or None). inflight_id is
    the oldest stuck row THIS run when it is over threshold, else None. Fires when
    a different row is stuck, or the same row crosses the re-alert interval; keeps
    quiet in between so a single hung worker cannot spam every run. When nothing
    is stuck, the state is cleared so a later, distinct stuck row alerts fresh.
    """
    if inflight_id is None:
        return True, None
    if (prev and prev.get("id") == inflight_id
            and (now - float(prev.get("last_alert_at", 0))) < RE_ALERT_INFLIGHT):
        return True, prev
    return False, {"id": inflight_id, "last_alert_at": now}


def check(alert: bool = True) -> dict:
    conn = mq.connect()
    now = time.time()
    try:
        m = mq.metrics(conn)
        # Pull the errored rows that have not yet had their dead-letter WARN
        # emitted. Only these page; a handled-but-errored row that already paged
        # is acked below so it cannot re-warn every interval forever.
        unacked_errored = mq.errored_unacked(conn)
        unacked_ids = [r["message_id"] for r in unacked_errored]

        # In-flight WARN de-dupe. mq.metrics already recomputes oldest_inflight_age
        # LIVE from the DB every run, so a cleared row drops to 0 instantly and
        # never re-warns. What was missing was rate-limiting: a row genuinely stuck
        # for hours re-posted the identical WARN every run. Alert once per stuck
        # row, then only every RE_ALERT_INFLIGHT_SEC, keyed on the row's id.
        state = _load_alert_state()
        inflight_over = m.get("oldest_inflight_age", 0.0) >= WARN_INFLIGHT
        inflight_id = _oldest_inflight_id(conn) if inflight_over else None
        suppress_inflight, new_inflight_state = _inflight_suppression(
            state.get("inflight"), inflight_id, now
        )

        alerts = _build_alerts(m, unacked_ids, suppress_inflight=suppress_inflight)

        if alert:
            for a in alerts:
                _alert(a)
            # Ack the dead-letters we just paged on so the siren stops. A NEW
            # errored row still pages once (it starts unacked); mark_errored
            # resets the ack so a row that re-errors pages again.
            if unacked_ids:
                mq.ack_dead_letters(conn, unacked_ids)
            # Persist the in-flight de-dupe state (records this run's alert time or
            # clears it when nothing is stuck) so the next run knows to stay quiet.
            state["inflight"] = new_inflight_state
            _save_alert_state(state)
    finally:
        conn.close()
    _log_metrics(m)

    m["alerts"] = alerts
    return m


def _build_alerts(m: dict, unacked_errored_ids: list,
                  suppress_inflight: bool = False) -> list:
    alerts = []
    if m["oldest_unacked_age"] >= PAGE_UNACKED:
        alerts.append(
            f"PAGE cx-chat intake: oldest unacked message is "
            f"{int(m['oldest_unacked_age'])}s old (threshold {int(PAGE_UNACKED)}s). "
            f"The eye reaction is not firing. {m['received_depth']} message(s) waiting."
        )
    if m["oldest_undispatched_age"] >= WARN_UNDISPATCHED:
        alerts.append(
            f"WARN cx-chat drainer: oldest undispatched message is "
            f"{int(m['oldest_undispatched_age'])}s old (threshold {int(WARN_UNDISPATCHED)}s). "
            f"queue_depth={m['queue_depth']}."
        )
    if not suppress_inflight and m.get("oldest_inflight_age", 0.0) >= WARN_INFLIGHT:
        alerts.append(
            f"WARN cx-chat worker: a message has been in flight "
            f"{int(m['oldest_inflight_age'])}s (threshold {int(WARN_INFLIGHT)}s). "
            f"A worker may be hung. inflight_depth={m['inflight_depth']}."
        )
    if m["queue_depth"] >= WARN_DEPTH:
        alerts.append(
            f"WARN cx-chat queue depth {m['queue_depth']} >= {WARN_DEPTH}. "
            f"by_state={m['by_state']}."
        )
    if unacked_errored_ids:
        alerts.append(
            f"WARN cx-chat dead-letter: {len(unacked_errored_ids)} errored "
            f"message(s) need attention: {', '.join(unacked_errored_ids)}."
        )

    return alerts


if __name__ == "__main__":
    out = check(alert="--no-alert" not in sys.argv)
    print(json.dumps(out, indent=2))
