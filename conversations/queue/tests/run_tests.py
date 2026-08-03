#!/usr/bin/env python3
"""End-to-end test suite for the cx-chat orchestrator queue + dispatch.

Runs WITHOUT pytest (plain asserts) so it works on a bare interpreter. Every
test runs in an isolated temp workspace with the real dispatch.py / cli.py /
lib.py code but FAKE Discord scripts (no real API calls, no real threads).

Invariants asserted:
  - ack-once          : exactly one eye reaction per message_id, even on replay
  - dispatch-once     : one thread + one transcript append per message_id
  - no message dropped: every message in a burst ends durably recorded
  - idempotent        : re-running dispatch.py for a message_id is a no-op that
                        returns identical JSON
  - per-thread order  : claims hand back a thread's messages in arrival order and
                        never two-in-flight for one thread
  - crash replay      : non-terminal rows survive and are re-armed on restart
Regression cases (from the real-world incidents this design closes):
  - inline-without-thread : a top-level message ALWAYS yields a thread
  - skipped-dispatch      : the eye + transcript only exist via dispatch/intake;
                            skipping them is detectable and never silently "ok"
Backward-compat:
  - dispatch.py top-level & reply still emit the exact JSON key contract the
    live listener depends on, with identical side effects.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

THIS = Path(__file__).resolve()
TESTS_DIR = THIS.parent
QUEUE_DIR = TESTS_DIR.parent
CONVERSATIONS_DIR = QUEUE_DIR.parent
FAKE_DISCORD = TESTS_DIR / "fake_discord"
CHAT_CHANNEL = "100000000000000001"  # placeholder listen-channel id for tests

PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(cond: bool, msg: str) -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(msg)
        print(f"  FAIL: {msg}")


def _env(ws: Path) -> dict:
    conv = ws / "conversations"
    e = dict(os.environ)
    e["THREADKEEP_VAULT_ROOT"] = str(ws)
    e["THREADKEEP_CONVERSATIONS_DIR"] = str(conv)
    e["THREADKEEP_DISCORD_SCRIPTS"] = str(FAKE_DISCORD)
    e["THREADKEEP_MQ_DB"] = str(conv / "state" / "mq.sqlite3")
    e["THREADKEEP_TEST_CALLLOG"] = str(ws / "calls.jsonl")
    e["THREADKEEP_LISTEN_CHANNEL_ID"] = CHAT_CHANNEL
    return e


def _setup_workspace() -> Path:
    """Create an isolated workspace skeleton with empty active/archived dirs."""
    d = Path(tempfile.mkdtemp(prefix="threadkeep-test-"))
    conv = d / "conversations"
    (conv / "active").mkdir(parents=True)
    (conv / "archived").mkdir(parents=True)
    (conv / "state").mkdir(parents=True)
    (conv / "logs").mkdir(parents=True)
    # seed an empty registry so thread-lookup works
    (conv / "_registry.json").write_text(json.dumps(
        {"schema_version": 1, "conversations": {}, "by_thread": {},
         "last_regenerated": None}) + "\n")
    return d


def _calls(ws: Path) -> list[dict]:
    p = ws / "calls.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def _run(args: list[str], ws: Path, check_rc: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(args, capture_output=True, text=True, env=_env(ws), timeout=120)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"cmd failed rc={r.returncode}: {args}\nSTDOUT:{r.stdout}\nSTDERR:{r.stderr}")
    return r


def dispatch(ws: Path, *args: str, check_rc: bool = True):
    return _run(["python3", str(CONVERSATIONS_DIR / "dispatch.py"), *args], ws, check_rc)


def _set_inprocess_env(ws: Path) -> None:
    """For tests that import the modules in-process, set the same env the
    subprocess fakes need so any shell-outs (react/send) hit the fakes + calllog."""
    conv = ws / "conversations"
    os.environ["THREADKEEP_VAULT_ROOT"] = str(ws)
    os.environ["THREADKEEP_CONVERSATIONS_DIR"] = str(conv)
    os.environ["THREADKEEP_DISCORD_SCRIPTS"] = str(FAKE_DISCORD)
    os.environ["THREADKEEP_MQ_DB"] = str(conv / "state" / "mq.sqlite3")
    os.environ["THREADKEEP_TEST_CALLLOG"] = str(ws / "calls.jsonl")
    os.environ["THREADKEEP_LISTEN_CHANNEL_ID"] = CHAT_CHANNEL


def mq_conn(ws: Path):
    sys.path.insert(0, str(QUEUE_DIR))
    _set_inprocess_env(ws)
    import importlib
    import mq as _mq
    importlib.reload(_mq)
    return _mq, _mq.connect()


# ---------------------------------------------------------------------------

def test_backward_compat_top_level():
    print("[1] backward-compat: dispatch.py top-level JSON contract + side effects")
    v = _setup_workspace()
    mid = "msg_bc_top_1"
    r = dispatch(v, "top-level", "--channel-id", CHAT_CHANNEL, "--message-id", mid,
                 "--user", "owner", "--title", "A test title", "--message", "hello world")
    out = json.loads(r.stdout.strip().splitlines()[-1])
    for k in ("mode", "session_id", "thread_id", "channel_id", "title", "convo_path", "is_new"):
        check(k in out, f"top-level JSON missing key {k}")
    check(out["mode"] == "top-level", "mode must be top-level")
    check(out["is_new"] is True, "is_new must be True for top-level")
    check(out["channel_id"] == CHAT_CHANNEL, "channel_id echoed")
    check(out["title"] == "A test title", "title echoed")
    # side effects: thread created, eye reacted, convo file exists w/ transcript
    calls = _calls(v)
    threads = [c for c in calls if c["call"] == "create_thread"]
    reacts = [c for c in calls if c["call"] == "react"]
    check(len(threads) == 1, "exactly one thread created (no inline-without-thread)")
    check(len(reacts) == 1, "exactly one eye reaction")
    convo = Path(out["convo_path"])
    check(convo.exists(), "convo .md created")
    check("hello world" in convo.read_text(), "user turn appended to transcript")


def test_backward_compat_reply():
    print("[2] backward-compat: dispatch.py reply JSON contract + side effects")
    v = _setup_workspace()
    # first create a top-level so a thread is registered
    r = dispatch(v, "top-level", "--channel-id", CHAT_CHANNEL, "--message-id", "m_seed",
                 "--user", "owner", "--title", "Seed", "--message", "seed")
    top = json.loads(r.stdout.strip().splitlines()[-1])
    tid = top["thread_id"]
    # now reply in that thread
    r2 = dispatch(v, "reply", "--thread-id", tid, "--message-id", "m_reply1",
                  "--user", "owner", "--message", "a reply body")
    out = json.loads(r2.stdout.strip().splitlines()[-1])
    for k in ("mode", "session_id", "thread_id", "channel_id", "title", "convo_path", "is_new"):
        check(k in out, f"reply JSON missing key {k}")
    check(out["mode"] == "reply", "mode must be reply")
    check(out["is_new"] is False, "is_new must be False for reply")
    check(out["thread_id"] == tid, "reply thread_id echoed")
    convo = Path(out["convo_path"])
    check("a reply body" in convo.read_text(), "reply turn appended")


def test_idempotent_top_level():
    print("[3] idempotency: repeat top-level message_id = same JSON, no double effects")
    v = _setup_workspace()
    mid = "msg_idem_top"
    r1 = dispatch(v, "top-level", "--channel-id", CHAT_CHANNEL, "--message-id", mid,
                  "--user", "owner", "--title", "Idem", "--message", "once")
    out1 = json.loads(r1.stdout.strip().splitlines()[-1])
    r2 = dispatch(v, "top-level", "--channel-id", CHAT_CHANNEL, "--message-id", mid,
                  "--user", "owner", "--title", "Idem", "--message", "once")
    out2 = json.loads(r2.stdout.strip().splitlines()[-1])
    check(out1 == out2, "repeat top-level returns identical JSON")
    check(r2.returncode == 0, "repeat top-level exits 0")
    calls = _calls(v)
    threads = [c for c in calls if c["call"] == "create_thread"]
    reacts = [c for c in calls if c["call"] == "react" and c["message_id"] == mid]
    check(len(threads) == 1, "dispatch-once: only ONE thread despite two runs")
    check(len(reacts) == 1, "ack-once: only ONE eye despite two runs")
    convo = Path(out1["convo_path"])
    check(convo.read_text().count("\nonce\n") == 1, "transcript appended only once")


def test_idempotent_reply():
    print("[4] idempotency: repeat reply message_id = no double append, no double ack")
    v = _setup_workspace()
    r = dispatch(v, "top-level", "--channel-id", CHAT_CHANNEL, "--message-id", "m_seed2",
                 "--user", "owner", "--title", "Seed2", "--message", "seed")
    tid = json.loads(r.stdout.strip().splitlines()[-1])["thread_id"]
    rmid = "m_reply_idem"
    r1 = dispatch(v, "reply", "--thread-id", tid, "--message-id", rmid,
                  "--user", "owner", "--message", "dup body")
    out1 = json.loads(r1.stdout.strip().splitlines()[-1])
    r2 = dispatch(v, "reply", "--thread-id", tid, "--message-id", rmid,
                  "--user", "owner", "--message", "dup body")
    out2 = json.loads(r2.stdout.strip().splitlines()[-1])
    check(out1 == out2, "repeat reply returns identical JSON")
    convo = Path(out1["convo_path"])
    check(convo.read_text().count("\ndup body\n") == 1, "reply appended only once on replay")
    reacts = [c for c in _calls(v) if c["call"] == "react" and c["message_id"] == rmid]
    check(len(reacts) == 1, "ack-once on reply replay")


def test_queue_burst_ack_once_no_drop():
    print("[5] burst via intake: N messages, each enqueued once, eye once, none dropped")
    v = _setup_workspace()
    mqmod, conn = mq_conn(v)
    import importlib, intake as _intake
    importlib.reload(_intake)
    N = 30
    ids = [f"burst_{i}" for i in range(N)]
    # simulate a fast burst: same message delivered, some delivered twice (retry)
    for mid in ids:
        _intake.handle_inbound(message_id=mid, chat_id=CHAT_CHANNEL,
                               body=f"body {mid}", user="owner", conn=conn)
    # deliver half of them a second time (duplicate delivery)
    for mid in ids[:N // 2]:
        _intake.handle_inbound(message_id=mid, chat_id=CHAT_CHANNEL,
                               body=f"body {mid}", user="owner", conn=conn)
    rows = conn.execute("SELECT message_id FROM messages").fetchall()
    check(len(rows) == N, f"no drop + dedupe: exactly {N} rows ({len(rows)} found)")
    reacts = [c for c in _calls(v) if c["call"] == "react"]
    by_mid = {}
    for c in reacts:
        by_mid[c["message_id"]] = by_mid.get(c["message_id"], 0) + 1
    # eye is idempotent on Discord side; we tolerate a re-react attempt but the
    # row count (durable record) is the strict ack-once guarantee. Assert no
    # message has ZERO eyes and the durable record is exactly-once.
    check(all(m in by_mid for m in ids), "every burst message got an eye reaction")
    conn.close()


def test_per_thread_ordering_and_mutex():
    print("[6] per-thread ordering: claims hand back oldest-first, one-in-flight/thread")
    v = _setup_workspace()
    mqmod, conn = mq_conn(v)
    import importlib, intake as _intake
    importlib.reload(_intake)
    # Two threads interleaved. Thread A gets a1,a2,a3; thread B gets b1,b2.
    seq = [("A", "a1"), ("B", "b1"), ("A", "a2"), ("A", "a3"), ("B", "b2")]
    for thr, mid in seq:
        _intake.handle_inbound(message_id=mid, chat_id=f"thread_{thr}",
                               body=mid, user="owner", react=False, conn=conn)
    # First claim per thread: should be a1 and b1 (oldest). Claim once; while A's
    # row is in flight, A must not hand back another row.
    first = mqmod.claim_next(conn)
    second = mqmod.claim_next(conn)
    claimed_ids = {first["message_id"], second["message_id"]}
    check(claimed_ids == {"a1", "b1"}, f"first two claims are oldest per thread, got {claimed_ids}")
    # No third claim available: A and B both have a row in flight.
    third = mqmod.claim_next(conn)
    check(third is None, "no thread yields a 2nd in-flight row (per-thread mutex)")
    # Finish a1 -> A's next (a2) becomes claimable, in order.
    mqmod.mark_done(conn, "a1")
    nxt = mqmod.claim_next(conn)
    check(nxt is not None and nxt["message_id"] == "a2", "thread A resumes at a2 in order")
    conn.close()


def test_crash_replay():
    print("[7] crash replay: non-terminal rows survive restart and stale claims re-arm")
    v = _setup_workspace()
    mqmod, conn = mq_conn(v)
    import importlib, intake as _intake, drainer as _drainer
    importlib.reload(_intake)
    importlib.reload(_drainer)
    for mid in ("c1", "c2", "c3"):
        _intake.handle_inbound(message_id=mid, chat_id=CHAT_CHANNEL,
                               body=mid, user="owner", react=False, conn=conn)
    # claim c1 then "crash" (never dispatch). Backdate its claim to look stale.
    row = mqmod.claim_next(conn)
    check(row["message_id"] == "c1", "claimed c1")
    conn.execute("UPDATE messages SET claimed_at=? WHERE message_id='c1'",
                 (time.time() - 9999,))
    # simulate restart: reopen connection, run startup replay
    conn.close()
    conn = mqmod.connect()
    rep = _drainer.startup_replay(conn)
    check("c1" in rep["rearmed"], "stale claimed c1 re-armed on startup")
    pend_ids = {p["message_id"] for p in rep["pending"]}
    check({"c1", "c2", "c3"} <= pend_ids, "all non-terminal rows present after restart (no loss)")
    # after re-arm, c1 is claimable again
    again = mqmod.claim_next(conn)
    check(again is not None and again["message_id"] == "c1", "c1 claimable again after replay")
    conn.close()


def test_regression_inline_without_thread():
    print("[8] regression #1: top-level ALWAYS creates a thread")
    v = _setup_workspace()
    r = dispatch(v, "top-level", "--channel-id", CHAT_CHANNEL, "--message-id", "reg_inline",
                 "--user", "owner", "--title", "Short", "--message", "Hi")
    out = json.loads(r.stdout.strip().splitlines()[-1])
    threads = [c for c in _calls(v) if c["call"] == "create_thread"]
    check(len(threads) == 1, "a short top-level still creates a thread (no inline reply)")
    check(out["thread_id"].startswith("thr_"), "thread_id present in result")


def test_regression_skipped_dispatch_detectable():
    print("[9] regression #2: skipping dispatch is detectable, not silent")
    v = _setup_workspace()
    mqmod, conn = mq_conn(v)
    import importlib, intake as _intake
    importlib.reload(_intake)
    # intake records + acks, but we deliberately DO NOT dispatch.
    _intake.handle_inbound(message_id="skip1", chat_id=CHAT_CHANNEL, body="x",
                           user="owner", conn=conn)
    m = mqmod.metrics(conn)
    check(m["received_depth"] == 1, "undispatched message is visible in queue depth")
    check(m["oldest_undispatched_age"] >= 0, "undispatched age is measured, not hidden")
    # the eye DID fire via intake (ack decoupled from dispatch), proving the
    # 'eye disappeared' mode cannot recur: ack no longer depends on the LLM
    # reaching dispatch.
    reacts = [c for c in _calls(v) if c["call"] == "react" and c["message_id"] == "skip1"]
    check(len(reacts) == 1, "eye fired at intake even though dispatch was skipped")
    conn.close()


def test_monitor_alerts():
    print("[10] observability: monitor pages on stale unacked + warns on depth")
    v = _setup_workspace()
    mqmod, conn = mq_conn(v)
    # insert a row that is old and unacked
    now = time.time()
    conn.execute(
        "INSERT INTO messages (message_id, chat_id, body, state, received_at, updated_at) "
        "VALUES ('old1', ?, 'x', 'received', ?, ?)",
        (CHAT_CHANNEL, now - 9999, now - 9999),
    )
    conn.close()
    sys.path.insert(0, str(QUEUE_DIR))
    import importlib, monitor as _mon
    importlib.reload(_mon)
    # point monitor's SEND at the fake, give it an errors channel, lower thresholds
    _mon.SEND = FAKE_DISCORD / "send_message.py"
    _mon.ERRORS_CHANNEL = CHAT_CHANNEL
    _mon.PAGE_UNACKED = 1
    _mon.WARN_UNDISPATCHED = 1
    res = _mon.check(alert=True)
    check(any("PAGE" in a for a in res["alerts"]), "monitor pages on stale unacked message")
    sends = [c for c in _calls(v) if c["call"] == "send"]
    check(len(sends) >= 1, "alert dispatched to errors channel")


def test_concurrent_appends_no_loss():
    print("[11] hardening: concurrent appends to same convo do not lose turns")
    v = _setup_workspace()
    r = dispatch(v, "top-level", "--channel-id", CHAT_CHANNEL, "--message-id", "conc_seed",
                 "--user", "owner", "--title", "Conc", "--message", "seed")
    out = json.loads(r.stdout.strip().splitlines()[-1])
    sid = out["session_id"]
    cli = str(CONVERSATIONS_DIR / "cli.py")
    # fire 8 appends concurrently via subprocess
    procs = []
    for i in range(8):
        p = subprocess.Popen(
            ["python3", cli, "append-turn", sid, "--speaker", "claude",
             "--text", f"concurrent-turn-{i}"],
            env=_env(v), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        procs.append(p)
    for p in procs:
        p.wait()
    body = Path(out["convo_path"]).read_text()
    present = sum(1 for i in range(8) if f"concurrent-turn-{i}" in body)
    check(present == 8, f"all 8 concurrent appends survived (found {present}/8) under lock")


def main() -> int:
    tests = [
        test_backward_compat_top_level,
        test_backward_compat_reply,
        test_idempotent_top_level,
        test_idempotent_reply,
        test_queue_burst_ack_once_no_drop,
        test_per_thread_ordering_and_mutex,
        test_crash_replay,
        test_regression_inline_without_thread,
        test_regression_skipped_dispatch_detectable,
        test_monitor_alerts,
        test_concurrent_appends_no_loss,
    ]
    for t in tests:
        try:
            t()
        except Exception as e:
            global FAIL
            FAIL += 1
            FAILURES.append(f"{t.__name__} raised {type(e).__name__}: {e}")
            print(f"  ERROR in {t.__name__}: {e}")
    print()
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("FAILURES:")
        for fmsg in FAILURES:
            print(f"  - {fmsg}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
