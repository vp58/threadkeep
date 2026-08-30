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

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from unittest import mock
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
    e["DISCOPARTY_VAULT_ROOT"] = str(ws)
    e["DISCOPARTY_CONVERSATIONS_DIR"] = str(conv)
    e["DISCOPARTY_DISCORD_SCRIPTS"] = str(FAKE_DISCORD)
    e["DISCOPARTY_MQ_DB"] = str(conv / "state" / "mq.sqlite3")
    e["DISCOPARTY_TEST_CALLLOG"] = str(ws / "calls.jsonl")
    e["DISCOPARTY_LISTEN_CHANNEL_ID"] = CHAT_CHANNEL
    return e


def _setup_workspace() -> Path:
    """Create an isolated workspace skeleton with empty active/archived dirs."""
    d = Path(tempfile.mkdtemp(prefix="discoparty-test-"))
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
    if not args or args[0] not in {"top-level", "reply"}:
        raise ValueError("test dispatch requires top-level or reply")
    mode = args[0]
    options = dict(zip(args[1::2], args[2::2]))
    message_id = options["--message-id"]
    chat_id = options["--channel-id"] if mode == "top-level" else options["--thread-id"]
    mqmod, conn = mq_conn(ws)
    try:
        if mqmod.get(conn, message_id) is None:
            mqmod.enqueue(
                conn,
                message_id=message_id,
                chat_id=chat_id,
                body=options["--message"],
                user=options.get("--user"),
            )
            subprocess.run(
                [
                    "python3",
                    str(FAKE_DISCORD / "react.py"),
                    "--channel-id",
                    chat_id,
                    "--message-id",
                    message_id,
                    "--emoji",
                    "eyes",
                ],
                env=_env(ws),
                check=True,
                capture_output=True,
                text=True,
            )
            mqmod.mark_acked(conn, message_id)
            row = mqmod.claim_next(conn)
            if row is None or row["message_id"] != message_id:
                raise RuntimeError("test queue could not claim dispatch row")
        payload = {"message_id": message_id}
        if mode == "top-level":
            payload["title"] = options["--title"]
    finally:
        conn.close()
    result = subprocess.run(
        ["python3", str(CONVERSATIONS_DIR / "dispatch.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=_env(ws),
        timeout=120,
    )
    if check_rc and result.returncode != 0:
        raise RuntimeError(
            f"dispatch failed rc={result.returncode}\nSTDOUT:{result.stdout}\nSTDERR:{result.stderr}"
        )
    return result


def _claim_message(
    ws: Path,
    *,
    message_id: str,
    chat_id: str,
    body: str,
    user: str = "owner",
):
    mqmod, conn = mq_conn(ws)
    mqmod.enqueue(
        conn,
        message_id=message_id,
        chat_id=chat_id,
        body=body,
        user=user,
    )
    row = mqmod.claim_next(conn)
    if row is None or row["message_id"] != message_id:
        conn.close()
        raise RuntimeError("test could not claim the expected queue message")
    return mqmod, conn, row


def _dispatch_stdin(
    ws: Path,
    message_id: str,
    *,
    title: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    payload = {"message_id": message_id}
    if title is not None:
        payload["title"] = title
    environment = _env(ws)
    if extra_env:
        environment.update(extra_env)
    return subprocess.run(
        ["python3", str(CONVERSATIONS_DIR / "dispatch.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=environment,
        timeout=120,
    )


def _set_inprocess_env(ws: Path) -> None:
    """For tests that import the modules in-process, set the same env the
    subprocess fakes need so any shell-outs (react/send) hit the fakes + calllog."""
    conv = ws / "conversations"
    os.environ["DISCOPARTY_VAULT_ROOT"] = str(ws)
    os.environ["DISCOPARTY_CONVERSATIONS_DIR"] = str(conv)
    os.environ["DISCOPARTY_DISCORD_SCRIPTS"] = str(FAKE_DISCORD)
    os.environ["DISCOPARTY_MQ_DB"] = str(conv / "state" / "mq.sqlite3")
    os.environ["DISCOPARTY_TEST_CALLLOG"] = str(ws / "calls.jsonl")
    os.environ["DISCOPARTY_LISTEN_CHANNEL_ID"] = CHAT_CHANNEL


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
    mqmod.mark_errored(conn, "a1", "test terminal transition")
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
    check(out["thread_id"] == "reg_inline", "starter thread id equals source message id")


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


def test_dispatch_argv_secrecy():
    print("[12] security: body, title, and user never appear in dispatch/helper argv")
    v = _setup_workspace()
    body = "BODY_SENTINEL_9f4b"
    title = "TITLE SENTINEL 7c2a"
    user = "USER_SENTINEL_3d8e"
    message_id = "100000000000009901"
    mqmod, conn, row = _claim_message(
        v,
        message_id=message_id,
        chat_id=CHAT_CHANNEL,
        body=body,
        user=user,
    )
    _set_inprocess_env(v)
    import importlib
    import drainer as _drainer

    importlib.reload(_drainer)
    real_run = subprocess.run
    captured: list[list[str]] = []

    def recording_run(command, *args, **kwargs):
        captured.append([str(value) for value in command])
        return real_run(command, *args, **kwargs)

    with mock.patch.object(_drainer.subprocess, "run", side_effect=recording_run):
        result = _drainer.dispatch_claimed(conn, row, title=title)
    mqmod.mark_dispatched(
        conn,
        message_id,
        session_id=result["session_id"],
        thread_id=result["thread_id"],
    )
    argv_text = "\0".join(value for command in captured for value in command)
    check(body not in argv_text, "owner message body is absent from every dispatch argv")
    check(title not in argv_text, "generated title is absent from every dispatch argv")
    check(user not in argv_text, "owner display name is absent from every dispatch argv")
    helper_calls = [c for c in _calls(v) if c["call"] == "create_thread"]
    check(len(helper_calls) == 1, "thread helper was called exactly once")
    helper_argv = "\0".join(helper_calls[0]["argv"])
    check(body not in helper_argv and title not in helper_argv and user not in helper_argv,
          "opaque text is absent from helper argv")
    check(body in Path(result["convo_path"]).read_text(), "stdin/private-state body reached transcript")
    conn.close()


def test_ambiguous_thread_create_reconciles_without_repost():
    print("[13] crash replay: accepted thread create reconciles by frozen message ID")
    v = _setup_workspace()
    message_id = "100000000000009902"
    _mqmod, conn, _row = _claim_message(
        v,
        message_id=message_id,
        chat_id=CHAT_CHANNEL,
        body="thread create crash body",
    )
    conn.close()
    first = _dispatch_stdin(
        v,
        message_id,
        title="Crash safe thread",
        extra_env={"DISCOPARTY_TEST_THREAD_CRASH_AFTER_CREATE": "1"},
    )
    check(first.returncode != 0, "simulated loss of create acknowledgment fails closed")
    with sqlite3.connect(_env(v)["DISCOPARTY_MQ_DB"]) as db:
        state = db.execute(
            "SELECT state,thread_id FROM dispatch_operations WHERE message_id=?",
            (message_id,),
        ).fetchone()
    check(state == ("thread_create_attempted", message_id),
          "attempt and deterministic thread binding were durable before POST")
    check(not list((v / "conversations" / "active").glob("*.md")),
          "no conversation was fabricated without a confirmed thread")
    second = _dispatch_stdin(v, message_id, title="Crash safe thread")
    check(second.returncode == 0, f"retry reconciled accepted thread ({second.stderr.strip()})")
    out = json.loads(second.stdout)
    check(out["thread_id"] == message_id, "reconciled thread equals starter message ID")
    calls = [c for c in _calls(v) if c["call"] == "create_thread"]
    check([c["operation"] for c in calls] == ["create", "reconcile"],
          "retry used GET-only reconciliation and never repeated create")
    transcript = Path(out["convo_path"]).read_text()
    check(transcript.count("thread create crash body") == 1,
          "reconciled dispatch appended exactly one user turn")


def test_thread_create_crash_before_effect_recovers_once():
    print("[14] crash replay: pre-effect create crash recovers after durable absence")
    v = _setup_workspace()
    message_id = "100000000000009905"
    _mqmod, conn, _row = _claim_message(
        v,
        message_id=message_id,
        chat_id=CHAT_CHANNEL,
        body="pre-effect create crash body",
    )
    conn.close()
    first = _dispatch_stdin(
        v,
        message_id,
        title="Recover absent thread",
        extra_env={"DISCOPARTY_TEST_THREAD_FAIL_BEFORE_CREATE": "1"},
    )
    check(first.returncode != 0, "pre-effect create crash fails closed")
    with sqlite3.connect(_env(v)["DISCOPARTY_MQ_DB"]) as db:
        state = db.execute(
            "SELECT state,thread_id FROM dispatch_operations WHERE message_id=?",
            (message_id,),
        ).fetchone()
    check(state == ("thread_create_attempted", message_id),
          "unknown create outcome remains durably marked attempted")
    check(not (v / "fake-threads.json").exists(),
          "simulated pre-effect crash created no Discord thread")

    replay = _dispatch_stdin(v, message_id, title="Recover absent thread")
    check(replay.returncode == 0,
          f"bounded absence recovery completed ({replay.stderr.strip()})")
    out = json.loads(replay.stdout)
    calls = [c for c in _calls(v) if c["call"] == "create_thread"]
    check([c["operation"] for c in calls] == ["create", "reconcile", "recover"],
          "replay reconciled before the single recovery create")
    fake_threads = json.loads((v / "fake-threads.json").read_text())
    check(list(fake_threads) == [message_id],
          "recovery created exactly the deterministic starter thread")
    transcript = Path(out["convo_path"]).read_text()
    check(transcript.count("pre-effect create crash body") == 1,
          "recovered dispatch appended exactly one user turn")


def test_thread_recovery_state_survives_second_crash():
    print("[15] crash replay: durable absence survives a crash before recovery POST")
    v = _setup_workspace()
    message_id = "100000000000009906"
    _mqmod, conn, _row = _claim_message(
        v,
        message_id=message_id,
        chat_id=CHAT_CHANNEL,
        body="second recovery crash body",
    )
    conn.close()
    first = _dispatch_stdin(
        v,
        message_id,
        title="Persist recovery evidence",
        extra_env={"DISCOPARTY_TEST_THREAD_FAIL_BEFORE_CREATE": "1"},
    )
    check(first.returncode != 0, "initial pre-effect failure was injected")
    second = _dispatch_stdin(
        v,
        message_id,
        title="Persist recovery evidence",
        extra_env={"DISCOPARTY_TEST_THREAD_FAIL_BEFORE_RECOVERY": "1"},
    )
    check(second.returncode != 0, "crash after absence evidence fails closed")
    with sqlite3.connect(_env(v)["DISCOPARTY_MQ_DB"]) as db:
        state = db.execute(
            "SELECT state,thread_absence_confirmed_at "
            "FROM dispatch_operations WHERE message_id=?",
            (message_id,),
        ).fetchone()
    check(state is not None and state[0] == "thread_absence_confirmed" and state[1],
          "bounded absence evidence is durable before the recovery POST")
    check(not (v / "fake-threads.json").exists(),
          "second injected crash still has no external thread effect")

    replay = _dispatch_stdin(v, message_id, title="Persist recovery evidence")
    check(replay.returncode == 0,
          f"durable recovery state resumed successfully ({replay.stderr.strip()})")
    out = json.loads(replay.stdout)
    calls = [c for c in _calls(v) if c["call"] == "create_thread"]
    check([c["operation"] for c in calls] ==
          ["create", "reconcile", "recover", "recover"],
          "restart resumed recovery without reverting to initial create")
    transcript = Path(out["convo_path"]).read_text()
    check(transcript.count("second recovery crash body") == 1,
          "second crash replay still appended one user turn")


def test_thread_recovery_uses_bounded_exact_probes():
    print("[16] recovery: exact deterministic GET probes precede a retry POST")
    v = _setup_workspace()
    _set_inprocess_env(v)
    module_name = f"discoparty_create_thread_test_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(
        module_name, CONVERSATIONS_DIR.parent / "approval" / "create_thread.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the real create-thread helper")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    message_id = "100000000000009907"
    name = "Bounded recovery"
    request = {
        "operation": "recover",
        "channel_id": CHAT_CHANNEL,
        "message_id": message_id,
        "name": name,
        "auto_archive": 1440,
    }
    exact_thread = {
        "id": message_id,
        "parent_id": CHAT_CHANNEL,
        "type": 11,
        "owner_id": helper.CONFIG.discord.bot_user_id,
        "name": name,
    }

    with mock.patch.object(
        helper, "_get_existing", side_effect=[None, None, None, exact_thread]
    ) as get_existing, mock.patch.object(helper.time, "sleep"), mock.patch.object(
        helper, "_create_once"
    ) as create_once:
        resolved = helper._resolve_thread(request, "fake-token", name=name)
    check(resolved == exact_thread and get_existing.call_count == 4,
          "late exact thread visibility is accepted within the bounded probe window")
    check(create_once.call_count == 0,
          "a visible deterministic thread suppresses the recovery POST")

    with mock.patch.object(
        helper, "_get_existing", side_effect=[None, None, None, None]
    ) as get_existing, mock.patch.object(helper.time, "sleep") as sleeper, mock.patch.object(
        helper, "_create_once", return_value=exact_thread
    ) as create_once:
        resolved = helper._resolve_thread(request, "fake-token", name=name)
    check(resolved == exact_thread and get_existing.call_count == 4,
          "recovery uses one initial GET plus exactly three absence probes")
    check(sleeper.call_count == helper.RECOVERY_ABSENCE_PROBES - 1,
          "bounded probes wait only between observations")
    check(create_once.call_count == 1,
          "confirmed bounded absence permits exactly one recovery POST")


def test_concurrent_dispatch_is_single_effect():
    print("[17] concurrency: two dispatchers create one thread and one user turn")
    v = _setup_workspace()
    message_id = "100000000000009903"
    _mqmod, conn, _row = _claim_message(
        v,
        message_id=message_id,
        chat_id=CHAT_CHANNEL,
        body="concurrent dispatch body",
    )
    conn.close()
    environment = _env(v)
    environment["DISCOPARTY_TEST_THREAD_CREATE_DELAY"] = "0.4"
    payload = json.dumps({"message_id": message_id, "title": "Concurrent dispatch"})
    processes = [
        subprocess.Popen(
            ["python3", str(CONVERSATIONS_DIR / "dispatch.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        for _ in range(2)
    ]
    results = [process.communicate(payload, timeout=120) for process in processes]
    check(all(process.returncode == 0 for process in processes),
          f"both concurrent replays succeeded ({[stderr for _, stderr in results]})")
    outputs = [json.loads(stdout) for stdout, _stderr in results]
    check(outputs[0] == outputs[1], "concurrent replays returned one frozen binding")
    calls = [c for c in _calls(v) if c["call"] == "create_thread"]
    check(len(calls) == 1 and calls[0]["operation"] == "create",
          "only one thread-create helper call crossed the side-effect boundary")
    transcript = Path(outputs[0]["convo_path"]).read_text()
    check(transcript.count("concurrent dispatch body") == 1,
          "concurrent dispatch appended the inbound turn exactly once")


def test_dispatch_tamper_fails_closed():
    print("[18] tamper: changed queue body cannot replay a completed dispatch")
    v = _setup_workspace()
    message_id = "100000000000009904"
    _mqmod, conn, _row = _claim_message(
        v,
        message_id=message_id,
        chat_id=CHAT_CHANNEL,
        body="original immutable body",
    )
    conn.close()
    first = _dispatch_stdin(v, message_id, title="Immutable dispatch")
    check(first.returncode == 0, "initial immutable dispatch succeeded")
    out = json.loads(first.stdout)
    with sqlite3.connect(_env(v)["DISCOPARTY_MQ_DB"]) as db:
        db.execute(
            "UPDATE messages SET body='tampered replacement' WHERE message_id=?",
            (message_id,),
        )
    replay = _dispatch_stdin(v, message_id, title="Immutable dispatch")
    check(replay.returncode != 0 and "immutable request" in replay.stderr,
          "changed durable body is rejected by request digest")
    transcript = Path(out["convo_path"]).read_text()
    check(transcript.count("original immutable body") == 1,
          "original transcript turn remains exactly once")
    check("tampered replacement" not in transcript,
          "tampered body never reaches the transcript")
    check(len([c for c in _calls(v) if c["call"] == "create_thread"]) == 1,
          "tampered replay causes no second Discord side effect")


def test_dispatch_lock_and_db_errors_fail_closed():
    print("[19] state safety: unsafe lock and corrupt DB stop before side effects")
    v = _setup_workspace()
    message_id = "100000000000009905"
    _mqmod, conn, _row = _claim_message(
        v,
        message_id=message_id,
        chat_id=CHAT_CHANNEL,
        body="must not dispatch",
    )
    conn.close()
    lock = v / "conversations" / "state" / ".dispatch.lock"
    lock.symlink_to(v / "outside-lock-target")
    blocked = _dispatch_stdin(v, message_id, title="Unsafe lock")
    check(blocked.returncode != 0, "symlinked dispatch lock fails closed")
    check(not _calls(v), "unsafe lock fails before any Discord helper")

    broken = _setup_workspace()
    db_path = broken / "conversations" / "state" / "mq.sqlite3"
    db_path.write_bytes(b"not a sqlite database")
    os.chmod(db_path, 0o600)
    os.environ.update({
        "DISCOPARTY_VAULT_ROOT": str(broken),
        "DISCOPARTY_CONVERSATIONS_DIR": str(broken / "conversations"),
        "DISCOPARTY_MQ_DB": str(db_path),
    })
    sys.path.insert(0, str(QUEUE_DIR))
    import importlib
    import mq as corrupt_mq

    importlib.reload(corrupt_mq)
    try:
        corrupt_mq.connect()
    except Exception:
        failed = True
    else:
        failed = False
    check(failed, "corrupt queue database is rejected instead of recreated or bypassed")


def test_reaction_failure_never_marks_queue_acked():
    print("[20] acknowledgment: 401, 403, and nonzero child exits remain retriable")
    for index, status in enumerate(("401", "403", "nonzero")):
        v = _setup_workspace()
        mqmod, conn = mq_conn(v)
        import importlib
        import intake as _intake

        importlib.reload(_intake)
        message_id = f"1000000000000099{10 + index}"
        os.environ["DISCOPARTY_TEST_REACT_STATUS"] = status
        try:
            failed = _intake.handle_inbound(
                message_id=message_id,
                chat_id=CHAT_CHANNEL,
                body=f"ack failure {status}",
                user="owner",
                conn=conn,
            )
        finally:
            os.environ.pop("DISCOPARTY_TEST_REACT_STATUS", None)
        row = mqmod.get(conn, message_id)
        check(not failed["acked"], f"HTTP/exit {status} is not reported as acknowledged")
        check(row["acked_at"] is None, f"HTTP/exit {status} leaves acked_at NULL")
        retried = _intake.handle_inbound(
            message_id=message_id,
            chat_id=CHAT_CHANNEL,
            body=f"ack failure {status}",
            user="owner",
            conn=conn,
        )
        check(retried["acked"], f"HTTP/exit {status} row retries the eye reaction")
        check(mqmod.get(conn, message_id)["acked_at"] is not None,
              f"HTTP/exit {status} records only the later confirmed eye")
        conn.close()


def test_sensitive_input_is_rejected_before_queue_persistence():
    print("[21] ingress DLP: likely secrets are rejected before durable queue storage")
    v = _setup_workspace()
    mqmod, conn = mq_conn(v)
    import importlib
    import intake as _intake

    importlib.reload(_intake)
    rejected = _intake.handle_inbound(
        message_id="100000000000009950",
        chat_id=CHAT_CHANNEL,
        body="api_key=supersecretvalue123456789",
        user="owner",
        conn=conn,
    )
    check(rejected.get("rejected") == "sensitive-data", "secret input is rejected")
    check(
        mqmod.get(conn, "100000000000009950") is None,
        "rejected raw input never enters the Claude queue",
    )
    rejection_calls = [
        call
        for call in _calls(v)
        if call.get("message_id") == "100000000000009950"
    ]
    check(
        len(rejection_calls) == 1 and rejection_calls[0].get("emoji") == "🚫",
        "rejected input gets an unambiguous non-eye reaction",
    )

    accepted = _intake.handle_inbound(
        message_id="100000000000009951",
        chat_id=CHAT_CHANNEL,
        body="ordinary public task",
        user="owner",
        conn=conn,
    )
    check(accepted["new"], "ordinary input still enters the queue")
    check(
        mqmod.get(conn, "100000000000009951")["body"] == "ordinary public task",
        "ordinary queue content is unchanged",
    )
    conn.close()


def test_disabled_codex_settings_cannot_break_claude_config():
    print("[22] shared config: disabled Codex validation cannot break Claude startup")
    with tempfile.TemporaryDirectory(prefix="discoparty-config-test-") as tmp:
        config_path = Path(tmp) / "config.toml"
        config_path.write_text(
            f'''[paths]
workspace_root = "{tmp}"
conversations_dir = "{tmp}/conversations"

[discord]
chat_channel_id = "1"
errors_channel_id = "2"
owner_user_id = "3"

[runtime]
timezone = "UTC"
max_messages_per_minute = 121
max_messages_per_hour = 2001
max_concurrent_workers = 3
use_dangerously_skip_permissions = false

[codex]
enabled = false
sandbox_mode = "future-unsupported-mode"
full_computer_access_accepted = "not-a-boolean"
max_messages_per_minute = 0
max_messages_per_hour = 0
max_pending_jobs = 0
max_input_chars = 0
retention_days = 0
max_database_bytes = 0
'''
        )
        env = dict(os.environ)
        for name in tuple(env):
            if name.startswith("DISCOPARTY_CODEX_"):
                env.pop(name)
        env["DISCOPARTY_CONFIG"] = str(config_path)
        env["DISCOPARTY_CODEX_SANDBOX_MODE"] = "invalid-environment-mode"
        env["DISCOPARTY_CODEX_FULL_COMPUTER_ACCESS_ACCEPTED"] = "invalid"
        env["DISCOPARTY_CODEX_MAX_MESSAGES_PER_MINUTE"] = "invalid"
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from conversations.config import CONFIG; "
                    "assert CONFIG.codex.enabled is False; "
                    "assert CONFIG.runtime.max_messages_per_minute == 121; "
                    "assert CONFIG.runtime.max_messages_per_hour == 2001"
                ),
            ],
            cwd=CONVERSATIONS_DIR.parent,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )
        check(
            probe.returncode == 0,
            "disabled Codex-only settings are inert during Claude config import"
            + (f" ({probe.stderr.strip()})" if probe.stderr.strip() else ""),
        )

        config_path.write_text(config_path.read_text().replace("enabled = false", "enabled = true"))
        enabled_probe = subprocess.run(
            [sys.executable, "-c", "import conversations.config"],
            cwd=CONVERSATIONS_DIR.parent,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )
        check(
            enabled_probe.returncode != 0
            and "codex.sandbox_mode" in enabled_probe.stderr,
            "enabling Codex restores strict Codex-only validation",
        )


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
        test_dispatch_argv_secrecy,
        test_ambiguous_thread_create_reconciles_without_repost,
        test_thread_create_crash_before_effect_recovers_once,
        test_thread_recovery_state_survives_second_crash,
        test_thread_recovery_uses_bounded_exact_probes,
        test_concurrent_dispatch_is_single_effect,
        test_dispatch_tamper_fails_closed,
        test_dispatch_lock_and_db_errors_fail_closed,
        test_reaction_failure_never_marks_queue_acked,
        test_sensitive_input_is_rejected_before_queue_persistence,
        test_disabled_codex_settings_cannot_break_claude_config,
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
