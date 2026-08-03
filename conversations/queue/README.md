# cx-chat orchestrator queue (durable, idempotent intake + drainer)

Makes the listener burst-safe: instant ack and durable enqueue OFF the LLM hot
path, idempotency keyed on the Discord `message_id`, the listener demoted to a
queue drainer, backlog observability, and crash recovery / replay.

Everything here is ADDITIVE. The legacy path (listener calls `dispatch.py`
directly) keeps working unchanged whether or not this package is active, because
`dispatch.py` is idempotent on `message_id`.

## Why

Without a queue, the eye-reaction ack and the durable record of an inbound
message both depend on the LLM listener reaching them. Under a burst, or during a
compaction / restart, that meant messages could go un-acked or, worse, get a
worker spawned without the transcript ever being appended. The queue moves the
ack and the durable write to deterministic, LLM-free code so they happen the
instant a message lands, and survive a crash.

## Files

- `mq.py`         durable SQLite queue (WAL), state machine, per-thread ordering,
                  claim-by-update, crash recovery, metrics.
- `idempotency.py` ledger used by `dispatch.py` (message_id -> stored JSON).
- `intake.py`    `handle_inbound()`: react eye + enqueue, deterministic, no LLM.
- `drainer.py`   claim next ready row, classify (registry lookup), call the
                 idempotent `dispatch.py`, mark state; `startup_replay()`.
- `monitor.py`   emit `oldest_unacked_age` / `oldest_undispatched_age` /
                 `queue_depth`, alert to the errors channel on thresholds.
- `tests/run_tests.py` end-to-end suite (no pytest needed).

State DB: `<conversations>/state/mq.sqlite3`. Override with `THREADKEEP_MQ_DB`,
or point `THREADKEEP_CONVERSATIONS_DIR` at your workspace conversations dir.

## State machine

```
received   -> intake inserted the row (eye reaction already added)
claimed    -> a drainer took ownership to dispatch it
dispatched -> dispatch.py ran (thread bound, transcript appended)
spawned    -> a worker subagent was launched
done       -> worker finished
errored    -> terminal failure (dead-lettered)
```

`claim_next` hands back the oldest `received` row whose thread has nothing in
flight, so per-thread order is preserved and a thread never has two messages in
flight at once.

## Listener protocol (queue-first)

The listener becomes a drainer. Per inbound message:

1. INTAKE FIRST (deterministic, no reasoning). Call `intake.handle_inbound(
   message_id, chat_id, body, user)`. This adds the eye reaction and durably
   records the message. Idempotent on `message_id`.

2. DRAIN. Call `drainer.drain_one(conn)`. It claims the oldest ready row and
   returns its classification (`top-level` | `reply` | `unowned`) and whether a
   title is needed.
   - `unowned`: `mark_errored` and stop.
   - `top-level` needing a title: the LLM supplies a 4-7 word title, then
     `dispatch_claimed(conn, row, title=...)`.
   - `reply`: `dispatch_claimed(conn, row)` (no title).

3. SPAWN, then `mark_spawned`. The worker runs async and posts to the thread.

On startup / after a restart or compaction, run `drainer.startup_replay(conn)`
once to re-arm stale claims and list non-terminal rows a crash left behind.

## Configuration (env vars)

| Var | Meaning | Default |
|---|---|---|
| `THREADKEEP_MQ_DB` | queue SQLite path | `<conversations>/state/mq.sqlite3` |
| `THREADKEEP_CONVERSATIONS_DIR` | conversations dir (state/, logs/ live under it) | `<repo>/conversations` |
| `THREADKEEP_LISTEN_CHANNEL_ID` | listen channel; a top-level post here is a new thread | (unset) |
| `THREADKEEP_DISCORD_SCRIPTS` | dir holding `react.py` / `send_message.py` | `<repo>/approval` |
| `THREADKEEP_DEFAULT_USER` | posting username when a row has none | `owner` |
| `THREADKEEP_ERRORS_CHANNEL_ID` | channel `monitor.py` posts alerts to | (unset) |
| `THREADKEEP_PAGE_UNACKED_SEC` | PAGE threshold: oldest unacked age | `120` |
| `THREADKEEP_WARN_UNDISPATCHED_SEC` | WARN threshold: oldest undispatched age | `180` |
| `THREADKEEP_WARN_INFLIGHT_SEC` | WARN threshold: oldest in-flight age | `5400` |
| `THREADKEEP_WARN_DEPTH` | WARN threshold: queue depth | `25` |

`monitor.py` is meant to run on a short interval (launchd / systemd / cron), the
same way as the healthcheck. It fails open: if it cannot read the DB it warns to
stderr and never crashes the box.

## Tests

```
python3 conversations/queue/tests/run_tests.py
```

Runs in isolated temp workspaces with fake Discord scripts (no real API).
Asserts ack-once, dispatch-once, no-drop, idempotency, per-thread ordering,
crash replay, the two incident regressions (a top-level always gets a thread;
skipping dispatch is detectable, not silent), monitor alerting, concurrent-append
safety, and the `dispatch.py` backward-compat JSON contract.
