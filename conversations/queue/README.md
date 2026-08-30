# Claude Discord queue and dispatch state machine

The Claude listener records authorized owner messages in SQLite before it does
any reasoning. One durable row then moves through intake, dispatch, worker
authorization, response delivery, and completion.

The schema migration is additive. The runtime protocol is intentionally not
backward compatible with direct `dispatch.py` calls. Dispatch accepts only a
claimed queue message ID over JSON stdin, reads the body and display name from
private state, and fails closed if the queue, operation ledger, or lock is
unavailable.

## Files

- `mq.py`: durable inbound queue, strict transitions, per-thread ordering, and
  immutable response delivery manifest.
- `idempotency.py`: fail-closed dispatch operation ledger and process lock.
- `intake.py`: owner-message intake and idempotent eye reaction.
- `drainer.py`: claim, dispatch, worker authorization, delivery, reconciliation,
  and startup inventory.
- `monitor.py`: measured backlog and dead-letter alerts.
- `tests/run_tests.py`: isolated crash, concurrency, tamper, and argv tests.

State lives at `<conversations>/state/mq.sqlite3`, mode `0600`, inside a `0700`
directory. SQLite uses WAL and `synchronous=FULL` for the state written before
Discord side effects.

## Queue states

```text
received   intake has durably recorded the message
claimed    one drainer owns pre-dispatch work
dispatched thread, conversation, and one input turn are durably bound
spawned    one worker launch has been durably authorized
done       exact response was confirmed, transcribed once, and terminalized
errored    terminal failure with no unresolved Discord response POST
```

`spawned` is an authorization written before the Agent call. A crash at that
boundary is ambiguous because the Agent call may have succeeded. Startup never
authorizes or launches a second worker automatically.

## Dispatch operation states

Each claimed message has an immutable request digest, session ID, input-turn
token, and, for a new conversation, a thread ID frozen to the Discord starter
message ID.

```text
prepared
  -> thread_create_attempted
  -> thread_confirmed
  -> conversation_ready
  -> turn_appended
  -> completed
```

A reply skips the thread and conversation creation steps. Before its first
thread POST, dispatch commits `thread_create_attempted`. If the response is
lost, retry performs only `GET /channels/{source_message_id}` and validates the
exact public-thread type, parent, bot owner, name, and ID. It never repeats an
unproven create POST.

The conversation binding and transcript append are idempotent. Random markers
inside the private transcript make a crash after file replacement safe to
replay without a second turn.

## Response delivery states

`complete-response` stores the exact filtered content, SHA-256 digest, stable
nonce, and destination before the first POST. It records `response_attempted_at`
before crossing the network boundary.

- A recent retry reuses the same nonce with `enforce_nonce=true`.
- An older unknown attempt performs a bounded Discord history scan for the
  exact bot author, destination, nonce, and content.
- A unique exact match is confirmed without another POST.
- No provable match, duplicate matches, malformed pagination, or mismatched
  content sets `response_ambiguous_at` and quarantines the row.
- `mark-errored` is rejected while a response POST is unresolved.
- The transcript is appended once only after exact Discord readback. The row
  becomes `done` only after both are durable.

`reconcile-response --message-id <id>` resumes from the stored response
manifest and never needs the original exchange file.

## Listener protocol

1. Allocate a private intake exchange and run `intake.py --exchange-id <id>`.
2. Run `drainer.py drain-one`.
3. For a top-level row, write the generated title to a private title exchange.
4. Run `drainer.py dispatch-claimed ...`.
5. Run `drainer.py mark-spawned ...` before the Agent call.
6. Spawn one background worker.
7. The worker writes a private response exchange and runs `complete-response`.

Owner text, title, and display name never appear in dispatch or Discord-helper
argv. There is no raw-text fallback.

## Existing database takeover

Do not start the new listener against an active legacy queue. First stop legacy
intake, listener, workers, and healthcheck, then take a SQLite API backup and
inventory every nonterminal row.

| Existing state | Automatic takeover treatment |
|---|---|
| `received` | Resume only after the old runtime is quiesced and Discord ingress reconciliation proves the queue is complete. No dispatch side effect has started for the row. |
| `claimed` with no `dispatch_operations` row | Unresolved manual-review item. Quarantine only after the operator acknowledges the exact count and frozen queue digest. Never replay. |
| `claimed` with `prepared` operation | Safe to resume. No Discord create attempt was recorded. |
| `claimed` with `thread_create_attempted` | Reconcile the deterministic thread ID by GET only. Never repost. |
| `claimed` with a later operation state | Resume that exact frozen operation. Transcript markers prevent duplicate turns. |
| `dispatched` | Quarantine. Under the legacy spawn-then-mark protocol, a worker may or may not already exist. Never auto-spawn. |
| `spawned` without a prepared response | Hard stop. Worker execution and local side effects may be in progress or complete. Reconcile manually before takeover. |
| `spawned` with `response_attempted_at` | Hard stop. Run response reconciliation manually. Never dead-letter or blindly POST during takeover. |
| `done` or `errored` | Preserve as terminal history. |

Legacy `dispatch_ledger` successes are imported into the new operation ledger
as completed results on first exact replay. This prevents recreating a known
thread or reappending a known input turn. It does not make an ambiguous legacy
worker launch safe.

`claude_takeover.py plan` freezes a SHA-256 digest over every full nonterminal
row and dispatch operation, then produces an exact count-bound acknowledgment.
The installer recomputes that digest only after the exact five legacy jobs and
the `cx-chat` process tree are stopped. Any drift rolls the legacy runtime back
before quarantine. The pre-mutation SQLite API snapshot, raw database and WAL
files, conversation state, approval state, and legacy plists are stored in a
private hash-manifested backup.

An explicitly quarantined `claimed` row without an operation ledger or a
`dispatched` row becomes an errored queue row so it cannot be selected. Its
entire original row is also frozen in `takeover_quarantine` for a safe rollback
before replacement acceptance. These are unresolved manual-review items, not
migrated or completed work. They are never replayed automatically.

Existing `received` rows can enter the new flow only after quiescence, backup,
and Discord cursor reconciliation. The reconciler walks the root
channel plus every thread in `_registry.json` from one global lower snowflake
through a captured maintenance upper bound. It stores the full Discord payload,
enqueues owner messages idempotently by `message_id`, and adds the eyes reaction.
It repeats the bounded scan after exact replacement readiness, tolerating
overlap without duplicates. The new Gateway starts without an old session or
sequence.

Finalization persists a private random 256-bit challenge and 15-minute expiry
before it sends a bare local drain prompt to the exact tmux listener. Discord
messages are channel-envelope wrapped and cannot invoke the local-only prompt
contract. The challenge is accepted once. Even after the exact response token,
the controller queries the queue directly and refuses to commit while any row
remains in `received`, `claimed`, or `dispatched`. Same-thread rows may wait for
the preceding new worker to finish, but the listener keeps pumping until every
safe row has crossed the durable `spawned` boundary or the handshake expires.

Automatic rollback is allowed only while the durable queue baseline proves the
replacement accepted no new row and changed no prior nonterminal row. After any
new work is admitted, or after takeover commits, restarting the legacy runtime
is forbidden.

## Tests

```bash
python3 conversations/queue/tests/run_tests.py
python3 -m unittest conversations/queue/tests/test_claude_takeover.py -v
python3 -m unittest discover -s discord-gateway/tests -t discord-gateway -v
```

The suites cover immutable duplicate intake, per-thread ordering, one input
turn under concurrent dispatch, accepted-but-unacknowledged thread creation,
argv secrecy, unsafe locks, corrupt SQLite, immutable response manifests,
unknown POST history reconciliation, terminal ambiguity quarantine, and crash
replay after Discord confirmation. The takeover suite adds shutdown ordering,
private backup verification, exact-count authorization, queue-drift rejection,
root-and-thread gap reconciliation, overlap de-duplication, fresh Gateway state,
challenge-bound safe-backlog draining, safe failure rollback, and the permanent
rollback barrier after acceptance.
