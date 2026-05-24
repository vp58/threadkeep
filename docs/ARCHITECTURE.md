# Threadkeep architecture

Threadkeep is built around a hard separation between listening and working. A single Claude Code session listens to one Discord channel and never does work itself. It writes state to disk and fires a background subagent for every message. The subagent does the work and exits. This lets the listener handle many parallel conversations without stalling.

## Component map

```
                 +-----------------+
   Discord  ---> | Discord plugin  |
   channel       | (Claude Code)   |
                 +--------+--------+
                          |
                          v
   +---------------------- listener ----------------------+
   | Claude Code session running agent/cx-chat.md         |
   |   - For top-level posts: dispatch.py creates thread  |
   |     + conversation, fires Agent subagent             |
   |   - For thread replies: dispatch.py appends turn,    |
   |     fires Agent subagent                             |
   |   - For /convo commands: runs CLI inline             |
   +------------------+-----------------+------------------+
                      |                 |
                      v                 v
              conversations/      Agent subagent
              active/<sid>.md     (general-purpose)
                                  |
                                  v
                          worker does the work
                          posts reply via send_message.py
                          appends transcript via cli.py
                          (optional) requests approval
                                  |
                                  v
                          request_approval.py posts draft
                          with Approve/Reject buttons
                                  |
   +------------------------------+-----------------------+
   | Discord gateway client (persistent WebSocket)        |
   |   - INTERACTION_CREATE -> router.py                  |
   |   - router.py auth-checks user, runs responder       |
   |   - responder writes approval marker to disk         |
   +------------------+-----------------+------------------+
                      |                 |
                      v                 v
              approvals/<sha>.json   marker-watcher (poll)
                                     - reads pending/<sha>.json
                                     - invokes outbound gate
                                     - writes completed/ or failed/
```

## The three daemons

There are three long-running processes besides the Claude Code listener.

### 1. Listener tmux session (`threadkeep-chat`)

A single Claude Code session running the Discord plugin. Its identity is loaded from `agent/cx-chat.md`. The listener never does work itself: it parses incoming Discord messages, runs `conversations/dispatch.py` to handle the deterministic state changes (create thread, create conversation file, append user turn), and fires an Agent subagent in the background to do the actual work.

Managed by `launchd/cx-chat-healthcheck.sh`, which runs every 5 minutes and restarts the tmux session if it died.

### 2. Gateway client (`discord-gateway/client.py`)

A persistent Discord gateway WebSocket connection. Receives every `INTERACTION_CREATE` event (button press, slash command) and pipes it to `router.py` via stdin.

Why a separate process: Discord requires that interactions ACK within 3 seconds. If the listener were responsible for ACKing buttons in addition to handling messages, a slow conversation could miss the ACK window. The gateway client is small and reliable. It reconnects on disconnect with exponential backoff and the documented resume/identify protocol.

Managed by `com.threadkeep.discord-gateway-client.plist` with `KeepAlive` on crash.

### 3. Marker watcher (`discord-gateway/marker-watcher.py`)

Polls `discord-gateway/approvals/` for marker files written by the router when the owner clicks Approve or Reject. For each approved marker with a matching pending send context, invokes the user-configured outbound script (Slack post, email send, etc.) and updates the Discord prompt message with the outcome.

Why a separate process: outbound gate scripts in production setups (Slack, email) routinely take 10 to 60 seconds because they run integrity checks and re-verification. The router cannot block for that long (Discord ACK window is 3 seconds). So the router writes a marker and returns immediately. The marker watcher picks up the marker and runs the slow path out of band.

Managed by `com.threadkeep.discord-marker-watcher.plist`. Polling interval is 2 seconds.

## Conversation model

Every conversation is a markdown file under `<workspace_root>/conversations/active/<session_id>.md`. The frontmatter holds:

```yaml
---
id: <uuid>
title: <short title>
discord_channel_id: <listen channel id>
discord_thread_id: <thread id>
claude_session_id: <uuid, same as id>
status: active | working | blocked | archived
created: 2026-05-21T17:34:02+00:00
last_message_at: 2026-05-22T18:30:15+00:00
message_count: 7
last_action_by: user | claude | system
tags: [optional, list]
---
```

The body is just an append-only transcript with `### <ts>, <speaker>` headers and freeform markdown turns.

A small `_registry.json` derived from frontmatter scans gives O(1) thread-id -> session-id lookup. If it drifts, regenerate it with `python3 conversations/cli.py regen-index`.

States:

- `active`: open conversation accepting replies
- `working`: worker is currently processing a turn
- `blocked`: worker hit something it cannot resolve; needs owner input
- `archived`: file moved to `<workspace_root>/conversations/archived/<session_id>.md`

The `gc` command auto-archives active conversations idle for N days.

## Approval marker lifecycle

The approval system is what lets a worker safely run outbound sends behind an owner-tap gate.

1. Worker runs outbound consistency checks on its draft, computes `full_sha = sha256(draft)`, takes the first 12+ chars as `sha_prefix`.
2. Worker writes a "pending" context file at `discord-gateway/pending/<sha_prefix>.json` describing the planned send (operation, target, channel ids, approver user id).
3. Worker calls `python3 approval/request_approval.py --channel-id <thread_id> --draft-file <path> --draft-sha <full_sha> --action "<operation>" --target "<target>"`.
4. `request_approval.py` posts the draft to Discord with native Approve and Reject buttons attached. Each button's `custom_id` is `approve:<sha_prefix>` or `reject:<sha_prefix>`.
5. The owner taps Approve. Discord delivers `INTERACTION_CREATE` to the gateway client.
6. The gateway client invokes `router.py`. Router auth-checks the user (must equal `config.discord.owner_user_id`), then invokes `request_approval_responder.py`.
7. The responder writes `discord-gateway/approvals/<sha_prefix>.json` with `status: approved`.
8. The router ACKs the interaction with a Discord type 7 `UPDATE_MESSAGE` callback that replaces the draft message body with an `[APPROVED <ts>]` prefix and clears the buttons. This is a single round-trip and avoids the "this interaction failed" client overlay that appears with the older type 6 + separate PATCH pattern.
9. The worker's `request_approval.py` was polling for the marker. It sees `status: approved` and returns an approval reference (channel_id:message_id) to the worker.
10. The worker uses the approval reference to invoke its outbound gate script with `--discord-approval-message-id`. The gate script re-verifies the reference against Discord and runs the send.
11. (Optional) The marker watcher daemon, if configured with `THREADKEEP_SLACK_GATE` or `THREADKEEP_EMAIL_GATE`, can invoke the gate script automatically out of band. This is for sends where the worker would otherwise time out.

If the owner taps Reject instead, the marker carries `status: rejected`, `request_approval.py` returns exit code 2, the marker watcher (if running) cleans up the pending file, and the message is rewritten with `[REJECTED <ts>]`.

## Why a separate marker file at all

A simpler design would have the worker poll Discord directly for a reaction or a typed confirmation message. We do that as a fallback (`--watch-mode typed`), but the marker file is the primary path because:

1. It is faster (sub-second poll vs Discord rate-limited message fetch).
2. It is auditable (every approve/reject leaves a JSON record on disk).
3. It survives Discord outages between approve and send.
4. It cleanly separates the synchronous Discord ACK (must be under 3 seconds) from the asynchronous outbound work (can take minutes).

## File and directory layout

```
threadkeep/
  agent/
    cx-chat.md                 listener identity
  approval/
    create_thread.py           creates a thread off a parent message
    react.py                   adds an emoji reaction
    request_approval.py        posts draft with buttons, waits for marker
    request_approval_responder.py  writes marker file (invoked by router)
    send_message.py            generic send-a-message helper
  conversations/
    cli.py                     conversation CRUD CLI
    config.py                  config loader (config.toml + env vars)
    dispatch.py                deterministic state setup per inbound msg
    lib.py                     conversation .md + registry library
  discord-gateway/
    client.py                  persistent WebSocket -> dispatches to router
    router.py                  one-shot router; auth, dispatch, ACK
    marker-watcher.py          polls approvals/, runs outbound gate
    tests/                     unittest mocks for the three above
    approvals/                 written by responder, read by request_approval + marker-watcher
    pending/                   written by worker, read by marker-watcher
    completed/                 marker-watcher success records
    failed/                    marker-watcher failure records
    processed-markers/         archived approval markers post-processing
    logs/                      rotating per-daemon log files
  hooks/
    discord-file-gate.sh       PreToolUse hook gating discord plugin file uploads
    outbound-send-gate-hook.sh PreToolUse hook gating Bash calls to outbound scripts
  launchd/
    cx-chat-healthcheck.sh     tmux session healthcheck (sourced by plist)
    templates/                 .plist.template files with placeholders
  systemd/
    templates/                 .service.template files for Linux
  cx-launcher.sh               launcher used by tmux to start Claude Code
  config.example.toml          documented config template
  install.sh                   macOS install script
  uninstall.sh                 reverses install.sh
  requirements.txt             one line: websockets>=12.0
  .env.example                 documented env var template
```
