# Threadkeep

Persistent Discord conversation orchestrator for Claude Code.

A single Claude Code session listens to one Discord channel, creates a durable markdown record of every conversation, and dispatches the actual work to background subagents. The listener stays responsive while threads run in parallel.

## What it does

1. You post a message in your configured Discord channel.
2. Threadkeep creates a Discord thread off the message and a markdown conversation file on disk.
3. A worker subagent is spawned via the Claude Code Agent tool. It does the actual work and replies in the thread.
4. You reply in the thread. The worker spawns again with the full prior context loaded.
5. The conversation file is the source of truth. A small JSON registry maps Discord thread ids to session ids.

The listener never does work itself. It sets up state and fires the subagent. This is what lets it handle many parallel conversations without stalling.

## Why this exists

The Claude Code Discord plugin gives you a great single-channel interface but the session does everything inline. If a conversation takes 5 minutes the listener is dead to other inbound messages for those 5 minutes. Threadkeep solves that by separating listening from working. Each conversation gets a thread, a transcript file, and its own subagent.

## Features

- Top-level message creates a thread, then dispatches the work.
- Thread replies are routed to the right conversation by id.
- All conversations stored as markdown with YAML frontmatter. Easy to grep, easy to back up.
- Channel-ownership filter. The bot only acts on messages in the configured listen channel or in threads it created.
- Native Discord Approve and Reject buttons for outbound sends. The optional gateway client and marker watcher daemon let workers gate outbound email and Slack sends behind a Discord tap.
- launchd templates for macOS, systemd templates for Linux.

## Status

Pre-release. Code has been running unattended on a single user's setup since 2026-05-21 handling parallel conversations end to end. The parameterization and public install path is new and has not yet been tested by anyone except the original author.

## Quick start

Full setup is in `docs/SETUP.md`. The short version:

1. Clone this repo.
2. Copy `.env.example` to `config.toml` and fill in your Discord listen channel id, errors channel id, owner user id, and timezone.
3. Set the `DISCORD_BOT_TOKEN` environment variable to your bot token, or set `discord.token_file` in `config.toml`.
4. Install dependencies: `python3 -m pip install -r requirements.txt`
5. On macOS: `bash install.sh` to install the launchd agents.
6. On Linux: copy the unit files from `systemd/templates/` to `~/.config/systemd/user/` and run `systemctl --user enable --now`.
7. Start your Claude Code session with the Discord plugin attached. The listener will pick up new messages.

## Architecture

- `agent/cx-chat.md` is the listener prompt. Drop it into your Claude Code session as the identity for the listening process.
- `conversations/` holds the dispatch script and CLI. The dispatch script handles all deterministic state changes per inbound message.
- `discord-gateway/` is an optional but recommended companion: a persistent WebSocket client that delivers Discord button presses to a small router, which writes approval markers to disk.
- `approval/` is the worker-facing API for requesting an outbound approval via Discord buttons.
- `hooks/outbound-send-gate-hook.sh` is a Claude Code PreToolUse hook that refuses outbound gate calls without a verified approval reference.
- `launchd/` and `systemd/` ship templates for keeping all of this running unattended.

See `docs/ARCHITECTURE.md` for the full diagram.

## Configuration

All configuration lives in one `config.toml` file or in environment variables prefixed with `THREADKEEP_`. The repo never reads secrets from the filesystem outside of optional token files you explicitly point at. See `.env.example` for the full set of options.

## Security

- Inbound Discord messages are untrusted input. The worker prompt treats them as such.
- The listener filters by channel ownership before dispatching. Messages in channels Threadkeep does not own are ignored.
- Outbound sends require explicit owner approval via Discord buttons or a typed sha confirmation.
- The default install does not enable `--dangerously-skip-permissions` for the worker. Permission prompts will surface in your Claude Code UI.

See `docs/SECURITY.md` for the threat model and disclosure policy.

## License

MIT. See `LICENSE`.

## Acknowledgments

This is a public extraction of a private orchestrator pattern that proved itself in production handling parallel conversations end to end. The original codename `cx-chat` is preserved in the listener identity file.
