# Threadkeep

Persistent Discord conversation orchestrator for Claude Code.

A single Claude Code session listens to one Discord channel, creates a durable markdown record of every conversation, and dispatches the actual work to background subagents. The listener stays responsive while threads run in parallel.

## Install

```
git clone https://github.com/vp58/threadkeep.git ~/.threadkeep
cd ~/.threadkeep
python3 -m pip install -r requirements.txt
bash install.sh
```

The installer is interactive. It will prompt you for your Discord listen channel id, errors channel id, owner user id, timezone, and bot token, then store the token in the macOS Keychain, render the launchd plists, and start the listener tmux session. Full walkthrough in `docs/SETUP.md`.

Uninstall with `bash uninstall.sh`.

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
- Idempotent installer with first-class uninstall.

## Status

Pre-release. The original private deployment has been running unattended since 2026-05-21 handling parallel conversations end to end. The public install path (install.sh, uninstall.sh, plist templates, Keychain integration) was added on 2026-05-23 and is freshly tested but has not yet been tried by users other than the original author.

## Tested on

- macOS 26.4 (Tahoe), Python 3.14.3, websockets 16.0
- macOS 15 (Sequoia) is expected to work but is not regularly tested
- macOS 14 (Sonoma) is expected to work but is not regularly tested
- Linux: see the sketch at the bottom of `docs/SETUP.md`. The systemd templates are shipped but the install script is macOS-specific.

## Architecture

- `cx-chat-listener/CLAUDE.md` is the listener identity, auto-loaded by Claude Code because the tmux session is started with cwd set to that subdir. It is the same content as `agent/cx-chat.md` and is re-asserted after `/compact` and `/clear` (which fixes the identity-loss bug where the listener forgot its protocol after the first compaction).
- `cx-chat-listener/hooks/precompact-identity.sh` and `cx-chat-listener/hooks/userpromptsubmit-anchor.sh` are user-scoped Claude Code hooks that defend identity across compaction and per-message. See `docs/SETUP.md` step 6 for the registration block.
- `agent/cx-chat.md` is the canonical reference copy of the listener prompt (same content as the cwd CLAUDE.md). Kept for documentation and for tools that want to read the protocol without resolving discovery rules.
- `conversations/` holds the dispatch script and CLI. The dispatch script handles all deterministic state changes per inbound message.
- `discord-gateway/` is an optional but recommended companion: a persistent WebSocket client that delivers Discord button presses to a small router, which writes approval markers to disk. The marker watcher then runs out-of-band outbound work.
- `approval/` is the worker-facing API for requesting an outbound approval via Discord buttons.
- `hooks/outbound-send-gate-hook.sh` is a Claude Code PreToolUse hook that refuses outbound gate calls without a verified approval reference.
- `hooks/discord-file-gate.sh` is a Claude Code PreToolUse hook that restricts file attachments in Discord replies to an explicit allowlist of directory prefixes.
- `launchd/templates/*.plist.template` are rendered by install.sh with `__REPO_ROOT__`, `__HOME__`, `__PYTHON_BIN__`, `__LABEL__`, and `__TMUX_SESSION__` substitutions.
- `systemd/templates/*.service.template` are the Linux equivalents.

See `docs/ARCHITECTURE.md` for the full diagram and the conversation + approval lifecycles.

## Configuration

All configuration lives in one `config.toml` file or in environment variables prefixed with `THREADKEEP_`. The repo never reads secrets from the filesystem outside of optional token files you explicitly point at. See `.env.example` for the full set of options.

The bot token is stored separately in the macOS Keychain (service `threadkeep-secret`, account `discord-bot-token`) and never lands on disk in plaintext.

## Run from source (developers)

```
git clone https://github.com/vp58/threadkeep.git
cd threadkeep
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s discord-gateway/tests -t discord-gateway -v
```

To run the daemons by hand without launchd:

```
export DISCORD_BOT_TOKEN=...
cp config.example.toml config.toml
# edit config.toml with your channel ids
python3 discord-gateway/client.py &
python3 discord-gateway/marker-watcher.py &
bash cx-launcher.sh   # opens Claude Code with Discord plugin in foreground
```

## Security

- Inbound Discord messages are untrusted input. The worker prompt treats them as such.
- The listener filters by channel ownership before dispatching. Messages in channels Threadkeep does not own are ignored.
- The router refuses interactions from any user other than the configured owner.
- Outbound sends require explicit owner approval via Discord buttons or a typed sha confirmation.
- The default install does not enable `--dangerously-skip-permissions` for the worker. Permission prompts will surface in your Claude Code UI.

See `docs/SECURITY.md` for the full trust model and disclosure flow.

## License

MIT. See `LICENSE`.

## Acknowledgments

This is a public extraction of a private orchestrator pattern that proved itself in production handling parallel conversations end to end. The original codename `cx-chat` is preserved in the listener identity file.
