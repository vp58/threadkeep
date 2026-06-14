# Threadkeep setup guide

End-to-end install for a fresh machine. Tested on macOS 14, 15, and 26 (Sonoma, Sequoia, Tahoe). Linux setup is sketched at the bottom.

## What you need before you start

- A Discord server you own (or have admin on)
- A Discord application + bot you control, with the bot token in hand
- Two channel ids: one for the listener to read, one for error notifications (can be the same channel)
- Your own Discord user id (for the owner approval check)
- Claude Code CLI installed and signed into a subscription plan, with the Discord plugin available
- macOS Keychain access (you will see a Keychain prompt the first time the launcher runs)

The bot must be invited to the server with these scopes: `bot`, `applications.commands`. Required permissions: Read Messages, Send Messages, Create Public Threads, Manage Threads, Add Reactions.

## 1. Create a Discord bot

If you already have a bot token, skip to step 2.

1. Open https://discord.com/developers/applications.
2. Create a new application named `Threadkeep`.
3. Open the Bot tab and create a bot user.
4. Copy the bot token. Treat it like a password. The installer stores it in macOS Keychain.
5. Open OAuth2 > URL Generator.
6. Select scopes `bot` and `applications.commands`.
7. Select bot permissions: Read Messages, Send Messages, Create Public Threads, Manage Threads, Add Reactions.
8. Open the generated URL and invite the bot to your server.
9. In Discord, enable Developer Mode, then copy your listen channel id, errors channel id, and your own user id.

The bot does not need administrator permission.

## 2. Clone the repo and install Python deps

```
git clone https://github.com/vp58/threadkeep.git ~/.threadkeep
cd ~/.threadkeep
python3 -m pip install -r requirements.txt
```

Python 3.11 or newer is required. Threadkeep uses the stdlib `tomllib` module.

## 3. Run the installer

```
bash install.sh
```

The installer is interactive. It will:

1. Check your prerequisites (python3, websockets, tmux, curl, jq).
2. Ask for the repo root (defaults to the directory the script lives in).
3. Ask for the workspace root (where conversation transcripts live, defaults to `~/.threadkeep`).
4. Ask for your Discord listen channel id, errors channel id, owner user id, and timezone.
5. Ask for your Discord bot token (or reuse an existing macOS Keychain entry).
6. Store the token in macOS Keychain under service `threadkeep-secret`, account `discord-bot-token`.
7. Write `config.toml`.
8. Render and install three launchd plists under `~/Library/LaunchAgents/`:
   - `com.threadkeep.cx-chat-healthcheck.plist` (runs every 5 minutes, restarts the listener tmux session if it died)
   - `com.threadkeep.discord-gateway-client.plist` (persistent WebSocket client for button presses)
   - `com.threadkeep.discord-marker-watcher.plist` (polls for approval markers and runs outbound gates)
9. Bootstrap the agents with `launchctl bootstrap`.
10. Start the listener tmux session via `cx-launcher.sh`.

## 4. Verify

The healthcheck started a tmux session named `threadkeep-chat`. Attach to it:

```
tmux attach -t threadkeep-chat
```

You should see Claude Code running with the Discord plugin attached, having just received the bootstrap prompt that told it to load `agent/cx-chat.md`. Detach with `Ctrl-b d`.

Check the gateway client is running:

```
launchctl print gui/$UID/com.threadkeep.discord-gateway-client | head -20
tail -f ~/.threadkeep/discord-gateway/logs/client.log
```

You should see a `READY` log line and periodic heartbeat acks.

Send a test message in the listen channel. The listener should:

1. React with `:eyes:` on your message.
2. Create a thread off the message with a generated title.
3. Spawn a worker subagent that replies inside the thread.

If anything is off, see the troubleshooting section below.

## 5. Configuration files at a glance

- `config.toml`: paths, channel ids, owner user id, runtime knobs (timezone, rate limits).
- `~/Library/LaunchAgents/com.threadkeep.*.plist`: the rendered plists. Edit these only if you know what you are doing. The originals are in `launchd/templates/`.
- `~/.threadkeep/conversations/`: source of truth for every conversation, stored as markdown.
- `~/.threadkeep/discord-gateway/logs/`: client.log, router.log, marker-watcher.log. Tail these when debugging.

## 6. Optional: outbound send gates

If your worker needs to send Slack messages or emails on your behalf, see `docs/ARCHITECTURE.md` for the marker watcher protocol. You write a small adapter script that accepts `--pending-json`, calls your provider, and prints JSON. Set the path via `THREADKEEP_SLACK_GATE` or `THREADKEEP_EMAIL_GATE` and the marker watcher will route approved sends through it. See `examples/slack_gate.py` for the minimal adapter shape.

## 7. Identity persistence across /compact

The listener loads its protocol from `cx-chat-listener/CLAUDE.md`. The tmux session is started with cwd set to that subdir so Claude Code auto-loads the file on init and re-asserts it after `/compact` and `/clear`. Without this, the listener loses its agent identity after the first compaction and starts replying inline to top-level posts instead of running dispatch.py and spawning a worker.

Three layers protect identity:

1. **Primary: `cx-chat-listener/CLAUDE.md`.** Claude Code walks UP from cwd and loads every `CLAUDE.md` it finds. Place the listener identity in the cwd, place any host-specific rules in a parent dir (e.g. your home `CLAUDE.md`). Both load. The cwd file is re-asserted after `/compact` and `/clear`.

2. **Secondary: PreCompact hook** (`cx-chat-listener/hooks/precompact-identity.sh`). Fires right before `/compact` runs and emits the identity file verbatim via `hookSpecificOutput.additionalContext`, which Claude Code injects into the compaction summary. Guarantees the protocol survives even if the cwd CLAUDE.md mechanism is bypassed.

3. **Tertiary: UserPromptSubmit hook** (`cx-chat-listener/hooks/userpromptsubmit-anchor.sh`). Fires on every user prompt and injects a one-line reminder ("you are cx-chat, top-level posts go through dispatch.py, never reply inline"). Cheap per-message belt-and-suspenders.

Both hooks gate on cwd so they only run for the listener session. Other Claude Code sessions you run from elsewhere on the same machine are unaffected.

To register the hooks, add this to your user-scoped `~/.claude/settings.local.json` (merge with any existing `hooks` block):

```json
{
  "hooks": {
    "PreCompact": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "<absolute-path-to-repo>/cx-chat-listener/hooks/precompact-identity.sh"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "<absolute-path-to-repo>/cx-chat-listener/hooks/userpromptsubmit-anchor.sh"
          }
        ]
      }
    ]
  }
}
```

Replace `<absolute-path-to-repo>` with the value of `$THREADKEEP_REPO_ROOT` you set during install.

Hooks are user-scoped (in `~/.claude/settings.local.json`), not repo-scoped, because Claude Code requires hook commands to live at the user level for trust. The hooks themselves live in the repo so they ship with the code.

## 8. Uninstall

```
bash uninstall.sh
```

This unloads and removes the launchd plists, kills the tmux session, removes the Keychain entry, and optionally archives the conversations dir.

## Troubleshooting

### Keychain prompt every time

The first time `cx-launcher.sh` (or any process that reads the Keychain entry) runs from a new context, macOS may prompt for permission. Click "Always Allow" once and the prompt should not return.

### Gateway client crashing

Check `discord-gateway/logs/launchd.stderr.log`. The most common cause is a bad token. Re-run `install.sh --reinstall` to refresh the Keychain entry.

### Listener not picking up messages

Make sure the listener tmux session has Claude Code running with the Discord plugin attached. From the session, you should be able to send a message and see it logged. If not:

1. Check that `cx-launcher.sh` is executable.
2. Check that `claude` is on the launcher's PATH (the plist sets PATH to `/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`).
3. Check the Discord plugin is configured (`claude --channels plugin:discord@claude-plugins-official` should work standalone).

### Button presses do nothing

The gateway client is the persistent WebSocket. Check `discord-gateway/logs/client.log` for `INTERACTION_CREATE` events and router invocations. If the gateway is up but interactions are not dispatching, your bot may be missing the `applications.commands` scope. Re-invite the bot with the correct scopes.

### Test the test suite

```
python3 -m unittest discover -s discord-gateway/tests -t discord-gateway -v
```

All 16 tests should pass.

## Linux setup (sketch)

Threadkeep should run on Linux but the install script is macOS-specific. Manual steps:

1. Install Python 3.11+, `websockets`, `tmux`, `curl`, `jq`.
2. Copy `config.example.toml` to `config.toml` and fill in your values.
3. Set `DISCORD_BOT_TOKEN` in your shell or via a secret manager.
4. Render the systemd templates from `systemd/templates/` with your repo root and python path, then `systemctl --user enable --now threadkeep-gateway-client threadkeep-marker-watcher`.
5. Start the listener tmux session manually via `bash cx-launcher.sh`.

Linux install scripting is a stretch goal. PRs welcome.
