#!/bin/bash
# cx-chat-healthcheck.sh
#
# Checks if the cx-chat tmux session is alive. If not, restarts it with the
# Claude Code Discord plugin attached, then sends the bootstrap prompt that
# loads the cx-chat identity. Posts a notification to the configured errors
# channel on action.
#
# Runs under launchd via com.disclawd.cx-chat-healthcheck.plist.

set -u

REPO_ROOT="${DISCLAWD_REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
CONFIG="${DISCLAWD_CONFIG:-$REPO_ROOT/config.toml}"
SESSION="cx-chat"
SEND="$REPO_ROOT/approval/send_message.py"

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
export DISCLAWD_CONFIG="$CONFIG"

eval "$(
PYTHONPATH="$REPO_ROOT/conversations" python3 - <<'PY'
import shlex
from config import CONFIG

values = {
    "WORKSPACE_ROOT": str(CONFIG.paths.workspace_root),
    "LOG": str(CONFIG.paths.log_file or (CONFIG.paths.workspace_root / "cx-chat-healthcheck.log")),
    "ERRORS_CHANNEL": CONFIG.discord.errors_channel_id,
    "CHAT_CHANNEL": CONFIG.discord.chat_channel_id,
    "USE_SKIP_PERMISSIONS": "1" if CONFIG.runtime.use_dangerously_skip_permissions else "0",
}
for key, value in values.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"

ts() { date "+%Y-%m-%d %H:%M:%S %Z"; }

log() { echo "[$(ts)] $*" >> "$LOG"; }

post_alert() {
  local msg="$1"
  python3 "$SEND" \
    --channel-id "$ERRORS_CHANNEL" \
    --message "$msg" \
    --mention-owner \
    >> "$LOG" 2>&1 || true
}

start_cx_chat() {
  log "Starting cx-chat tmux session"
  tmux new-session -d -s "$SESSION" -c "$WORKSPACE_ROOT" 2>>"$LOG"
  if [ $? -ne 0 ]; then
    log "ERROR: tmux new-session failed"
    return 1
  fi

  local claude_cmd="claude --channels plugin:discord@claude-plugins-official"
  if [ "$USE_SKIP_PERMISSIONS" = "1" ]; then
    claude_cmd="claude --dangerously-skip-permissions --channels plugin:discord@claude-plugins-official"
  fi
  tmux send-keys -t "$SESSION" "$claude_cmd" Enter
  log "claude command sent; sleeping 15s for init"
  sleep 15

  local prompt="You are cx-chat. Read your full protocol at $REPO_ROOT/agent/cx-chat.md right now and follow it for every inbound Discord message in channel $CHAT_CHANNEL. Confirm in one line you have the protocol, then listen."
  tmux send-keys -t "$SESSION" "$prompt" Enter
  sleep 2
  tmux send-keys -t "$SESSION" Enter
  log "Bootstrap prompt sent; cx-chat should be loading identity"
  return 0
}

main() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    exit 0
  fi

  log "cx-chat session missing. Restarting."

  if start_cx_chat; then
    sleep 5
    if tmux has-session -t "$SESSION" 2>/dev/null; then
      log "Restart successful"
      post_alert "cx-chat tmux session was missing on $(hostname); restarted automatically at $(ts)."
    else
      log "Restart claimed success but session is not present. Manual intervention needed."
      post_alert "cx-chat restart FAILED on $(hostname) at $(ts). Manual fix required."
    fi
  else
    log "start_cx_chat returned non-zero"
    post_alert "cx-chat restart attempt failed on $(hostname) at $(ts). Check healthcheck log."
  fi
}

main "$@"
