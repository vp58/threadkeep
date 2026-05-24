#!/usr/bin/env bash
# cx-chat-healthcheck.sh
#
# Checks if the Threadkeep listener tmux session is alive. If not, restarts
# it by launching cx-launcher.sh (which resolves the bot token from Keychain
# and execs Claude Code with the Discord plugin attached), then sends the
# bootstrap prompt that loads the cx-chat identity. Posts a notification to
# the configured errors channel on action.
#
# Runs under launchd via com.threadkeep.cx-chat-healthcheck.plist or directly
# from cron.

set -u

REPO_ROOT="${THREADKEEP_REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
CONFIG="${THREADKEEP_CONFIG:-$REPO_ROOT/config.toml}"
SESSION="${THREADKEEP_TMUX_SESSION:-threadkeep-chat}"
SEND="$REPO_ROOT/approval/send_message.py"
LAUNCHER="$REPO_ROOT/cx-launcher.sh"

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
export THREADKEEP_CONFIG="$CONFIG"
export THREADKEEP_REPO_ROOT="$REPO_ROOT"

eval "$(
PYTHONPATH="$REPO_ROOT/conversations" python3 - <<'PY'
import shlex
from config import CONFIG

values = {
    "WORKSPACE_ROOT": str(CONFIG.paths.workspace_root),
    "LOG": str(CONFIG.paths.log_file or (CONFIG.paths.workspace_root / "cx-chat-healthcheck.log")),
    "ERRORS_CHANNEL": CONFIG.discord.errors_channel_id,
    "CHAT_CHANNEL": CONFIG.discord.chat_channel_id,
}
for key, value in values.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"

mkdir -p "$(dirname "$LOG")" 2>/dev/null || true

ts() { date "+%Y-%m-%d %H:%M:%S %Z"; }

log() { echo "[$(ts)] $*" >> "$LOG"; }

post_alert() {
  local msg="$1"
  if [ -z "${ERRORS_CHANNEL:-}" ]; then
    return 0
  fi
  python3 "$SEND" \
    --channel-id "$ERRORS_CHANNEL" \
    --message "$msg" \
    --mention-owner \
    >> "$LOG" 2>&1 || true
}

start_cx_chat() {
  # Launch tmux with cwd set to the cx-chat-listener subdir so Claude Code
  # auto-loads cx-chat-listener/CLAUDE.md on init AND re-asserts it after
  # /compact and /clear. Any CLAUDE.md in parent dirs is still loaded via
  # parent-walk discovery. If the subdir is missing (older install), fall
  # back to the repo root so the launch still succeeds.
  local listener_cwd="$REPO_ROOT/cx-chat-listener"
  local cwd
  if [ -d "$listener_cwd" ]; then
    cwd="$listener_cwd"
  else
    cwd="$REPO_ROOT"
    log "WARN: $listener_cwd missing, falling back to repo root cwd"
  fi

  log "Starting $SESSION tmux session via $LAUNCHER (cwd=$cwd)"
  if [ ! -x "$LAUNCHER" ]; then
    log "ERROR: launcher not executable at $LAUNCHER"
    return 1
  fi
  tmux new-session -d -s "$SESSION" -c "$cwd" "$LAUNCHER" 2>>"$LOG"
  if [ $? -ne 0 ]; then
    log "ERROR: tmux new-session failed"
    return 1
  fi
  log "tmux session started; sleeping 15s for Claude Code init"
  sleep 15

  # Belt-and-suspenders bootstrap prompt. The cwd CLAUDE.md is the primary
  # identity mechanism, but this also re-asserts the protocol immediately
  # in case the user has Claude Code starting in a mode that skips
  # auto-loading on first turn.
  local prompt="You are the Threadkeep cx-chat listener. Your identity is in $cwd/CLAUDE.md (auto-loaded). Follow it for every inbound Discord message in channel $CHAT_CHANNEL. Confirm in one line you have the protocol, then listen."
  tmux send-keys -t "$SESSION" "$prompt" Enter
  sleep 2
  tmux send-keys -t "$SESSION" Enter
  log "Bootstrap prompt sent; listener should be loading identity"
  return 0
}

main() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    exit 0
  fi

  log "$SESSION session missing. Restarting."

  if start_cx_chat; then
    sleep 5
    if tmux has-session -t "$SESSION" 2>/dev/null; then
      log "Restart successful"
      post_alert "Threadkeep $SESSION tmux session was missing on $(hostname); restarted automatically at $(ts)."
    else
      log "Restart claimed success but session is not present. Manual intervention needed."
      post_alert "Threadkeep $SESSION restart FAILED on $(hostname) at $(ts). Manual fix required."
    fi
  else
    log "start_cx_chat returned non-zero"
    post_alert "Threadkeep $SESSION restart attempt failed on $(hostname) at $(ts). Check healthcheck log."
  fi
}

main "$@"
