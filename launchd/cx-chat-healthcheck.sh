#!/usr/bin/env bash
# cx-chat-healthcheck.sh
#
# Checks if the Disco Party listener tmux session is alive. If not, restarts
# it by launching cx-launcher.sh (which resolves the bot token from Keychain
# and execs Claude Code with the Discord plugin attached), then sends the
# bootstrap prompt that loads the cx-chat identity. Posts a notification to
# the configured errors channel on action.
#
# Runs under launchd via com.discoparty.cx-chat-healthcheck.plist or directly
# from cron.

set -u

REPO_ROOT="${DISCOPARTY_REPO_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
CONFIG="${DISCOPARTY_CONFIG:-$REPO_ROOT/config.toml}"
SESSION="${DISCOPARTY_TMUX_SESSION:-discoparty-chat}"
SEND="$REPO_ROOT/approval/send_message.py"
LAUNCHER="$REPO_ROOT/cx-launcher.sh"
PERMISSION_VERIFIER="$REPO_ROOT/conversations/discord_permissions.py"
READINESS_TOKEN="DISCOPARTY_LISTENER_READY_v1_7f29c4b1"
CLAUDE_BIN="$HOME/.local/share/claude/versions/2.1.251"

PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
export DISCOPARTY_CONFIG="$CONFIG"
export DISCOPARTY_REPO_ROOT="$REPO_ROOT"

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

permission_fault_marker() {
  printf '%s/state/claude-discord-permission-fault' "$WORKSPACE_ROOT"
}

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

stop_cx_chat() {
  if ! tmux has-session -t "=$SESSION" 2>/dev/null; then
    return 0
  fi
  local current_pgid pane_count=0 pane_pid pane_command pane_cwd pgid process_command
  local -a groups=()
  current_pgid="$(/bin/ps -o pgid= -p "$$" 2>/dev/null | tr -d ' ')"
  if [[ ! "$current_pgid" =~ ^[0-9]+$ ]] || [ "$current_pgid" -le 1 ]; then
    log "ERROR: refusing to stop $SESSION because healthcheck PGID is malformed"
    return 1
  fi
  while IFS=$'\t' read -r pane_pid pane_command pane_cwd; do
    pane_count=$((pane_count + 1))
    if [[ ! "$pane_pid" =~ ^[0-9]+$ ]] || \
      [ "$pane_command" != "$LAUNCHER" ] || \
      [ "$pane_cwd" != "$REPO_ROOT/cx-chat-listener" ]; then
      log "ERROR: refusing to stop $SESSION because pane identity is not exact"
      return 1
    fi
    process_command="$(/bin/ps -o command= -p "$pane_pid" 2>/dev/null || true)"
    case "$process_command" in
      "$LAUNCHER"|"$LAUNCHER "*|"$CLAUDE_BIN"|"$CLAUDE_BIN "*) ;;
      *)
        log "ERROR: refusing to stop $SESSION because its process is not the reviewed launcher or Claude"
        return 1
        ;;
    esac
    pgid="$(/bin/ps -o pgid= -p "$pane_pid" 2>/dev/null | tr -d ' ' || true)"
    if [[ ! "$pgid" =~ ^[0-9]+$ ]] || [ "$pgid" -le 1 ] || \
      [ "$pgid" = "$current_pgid" ]; then
      log "ERROR: refusing to stop $SESSION because its process group is unsafe"
      return 1
    fi
    case " ${groups[*]} " in
      *" $pgid "*) ;;
      *) groups+=("$pgid") ;;
    esac
  done < <(tmux list-panes -t "=$SESSION" \
    -F '#{pane_pid}\t#{pane_start_command}\t#{pane_current_path}' 2>/dev/null)
  if [ "$pane_count" -ne 1 ] || [ "${#groups[@]}" -ne 1 ]; then
    log "ERROR: refusing to stop $SESSION because its pane layout is unexpected"
    return 1
  fi
  for pgid in "${groups[@]}"; do
    /bin/kill -TERM "-$pgid" 2>/dev/null || true
  done
  sleep 1
  for pgid in "${groups[@]}"; do
    if /bin/kill -0 "-$pgid" 2>/dev/null; then
      /bin/kill -KILL "-$pgid" 2>/dev/null || true
    fi
  done
  tmux kill-session -t "=$SESSION" 2>/dev/null || true
  log "Stopped exact $SESSION listener process group and tmux session"
}

listener_session_is_exact() {
  local pane_count=0 pane_pid pane_command pane_cwd process_command
  tmux has-session -t "=$SESSION" 2>/dev/null || return 1
  while IFS=$'\t' read -r pane_pid pane_command pane_cwd; do
    pane_count=$((pane_count + 1))
    [[ "$pane_pid" =~ ^[0-9]+$ ]] || return 1
    [ "$pane_command" = "$LAUNCHER" ] || return 1
    [ "$pane_cwd" = "$REPO_ROOT/cx-chat-listener" ] || return 1
    process_command="$(/bin/ps -o command= -p "$pane_pid" 2>/dev/null || true)"
    case "$process_command" in
      "$LAUNCHER"|"$LAUNCHER "*|"$CLAUDE_BIN"|"$CLAUDE_BIN "*) ;;
      *) return 1 ;;
    esac
  done < <(tmux list-panes -t "=$SESSION" \
    -F '#{pane_pid}\t#{pane_start_command}\t#{pane_current_path}' 2>/dev/null)
  [ "$pane_count" -eq 1 ]
}

listener_protocol_is_ready() {
  listener_session_is_exact || return 1
  tmux capture-pane -p -t "=$SESSION:0.0" -S -2000 2>/dev/null | \
    grep -Fq "$READINESS_TOKEN"
}

verify_discord_permissions() {
  if [ ! -f "$PERMISSION_VERIFIER" ]; then
    log "ERROR: Discord permission verifier is missing"
    return 1
  fi
  /usr/bin/env -i \
    HOME="$HOME" \
    USER="$(/usr/bin/id -un)" \
    LOGNAME="$(/usr/bin/id -un)" \
    PATH="$PATH" \
    LANG="C" \
    DISCOPARTY_CONFIG="$CONFIG" \
    PYTHONPATH="$REPO_ROOT/conversations" \
    python3 "$PERMISSION_VERIFIER" verify \
    >>"$LOG" 2>&1
}

enforce_discord_permissions() {
  local marker marker_dir temporary first_fault=0 stop_failed=0
  marker="$(permission_fault_marker)"
  marker_dir="$(dirname "$marker")"
  if verify_discord_permissions; then
    if [ -f "$marker" ]; then
      rm -f "$marker"
      log "Discord permission verification recovered"
      post_alert "Disco Party Discord least-privilege verification recovered on $(hostname) at $(ts)."
    fi
    return 0
  fi

  stop_cx_chat || stop_failed=1
  if [ ! -e "$marker" ]; then
    first_fault=1
    umask 077
    mkdir -p "$marker_dir"
    chmod 700 "$marker_dir" 2>/dev/null || true
    temporary="$marker.tmp.$$"
    printf '%s\n' "$(ts)" > "$temporary"
    chmod 600 "$temporary"
    mv -f "$temporary" "$marker"
  fi
  if [ "$stop_failed" = "1" ]; then
    log "CRITICAL: Discord verification failed and the existing tmux session was not safe to stop automatically"
  else
    log "ERROR: Discord least-privilege verification failed; listener remains stopped"
  fi
  if [ "$first_fault" = "1" ]; then
    if [ "$stop_failed" = "1" ]; then
      post_alert "Disco Party Discord permission verification failed on $(hostname) at $(ts), but the existing $SESSION session did not match the reviewed process identity and was not killed. Manual intervention is required."
    else
      post_alert "Disco Party stopped $SESSION on $(hostname) at $(ts) because Discord least-privilege verification failed. It will remain stopped until verification passes."
    fi
  fi
  return 1
}

start_cx_chat() {
  # The launcher passes the digest-pinned contract explicitly as a system
  # prompt. Keep cwd exact as a second identity binding.
  local listener_cwd="$REPO_ROOT/cx-chat-listener"
  local cwd="$listener_cwd"
  [ -d "$listener_cwd" ] || {
    log "ERROR: listener cwd is missing at $listener_cwd"
    return 1
  }

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

  local prompt="Run the Disco Party readiness check defined in your pinned system prompt. Reply only with its exact token."
  tmux send-keys -t "=$SESSION:0.0" "$prompt" Enter
  sleep 2
  tmux send-keys -t "=$SESSION:0.0" Enter
  local attempt=0
  while [ "$attempt" -lt 30 ]; do
    if listener_protocol_is_ready; then
      log "Pinned listener protocol readiness confirmed"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  log "ERROR: pinned listener protocol readiness token was not observed"
  stop_cx_chat || true
  return 1
}

main() {
  if ! enforce_discord_permissions; then
    exit 1
  fi

  if tmux has-session -t "=$SESSION" 2>/dev/null; then
    if listener_protocol_is_ready; then
      exit 0
    fi
    log "$SESSION exists but exact listener readiness is not proven"
    stop_cx_chat || exit 1
  fi

  log "$SESSION session missing. Restarting."

  if start_cx_chat; then
    sleep 5
    if listener_protocol_is_ready; then
      log "Restart successful"
      post_alert "Disco Party $SESSION tmux session was missing on $(hostname); restarted automatically at $(ts)."
    else
      log "Restart claimed success but session is not present. Manual intervention needed."
      post_alert "Disco Party $SESSION restart FAILED on $(hostname) at $(ts). Manual fix required."
    fi
  else
    log "start_cx_chat returned non-zero"
    post_alert "Disco Party $SESSION restart attempt failed on $(hostname) at $(ts). Check healthcheck log."
  fi
}

main "$@"
