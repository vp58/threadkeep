#!/usr/bin/env bash
# uninstall.sh
#
# Reverses install.sh. Stops the tmux listener, unloads launchd agents,
# removes the rendered plists, and optionally deletes the Keychain entry
# and archives the conversations dir.
#
# Flags:
#   --codex               Remove only the Codex Discord provider. Claude
#                         services, token, config, and conversations stay.
#   --label-prefix PREFIX  Match the install prefix. Default: "com.threadkeep".
#   --tmux-session NAME    tmux session to kill. Default: "threadkeep-chat".
#   --keep-keychain        Skip Keychain entry deletion.
#   --keep-chatgpt-login   Keep the ChatGPT login scoped to the isolated
#                          Threadkeep CODEX_HOME. Default: securely log out.
#   --keep-conversations   Skip the prompt about archiving conversations dir.
#   --non-interactive      Don't prompt. Implies --keep-conversations unless
#                          --archive-conversations is also set.
#   --archive-conversations
#                          Move the conversations dir to a timestamped sibling.
#   -h, --help             Show this help.

set -euo pipefail

# A caller-supplied credential must not reach even uninstaller setup children.
unset DISCORD_BOT_TOKEN THREADKEEP_CODEX_DISCORD_BOT_TOKEN OPENAI_API_KEY || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SECURITY_BIN="/usr/bin/security"
LAUNCHCTL_BIN="/bin/launchctl"
if [ "${THREADKEEP_TEST_MODE:-0}" = "1" ]; then
  SECURITY_BIN="${THREADKEEP_TEST_SECURITY_BIN:-$SECURITY_BIN}"
  LAUNCHCTL_BIN="${THREADKEEP_TEST_LAUNCHCTL_BIN:-$LAUNCHCTL_BIN}"
  PYTHON_BIN="${THREADKEEP_TEST_PYTHON_BIN:-$(command -v python3)}"
else
  PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  export PATH
  PYTHON_BIN="$(command -v python3 || true)"
fi

LABEL_PREFIX="com.threadkeep"
TMUX_SESSION="threadkeep-chat"
TMUX_SESSION_SET=0
KEEP_KEYCHAIN=0
KEEP_CHATGPT_LOGIN=0
KEEP_CONVERSATIONS=0
NON_INTERACTIVE=0
ARCHIVE_CONVERSATIONS=0
CODEX_ONLY=0

KEYCHAIN_SERVICE="threadkeep-secret"
KEYCHAIN_ACCOUNT="discord-bot-token"

usage() {
  sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --codex) CODEX_ONLY=1; shift ;;
    --label-prefix) LABEL_PREFIX="$2"; shift 2 ;;
    --tmux-session) TMUX_SESSION="$2"; TMUX_SESSION_SET=1; shift 2 ;;
    --keep-keychain) KEEP_KEYCHAIN=1; shift ;;
    --keep-chatgpt-login) KEEP_CHATGPT_LOGIN=1; shift ;;
    --keep-conversations) KEEP_CONVERSATIONS=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --archive-conversations) ARCHIVE_CONVERSATIONS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 2 ;;
  esac
done

if [ "$CODEX_ONLY" = "1" ] && [ "$TMUX_SESSION_SET" = "0" ]; then
  TMUX_SESSION="threadkeep-codex"
fi

red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[33m%s\033[0m\n" "$*"; }
blue()  { printf "\033[34m%s\033[0m\n" "$*"; }
say()   { printf "%s\n" "$*"; }

stop_listener_session() {
  local session="$1"
  local -a groups=()
  local pane_pid group current_group
  current_group="$(ps -o pgid= -p $$ | tr -d ' ')"
  if tmux has-session -t "$session" 2>/dev/null; then
    while IFS= read -r pane_pid; do
      case "$pane_pid" in
        ''|*[!0-9]*) continue ;;
      esac
      group="$(ps -o pgid= -p "$pane_pid" 2>/dev/null | tr -d ' ')"
      case "$group" in
        ''|*[!0-9]*) ;;
        *)
          if [ "$group" != "$current_group" ]; then
            groups+=("$group")
          fi
          ;;
      esac
    done < <(tmux list-panes -t "$session" -F '#{pane_pid}' 2>/dev/null || true)
    tmux kill-session -t "$session"
  fi
  if tmux has-session -t "$session" 2>/dev/null; then
    red "tmux session '$session' is still running."
    return 1
  fi
  for group in "${groups[@]}"; do
    if /bin/kill -0 -- "-$group" 2>/dev/null; then
      /bin/kill -TERM -- "-$group" 2>/dev/null || true
    fi
  done
  local attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    local alive=0
    for group in "${groups[@]}"; do
      if /bin/kill -0 -- "-$group" 2>/dev/null; then
        alive=1
      fi
    done
    [ "$alive" = "0" ] && break
    sleep 0.2
  done
  for group in "${groups[@]}"; do
    if /bin/kill -0 -- "-$group" 2>/dev/null; then
      /bin/kill -KILL -- "-$group" 2>/dev/null || true
      sleep 0.1
    fi
    if /bin/kill -0 -- "-$group" 2>/dev/null; then
      red "Claude listener process group $group is still running."
      return 1
    fi
  done
}

unload_and_remove_agent() {
  local label="$1" plist="$2"
  if "$LAUNCHCTL_BIN" print "gui/$UID/$label" >/dev/null 2>&1; then
    if ! "$LAUNCHCTL_BIN" bootout "gui/$UID/$label" >/dev/null 2>&1; then
      red "Could not unload $label. Its plist and credentials were not removed."
      return 1
    fi
    if "$LAUNCHCTL_BIN" print "gui/$UID/$label" >/dev/null 2>&1; then
      red "$label still appears loaded. Its plist and credentials were not removed."
      return 1
    fi
  fi
  rm -f "$plist"
}

canonical_account_home() {
  if [ "${THREADKEEP_TEST_MODE:-0}" = "1" ]; then
    printf '%s\n' "$HOME"
    return
  fi
  [ -n "$PYTHON_BIN" ] && [ -x "$PYTHON_BIN" ] || {
    red "Python 3 is required to verify the canonical macOS account home."
    return 1
  }
  /usr/bin/env -i PATH="/usr/bin:/bin" LANG=C "$PYTHON_BIN" -I - <<'PY'
import os
import pwd
import stat
from pathlib import Path

configured = Path(pwd.getpwuid(os.getuid()).pw_dir)
resolved = configured.resolve(strict=True)
metadata = resolved.stat()
if (
    not configured.is_absolute()
    or resolved != configured
    or not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != os.getuid()
    or stat.S_IMODE(metadata.st_mode) & 0o022
):
    raise SystemExit("canonical macOS account home is unsafe")
print(resolved)
PY
}

logout_codex_chatgpt() {
  local account_home=""
  account_home="$(canonical_account_home)" || return 1
  [ -n "$account_home" ] || {
    red "Canonical macOS account home could not be determined."
    return 1
  }

  local -a clean_env=(
    /usr/bin/env -i
    "HOME=$account_home"
    "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    "LANG=C"
    "PYTHONPATH=$SCRIPT_DIR"
    "PYTHONSAFEPATH=1"
    "PYTHONDONTWRITEBYTECODE=1"
    "THREADKEEP_CONFIG=$SCRIPT_DIR/config.toml"
  )
  if [ "${THREADKEEP_TEST_MODE:-0}" = "1" ]; then
    clean_env+=(
      "THREADKEEP_TEST_MODE=1"
      "THREADKEEP_TEST_SECRET_PROBE=${THREADKEEP_TEST_SECRET_PROBE:-}"
      "THREADKEEP_TEST_SECRET_PROBE_LOG=${THREADKEEP_TEST_SECRET_PROBE_LOG:-}"
      "THREADKEEP_TEST_EXPECT_REAL_HOME=${THREADKEEP_TEST_EXPECT_REAL_HOME:-$account_home}"
      "THREADKEEP_TEST_AUTH_LOGOUT_MARKER=${THREADKEEP_TEST_AUTH_LOGOUT_MARKER:-}"
      "THREADKEEP_TEST_AUTH_LOGOUT_LOG=${THREADKEEP_TEST_AUTH_LOGOUT_LOG:-}"
      "THREADKEEP_TEST_AUTH_LOGOUT_FAIL=${THREADKEEP_TEST_AUTH_LOGOUT_FAIL:-0}"
      "THREADKEEP_TEST_ASSERT_CLEAN=${THREADKEEP_TEST_ASSERT_CLEAN:-}"
      "THREADKEEP_TEST_EXPECT_CONFIG=${THREADKEEP_TEST_EXPECT_CONFIG:-$SCRIPT_DIR/config.toml}"
      "THREADKEEP_TEST_ORDER_LOG=${THREADKEEP_TEST_ORDER_LOG:-}"
    )
  fi
  "${clean_env[@]}" "$PYTHON_BIN" -m codex_discord_bridge.codex_auth \
    logout-configured
}

uninstall_codex() {
  local label="com.threadkeep.codex-discord-bridge"
  local agents_dir="$HOME/Library/LaunchAgents"
  local plist="$agents_dir/$label.plist"
  local codex_keychain_account="discord-bot-token-codex"

  say "Threadkeep Codex provider uninstaller (tmux: $TMUX_SESSION)"

  blue "Unloading the Codex LaunchAgent."
  if [ -f "$plist" ] || "$LAUNCHCTL_BIN" print "gui/$UID/$label" >/dev/null 2>&1; then
    unload_and_remove_agent "$label" "$plist"
    green "  Unloaded + removed $label"
  else
    say "  $label not installed; skipping."
  fi

  blue "Killing read-only tmux monitor '$TMUX_SESSION' if running."
  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    tmux kill-session -t "$TMUX_SESSION"
    green "  Killed tmux session '$TMUX_SESSION'."
  else
    say "  No tmux session '$TMUX_SESSION' to kill."
  fi

  if [ "$KEEP_CHATGPT_LOGIN" = "1" ]; then
    yellow "Keeping the isolated ChatGPT login (--keep-chatgpt-login)."
  else
    blue "Removing the ChatGPT login scoped to the isolated Threadkeep CODEX_HOME."
    if ! logout_codex_chatgpt; then
      red "Could not remove and verify the isolated ChatGPT login. Codex state and Discord credentials were left in place."
      return 1
    fi
    green "  Official Codex logout completed and logged-out status verified."
  fi

  if [ "$KEEP_KEYCHAIN" = "1" ]; then
    yellow "Skipping Codex Keychain delete (--keep-keychain)."
  else
    blue "Removing Keychain entry $KEYCHAIN_SERVICE/$codex_keychain_account."
    if "$SECURITY_BIN" find-generic-password \
      -s "$KEYCHAIN_SERVICE" -a "$codex_keychain_account" >/dev/null 2>&1; then
      if ! "$SECURITY_BIN" delete-generic-password \
        -s "$KEYCHAIN_SERVICE" -a "$codex_keychain_account" >/dev/null 2>&1; then
        red "Could not remove the Codex Discord token from Keychain."
        return 1
      fi
      if "$SECURITY_BIN" find-generic-password \
        -s "$KEYCHAIN_SERVICE" -a "$codex_keychain_account" >/dev/null 2>&1; then
        red "The Codex Discord token is still present in Keychain."
        return 1
      fi
      green "  Deleted."
    else
      say "  Entry not present."
    fi
  fi

  yellow "Leaving config.toml and Codex state in place for audit or reinstall."
  if [ "$KEEP_CHATGPT_LOGIN" = "1" ]; then
    yellow "The isolated ChatGPT login was retained by explicit request."
  else
    say "The isolated ChatGPT login was removed; noncredential Codex state remains for audit."
  fi
  green
  green "Codex provider uninstall complete. Claude was left unchanged."
}

main() {
  # A caller-supplied install credential must not enter launchctl, tmux, or
  # cleanup subprocesses during removal.
  export -n DISCORD_BOT_TOKEN 2>/dev/null || true
  unset DISCORD_BOT_TOKEN THREADKEEP_CODEX_DISCORD_BOT_TOKEN OPENAI_API_KEY || true
  if [ "$CODEX_ONLY" = "1" ]; then
    uninstall_codex
    return
  fi

  say "Threadkeep uninstaller (label prefix: $LABEL_PREFIX, tmux: $TMUX_SESSION)"

  # ----- launchd -----
  local agents_dir="$HOME/Library/LaunchAgents"
  blue "Unloading launchd agents."
  for component in cx-chat-healthcheck discord-gateway-client discord-marker-watcher; do
    local label="$LABEL_PREFIX.$component"
    local plist="$agents_dir/$label.plist"
    if [ -f "$plist" ] || "$LAUNCHCTL_BIN" print "gui/$UID/$label" >/dev/null 2>&1; then
      unload_and_remove_agent "$label" "$plist"
      green "  Unloaded + removed $label"
    else
      say "  $label not installed; skipping."
    fi
  done

  # ----- tmux -----
  blue "Killing tmux session '$TMUX_SESSION' if running."
  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    stop_listener_session "$TMUX_SESSION"
    green "  Killed tmux session '$TMUX_SESSION'."
  else
    say "  No tmux session '$TMUX_SESSION' to kill."
  fi

  blue "Removing any retired plaintext Claude Discord token copy."
  env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$SCRIPT_DIR/conversations" \
    python3 "$SCRIPT_DIR/conversations/discord_access.py" remove-legacy-token >/dev/null || {
      red "Could not remove or prove absence of the retired Claude Discord token copy."
      return 1
    }
  green "  Removed and verified absent."

  # ----- keychain -----
  if [ "$KEEP_KEYCHAIN" = "1" ]; then
    yellow "Skipping Keychain delete (--keep-keychain)."
  else
    blue "Removing Keychain entry $KEYCHAIN_SERVICE/$KEYCHAIN_ACCOUNT."
    if "$SECURITY_BIN" find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1; then
      "$SECURITY_BIN" delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1
      if "$SECURITY_BIN" find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1; then
        red "The Claude Discord token is still present in Keychain."
        return 1
      fi
      green "  Deleted."
    else
      say "  Entry not present."
    fi
  fi

  # ----- conversations dir -----
  if [ -f "$HOME/.threadkeep/conversations/_registry.json" ] || [ -d "$HOME/.threadkeep/conversations/active" ]; then
    local convo_dir="$HOME/.threadkeep/conversations"
    if [ "$ARCHIVE_CONVERSATIONS" = "1" ]; then
      local stamp
      stamp=$(date "+%Y%m%d-%H%M%S")
      mv "$convo_dir" "$convo_dir.archived-$stamp"
      green "  Archived $convo_dir -> $convo_dir.archived-$stamp"
    elif [ "$KEEP_CONVERSATIONS" = "1" ] || [ "$NON_INTERACTIVE" = "1" ]; then
      yellow "Leaving conversations dir in place at $convo_dir."
    else
      read -r -p "Archive conversations dir at $convo_dir? [y/N]: " yn
      case "$yn" in
        y|Y|yes|Yes|YES)
          local stamp
          stamp=$(date "+%Y%m%d-%H%M%S")
          mv "$convo_dir" "$convo_dir.archived-$stamp"
          green "  Archived to $convo_dir.archived-$stamp"
          ;;
        *)
          yellow "  Left in place."
          ;;
      esac
    fi
  fi

  green
  green "Uninstall complete."
}

main "$@"
