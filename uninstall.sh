#!/usr/bin/env bash
# uninstall.sh
#
# Reverses install.sh. Stops the tmux listener, unloads launchd agents,
# removes the rendered plists, and optionally deletes the Keychain entry
# and archives the conversations dir.
#
# Flags:
#   --label-prefix PREFIX  Match the install prefix. Default: "com.threadkeep".
#   --tmux-session NAME    tmux session to kill. Default: "threadkeep-chat".
#   --keep-keychain        Skip Keychain entry deletion.
#   --keep-conversations   Skip the prompt about archiving conversations dir.
#   --non-interactive      Don't prompt. Implies --keep-conversations unless
#                          --archive-conversations is also set.
#   --archive-conversations
#                          Move the conversations dir to a timestamped sibling.
#   -h, --help             Show this help.

set -euo pipefail

LABEL_PREFIX="com.threadkeep"
TMUX_SESSION="threadkeep-chat"
KEEP_KEYCHAIN=0
KEEP_CONVERSATIONS=0
NON_INTERACTIVE=0
ARCHIVE_CONVERSATIONS=0

KEYCHAIN_SERVICE="threadkeep-secret"
KEYCHAIN_ACCOUNT="discord-bot-token"

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --label-prefix) LABEL_PREFIX="$2"; shift 2 ;;
    --tmux-session) TMUX_SESSION="$2"; shift 2 ;;
    --keep-keychain) KEEP_KEYCHAIN=1; shift ;;
    --keep-conversations) KEEP_CONVERSATIONS=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --archive-conversations) ARCHIVE_CONVERSATIONS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 2 ;;
  esac
done

red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[33m%s\033[0m\n" "$*"; }
blue()  { printf "\033[34m%s\033[0m\n" "$*"; }
say()   { printf "%s\n" "$*"; }

main() {
  say "Threadkeep uninstaller (label prefix: $LABEL_PREFIX, tmux: $TMUX_SESSION)"

  # ----- launchd -----
  local agents_dir="$HOME/Library/LaunchAgents"
  blue "Unloading launchd agents."
  for component in cx-chat-healthcheck discord-gateway-client discord-marker-watcher; do
    local label="$LABEL_PREFIX.$component"
    local plist="$agents_dir/$label.plist"
    if [ -f "$plist" ]; then
      launchctl bootout "gui/$UID/$label" 2>/dev/null || true
      rm -f "$plist"
      green "  Unloaded + removed $label"
    else
      say "  $label not installed; skipping."
    fi
  done

  # ----- tmux -----
  blue "Killing tmux session '$TMUX_SESSION' if running."
  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    tmux kill-session -t "$TMUX_SESSION"
    green "  Killed tmux session '$TMUX_SESSION'."
  else
    say "  No tmux session '$TMUX_SESSION' to kill."
  fi

  # ----- keychain -----
  if [ "$KEEP_KEYCHAIN" = "1" ]; then
    yellow "Skipping Keychain delete (--keep-keychain)."
  else
    blue "Removing Keychain entry $KEYCHAIN_SERVICE/$KEYCHAIN_ACCOUNT."
    if security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1; then
      security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1 || true
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
