#!/usr/bin/env bash
# install.sh
#
# Threadkeep macOS install script. Idempotent. Re-running detects an existing
# install and offers reinstall, skip, or uninstall.
#
# What it does:
#   1. Verifies prerequisites (python3 >= 3.11, websockets, tmux, curl, jq).
#   2. Prompts for or accepts THREADKEEP_REPO_ROOT (defaults to script dir).
#   3. Resolves the Discord bot token (env var, stdin prompt, or existing
#      Keychain entry) and stores it in the macOS Keychain under
#      service "threadkeep-secret", account "discord-bot-token".
#   4. Generates config.toml from config.example.toml with substituted values
#      (chat_channel_id, errors_channel_id, owner_user_id, timezone).
#   5. Renders the launchd plist templates with __REPO_ROOT__, __HOME__,
#      __PYTHON_BIN__, __LABEL__, __TMUX_SESSION__ substitutions and writes
#      them to ~/Library/LaunchAgents/.
#   6. Bootstraps each plist with launchctl (skipped in --scratch mode).
#   7. Starts the listener tmux session via cx-launcher.sh (skipped in
#      --scratch mode).
#   8. Prints a summary + uninstall command.
#
# Flags:
#   --scratch              Don't actually bootstrap launchd agents or start
#                          tmux. Useful for testing the wiring in a sandbox.
#   --label-prefix PREFIX  Override the launchd label prefix. Default:
#                          "com.threadkeep". install.sh writes plists named
#                          PREFIX.cx-chat-healthcheck.plist etc. Used together
#                          with --scratch to avoid colliding with a real
#                          install on the same machine.
#   --tmux-session NAME    Override the tmux session name. Default:
#                          "threadkeep-chat". Should match anything you
#                          configure in your client.
#   --non-interactive      Don't prompt. Fail if required values aren't
#                          already in the env or in a .threadkeep.env file.
#   --reinstall            Skip the "existing install detected" prompt.
#   --uninstall            Run uninstall.sh and exit.
#   -h, --help             Show this help.
#
# Env vars honored as defaults for prompts:
#   DISCORD_BOT_TOKEN
#   THREADKEEP_REPO_ROOT
#   THREADKEEP_LISTEN_CHANNEL_ID
#   THREADKEEP_ERRORS_CHANNEL_ID
#   THREADKEEP_OWNER_USER_ID
#   THREADKEEP_TIMEZONE
#
# A .threadkeep.env file in the repo root, if present, is sourced for these
# vars before prompting.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$SCRIPT_DIR"
LABEL_PREFIX="com.threadkeep"
TMUX_SESSION="threadkeep-chat"
SCRATCH=0
NON_INTERACTIVE=0
REINSTALL=0

KEYCHAIN_SERVICE="threadkeep-secret"
KEYCHAIN_ACCOUNT="discord-bot-token"

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --scratch) SCRATCH=1; shift ;;
    --label-prefix) LABEL_PREFIX="$2"; shift 2 ;;
    --tmux-session) TMUX_SESSION="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --reinstall) REINSTALL=1; shift ;;
    --uninstall) exec "$SCRIPT_DIR/uninstall.sh" --label-prefix "$LABEL_PREFIX" --tmux-session "$TMUX_SESSION" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $1" >&2; usage; exit 2 ;;
  esac
done

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
blue()   { printf "\033[34m%s\033[0m\n" "$*"; }
say()    { printf "%s\n" "$*"; }

die() {
  red "ERROR: $*"
  exit 1
}

prompt() {
  local var="$1" label="$2" default="${3:-}"
  if [ "$NON_INTERACTIVE" = "1" ]; then
    local cur
    cur="$(eval "echo \${$var:-}")"
    [ -n "$cur" ] || die "$var is required in --non-interactive mode (env var or .threadkeep.env)."
    return 0
  fi
  local cur
  cur="$(eval "echo \${$var:-}")"
  local prompt_default
  if [ -n "$cur" ]; then prompt_default="$cur"
  else prompt_default="$default"
  fi
  local input
  if [ -n "$prompt_default" ]; then
    read -r -p "$label [$prompt_default]: " input
    input="${input:-$prompt_default}"
  else
    read -r -p "$label: " input
  fi
  printf -v "$var" '%s' "$input"
  export "$var"
}

prompt_secret() {
  local var="$1" label="$2"
  if [ "$NON_INTERACTIVE" = "1" ]; then
    local cur
    cur="$(eval "echo \${$var:-}")"
    [ -n "$cur" ] || die "$var is required in --non-interactive mode."
    return 0
  fi
  local input
  read -r -s -p "$label: " input
  echo
  printf -v "$var" '%s' "$input"
  export "$var"
}

# ----- prereqs -----

check_prereqs() {
  blue "Checking prerequisites."
  command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH."
  local pyver
  pyver=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  case "$pyver" in
    3.1[1-9]*|3.[2-9][0-9]*|[4-9].*) ;;
    *) die "python3 must be 3.11 or newer (found $pyver)." ;;
  esac
  python3 -c "import websockets" 2>/dev/null || \
    die "Python 'websockets' package not installed. Run: python3 -m pip install -r requirements.txt"
  command -v tmux >/dev/null 2>&1 || die "tmux not found on PATH. Install via 'brew install tmux'."
  command -v curl >/dev/null 2>&1 || die "curl not found on PATH."
  command -v jq   >/dev/null 2>&1 || die "jq not found on PATH. Install via 'brew install jq'."
  command -v security >/dev/null 2>&1 || die "macOS 'security' tool not found (not on macOS?)."
  green "  python3 $pyver, websockets, tmux, curl, jq, security: OK"
}

# ----- token resolution -----

resolve_bot_token() {
  if [ -n "${DISCORD_BOT_TOKEN:-}" ]; then
    say "  Using DISCORD_BOT_TOKEN from environment."
    return 0
  fi
  local existing
  existing=$(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w 2>/dev/null || true)
  if [ -n "$existing" ]; then
    if [ "$NON_INTERACTIVE" = "1" ]; then
      DISCORD_BOT_TOKEN="$existing"
      export DISCORD_BOT_TOKEN
      say "  Reusing existing Keychain entry $KEYCHAIN_SERVICE/$KEYCHAIN_ACCOUNT."
      return 0
    fi
    local reuse
    read -r -p "  Keychain entry $KEYCHAIN_SERVICE/$KEYCHAIN_ACCOUNT exists. Reuse it? [Y/n]: " reuse
    case "$reuse" in
      n|N|no|No|NO)
        prompt_secret DISCORD_BOT_TOKEN "  Paste Discord bot token"
        ;;
      *)
        DISCORD_BOT_TOKEN="$existing"
        export DISCORD_BOT_TOKEN
        return 0
        ;;
    esac
  else
    prompt_secret DISCORD_BOT_TOKEN "  Paste Discord bot token"
  fi
  [ -n "${DISCORD_BOT_TOKEN:-}" ] || die "Discord bot token cannot be empty."
}

store_token_in_keychain() {
  blue "Storing Discord bot token in macOS Keychain."
  security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1 || true
  security add-generic-password \
    -s "$KEYCHAIN_SERVICE" \
    -a "$KEYCHAIN_ACCOUNT" \
    -w "$DISCORD_BOT_TOKEN" \
    -U
  green "  Stored at service=$KEYCHAIN_SERVICE account=$KEYCHAIN_ACCOUNT."
}

# ----- config.toml -----

write_config_toml() {
  local target="$REPO_ROOT/config.toml"
  if [ -f "$target" ] && [ "$REINSTALL" != "1" ] && [ "$NON_INTERACTIVE" != "1" ]; then
    local overwrite
    read -r -p "  $target exists. Overwrite? [y/N]: " overwrite
    case "$overwrite" in
      y|Y|yes|Yes|YES) ;;
      *) say "  Keeping existing config.toml."; return 0 ;;
    esac
  fi
  cat > "$target" <<EOF
# Generated by install.sh on $(date -u "+%Y-%m-%dT%H:%M:%SZ")

[paths]
workspace_root = "$WORKSPACE_ROOT"
conversations_dir = "$WORKSPACE_ROOT/conversations"

[discord]
chat_channel_id = "$THREADKEEP_LISTEN_CHANNEL_ID"
errors_channel_id = "$THREADKEEP_ERRORS_CHANNEL_ID"
owner_user_id = "$THREADKEEP_OWNER_USER_ID"
token_env_var = "DISCORD_BOT_TOKEN"

[runtime]
timezone = "${THREADKEEP_TIMEZONE:-UTC}"
max_messages_per_minute = 5
max_messages_per_hour = 30
max_concurrent_workers = 3
use_dangerously_skip_permissions = false
EOF
  green "  Wrote $target."
}

# ----- launchd plist substitution -----

render_plist() {
  local template="$1" label="$2" target="$3" python_bin="$4"
  if [ ! -r "$template" ]; then
    die "Template not found: $template"
  fi
  sed \
    -e "s|__REPO_ROOT__|$REPO_ROOT|g" \
    -e "s|__HOME__|$HOME|g" \
    -e "s|__PYTHON_BIN__|$python_bin|g" \
    -e "s|__LABEL__|$label|g" \
    -e "s|__TMUX_SESSION__|$TMUX_SESSION|g" \
    "$template" > "$target"
  green "  Rendered $target"
}

install_plists() {
  blue "Rendering launchd plists with prefix '$LABEL_PREFIX'."
  local agents_dir="$HOME/Library/LaunchAgents"
  mkdir -p "$agents_dir"
  mkdir -p "$REPO_ROOT/logs" "$REPO_ROOT/discord-gateway/logs"

  local python_bin
  python_bin="$(command -v python3)"

  render_plist \
    "$REPO_ROOT/launchd/templates/com.threadkeep.cx-chat-healthcheck.plist.template" \
    "$LABEL_PREFIX.cx-chat-healthcheck" \
    "$agents_dir/$LABEL_PREFIX.cx-chat-healthcheck.plist" \
    "$python_bin"

  render_plist \
    "$REPO_ROOT/launchd/templates/com.threadkeep.discord-gateway-client.plist.template" \
    "$LABEL_PREFIX.discord-gateway-client" \
    "$agents_dir/$LABEL_PREFIX.discord-gateway-client.plist" \
    "$python_bin"

  render_plist \
    "$REPO_ROOT/launchd/templates/com.threadkeep.discord-marker-watcher.plist.template" \
    "$LABEL_PREFIX.discord-marker-watcher" \
    "$agents_dir/$LABEL_PREFIX.discord-marker-watcher.plist" \
    "$python_bin"
}

bootstrap_agents() {
  if [ "$SCRATCH" = "1" ]; then
    yellow "  --scratch mode: skipping launchctl bootstrap."
    return 0
  fi
  blue "Bootstrapping launchd agents."
  local agents_dir="$HOME/Library/LaunchAgents"
  for component in cx-chat-healthcheck discord-gateway-client discord-marker-watcher; do
    local label="$LABEL_PREFIX.$component"
    local plist="$agents_dir/$label.plist"
    launchctl bootout "gui/$UID/$label" 2>/dev/null || true
    launchctl bootstrap "gui/$UID" "$plist"
    launchctl enable "gui/$UID/$label" 2>/dev/null || true
    green "  Bootstrapped $label"
  done
}

verify_listener_cwd() {
  # The cx-chat-listener subdir is shipped in the repo. Its CLAUDE.md is the
  # primary mechanism that survives /compact and /clear. Verify it exists
  # before starting the tmux session so we fail loudly on an old checkout.
  local listener_cwd="$REPO_ROOT/cx-chat-listener"
  if [ ! -f "$listener_cwd/CLAUDE.md" ]; then
    yellow "  WARN: $listener_cwd/CLAUDE.md missing. Identity persistence across"
    yellow "        /compact will be degraded. Run 'git pull' on the repo to fix."
    return 1
  fi
  green "  Listener cwd verified at $listener_cwd"
  return 0
}

start_listener_session() {
  if [ "$SCRATCH" = "1" ]; then
    yellow "  --scratch mode: skipping tmux listener start."
    return 0
  fi
  blue "Starting tmux listener session '$TMUX_SESSION'."
  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    say "  Session already exists. Not restarting."
    return 0
  fi
  # The healthcheck will start the session on its next tick. We can also
  # start it directly now via the launcher. Always start with cwd at the
  # cx-chat-listener subdir so Claude Code auto-loads its CLAUDE.md, which
  # is what re-asserts identity after /compact and /clear.
  local listener_cwd="$REPO_ROOT/cx-chat-listener"
  local launch_cwd
  if [ -d "$listener_cwd" ]; then
    launch_cwd="$listener_cwd"
  else
    launch_cwd="$REPO_ROOT"
    yellow "  WARN: $listener_cwd missing, launching from repo root instead."
  fi
  if [ -x "$REPO_ROOT/cx-launcher.sh" ]; then
    tmux new-session -d -s "$TMUX_SESSION" -c "$launch_cwd" "$REPO_ROOT/cx-launcher.sh"
    green "  Started tmux session '$TMUX_SESSION' (cwd=$launch_cwd)."
  else
    yellow "  cx-launcher.sh not executable. Healthcheck will retry on next tick."
  fi
}

# ----- existing install detection -----

detect_existing() {
  local agents_dir="$HOME/Library/LaunchAgents"
  for component in cx-chat-healthcheck discord-gateway-client discord-marker-watcher; do
    if [ -f "$agents_dir/$LABEL_PREFIX.$component.plist" ]; then
      return 0
    fi
  done
  return 1
}

# ----- main -----

main() {
  say "Threadkeep installer (label prefix: $LABEL_PREFIX, scratch: $SCRATCH)"
  say

  if detect_existing && [ "$REINSTALL" != "1" ]; then
    if [ "$NON_INTERACTIVE" = "1" ]; then
      yellow "Existing install detected with prefix '$LABEL_PREFIX'. Reinstalling (--non-interactive)."
    else
      local choice
      read -r -p "Existing install detected. [r]einstall, [s]kip, or [u]ninstall? [r/s/u]: " choice
      case "$choice" in
        u|U) exec "$SCRIPT_DIR/uninstall.sh" --label-prefix "$LABEL_PREFIX" --tmux-session "$TMUX_SESSION" ;;
        s|S) say "Skipping. Bye."; exit 0 ;;
        *) ;;
      esac
    fi
  fi

  check_prereqs

  if [ -f "$SCRIPT_DIR/.threadkeep.env" ]; then
    say "Loading defaults from .threadkeep.env."
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.threadkeep.env"
  fi

  prompt REPO_ROOT "Repo root" "$DEFAULT_REPO_ROOT"
  REPO_ROOT="${REPO_ROOT/#~/$HOME}"
  [ -d "$REPO_ROOT" ] || die "Repo root does not exist: $REPO_ROOT"

  prompt WORKSPACE_ROOT "Workspace root (where conversations live)" "$HOME/.threadkeep"
  WORKSPACE_ROOT="${WORKSPACE_ROOT/#~/$HOME}"
  mkdir -p "$WORKSPACE_ROOT/conversations"

  prompt THREADKEEP_LISTEN_CHANNEL_ID "Discord listen channel id" ""
  prompt THREADKEEP_ERRORS_CHANNEL_ID "Discord errors channel id" "${THREADKEEP_LISTEN_CHANNEL_ID:-}"
  prompt THREADKEEP_OWNER_USER_ID "Discord owner user id (your user id)" ""
  prompt THREADKEEP_TIMEZONE "Timezone (IANA name)" "America/New_York"

  resolve_bot_token
  store_token_in_keychain
  write_config_toml
  verify_listener_cwd || true
  install_plists
  bootstrap_agents
  start_listener_session

  green
  green "Done."
  say
  say "Summary:"
  say "  Repo root:        $REPO_ROOT"
  say "  Workspace root:   $WORKSPACE_ROOT"
  say "  Config file:      $REPO_ROOT/config.toml"
  say "  Keychain entry:   service=$KEYCHAIN_SERVICE account=$KEYCHAIN_ACCOUNT"
  say "  Launchd label:    $LABEL_PREFIX.*"
  say "  Tmux session:     $TMUX_SESSION"
  say "  Plist files:      $HOME/Library/LaunchAgents/$LABEL_PREFIX.*.plist"
  say
  say "Verify:"
  say "  launchctl print gui/\$UID/$LABEL_PREFIX.discord-gateway-client | head -20"
  say "  tmux attach -t $TMUX_SESSION"
  say "  tail -f $REPO_ROOT/discord-gateway/logs/client.log"
  say
  say "Uninstall:"
  say "  $SCRIPT_DIR/uninstall.sh --label-prefix $LABEL_PREFIX --tmux-session $TMUX_SESSION"
}

main "$@"
