#!/usr/bin/env bash
# install.sh
#
# Disco Party macOS install script. Idempotent. Re-running detects an existing
# install and offers reinstall, skip, or uninstall.
#
# What it does:
#   1. Verifies prerequisites (Python, Claude Code, Bun, websockets, tmux, jq).
#   2. Prompts for or accepts DISCOPARTY_REPO_ROOT (defaults to script dir).
#   3. Resolves the Discord bot token (env var, stdin prompt, or existing
#      Keychain entry) and stores it in the macOS Keychain under
#      service "discoparty-secret", account "discord-bot-token".
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
#                          "com.discoparty". install.sh writes plists named
#                          PREFIX.cx-chat-healthcheck.plist etc. Used together
#                          with --scratch to avoid colliding with a real
#                          install on the same machine.
#   --tmux-session NAME    Override the tmux session name. Default:
#                          "discoparty-chat". Should match anything you
#                          configure in your client.
#   --non-interactive      Don't prompt. Fail if required values aren't
#                          already in the process environment.
#   --reinstall            Skip the "existing install detected" prompt.
#   --take-over-legacy     Replace the exact com.thesystem Claude deployment.
#                          Requires a maintenance phrase and quarantines legacy
#                          rows whose worker side effects cannot be proven.
#   --uninstall            Run uninstall.sh and exit.
#   -h, --help             Show this help.
#
# Env vars honored as defaults for prompts:
#   DISCORD_BOT_TOKEN
#   DISCOPARTY_REPO_ROOT
#   DISCOPARTY_LISTEN_CHANNEL_ID
#   DISCOPARTY_ERRORS_CHANNEL_ID
#   DISCOPARTY_OWNER_USER_ID
#   DISCOPARTY_TIMEZONE
#   DISCOPARTY_LEGACY_MAINTENANCE_PHRASE
#   DISCOPARTY_LEGACY_QUARANTINE_ACK
#
# Secret-bearing environment files are never loaded. A caller may provide the
# Discord token in this installer's transient process environment; it is stored
# in Keychain and cleared before any long-lived process starts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$SCRIPT_DIR"
LABEL_PREFIX="com.discoparty"
TMUX_SESSION="discoparty-chat"
SCRATCH=0
NON_INTERACTIVE=0
REINSTALL=0
CLAUDE_FULL_AUTHORITY=0
TAKE_OVER_LEGACY=0
TAKEOVER_RECEIPT=""
TAKEOVER_COMMITTED=0
CLAUDE_ACCESS_INSTALLED=0
LEGACY_MAINTENANCE_PHRASE=""
LEGACY_QUARANTINE_ACK=""
LEGACY_QUEUE_PLAN_SHA256=""
CONVERSATIONS_DIR=""

KEYCHAIN_SERVICE="discoparty-secret"
KEYCHAIN_ACCOUNT="discord-bot-token"
CLAUDE_BIN="$HOME/.local/share/claude/versions/2.1.251"
BUN_BIN="/opt/homebrew/bin/bun"

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
    --take-over-legacy) TAKE_OVER_LEGACY=1; shift ;;
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

collect_takeover_authorization() {
  [ "$TAKE_OVER_LEGACY" = "1" ] || return 0
  [ "$SCRATCH" = "0" ] || die \
    "--take-over-legacy cannot be combined with --scratch."
  [ "$LABEL_PREFIX" != "com.thesystem" ] || die \
    "The replacement label prefix must differ from com.thesystem."
  [ "$TMUX_SESSION" != "cx-chat" ] || die \
    "The replacement tmux session must differ from cx-chat."
  local expected="I HAVE STOPPED POSTING AND AUTHORIZE LEGACY CLAUDE TAKEOVER"
  if [ "$NON_INTERACTIVE" = "1" ]; then
    LEGACY_MAINTENANCE_PHRASE="${DISCOPARTY_LEGACY_MAINTENANCE_PHRASE:-}"
  else
    yellow "  Legacy takeover enters a maintenance window and stops all five com.thesystem jobs."
    yellow "  Legacy claimed or dispatched rows with unprovable worker effects will be quarantined, never replayed."
    yellow "  Do not post in the Claude Discord channel until this installer finishes."
    read -r -p "  Type $expected: " LEGACY_MAINTENANCE_PHRASE
  fi
  [ "$LEGACY_MAINTENANCE_PHRASE" = "$expected" ] || die \
    "The exact legacy takeover maintenance phrase was not provided."
}

collect_quarantine_authorization() {
  [ "$TAKE_OVER_LEGACY" = "1" ] || return 0
  local plan acknowledgment claimed dispatched hard_blockers spawned
  plan="$(
    env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH="$REPO_ROOT/conversations" \
      python3 "$REPO_ROOT/conversations/claude_takeover.py" plan \
        --queue-db "$CONVERSATIONS_DIR/state/mq.sqlite3"
  )" || die "Could not build the read-only legacy queue takeover plan."
  IFS=$'\t' read -r \
    claimed dispatched hard_blockers spawned LEGACY_QUEUE_PLAN_SHA256 acknowledgment <<< "$(
      printf '%s' "$plan" | python3 -c '
import json, sys
value = json.load(sys.stdin)
print(
    value["claimed_without_ledger"],
    value["dispatched"],
    value["hard_blockers"],
    value["spawned_blockers"],
    value["snapshot_sha256"],
    value["acknowledgment"],
    sep="\t",
)
'
    )" || die "Legacy queue takeover plan is malformed."
  [ "$hard_blockers" = "0" ] || die \
    "Legacy queue contains $hard_blockers hard blocker(s), including $spawned spawned row(s). Inspect the read-only plan and reconcile them manually before takeover."
  yellow "  Unresolved manual-review rows: $claimed claimed without a new operation ledger, $dispatched dispatched."
  if [ "$NON_INTERACTIVE" = "1" ]; then
    LEGACY_QUARANTINE_ACK="${DISCOPARTY_LEGACY_QUARANTINE_ACK:-}"
  else
    read -r -p "  Type $acknowledgment: " LEGACY_QUARANTINE_ACK
  fi
  [ "$LEGACY_QUARANTINE_ACK" = "$acknowledgment" ] || die \
    "The exact count-bound quarantine acknowledgment was not provided."
}

takeover_exit_trap() {
  local result=$?
  trap - EXIT
  if [ "$CLAUDE_ACCESS_INSTALLED" = "1" ]; then
    if ! env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH="$REPO_ROOT/conversations" \
      python3 "$REPO_ROOT/conversations/discord_access.py" \
        remove-legacy-token >/dev/null; then
      red "  Could not prove the retired Claude plugin .env is absent during rollback."
    fi
  fi
  if [ "$TAKE_OVER_LEGACY" = "1" ] && \
    [ -n "$TAKEOVER_RECEIPT" ] && [ -f "$TAKEOVER_RECEIPT" ] && \
    [ "$TAKEOVER_COMMITTED" != "1" ]; then
    yellow "A replacement gate failed. Checking whether automatic legacy rollback is still safe."
    if env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH="$REPO_ROOT/conversations" \
      python3 "$REPO_ROOT/conversations/claude_takeover.py" abort \
        --receipt "$TAKEOVER_RECEIPT"; then
      yellow "  The exact legacy runtime was restored because the replacement accepted no work."
    else
      red "  Automatic rollback was refused or failed. Keep both runtimes stopped and inspect the private takeover receipt."
    fi
  fi
  exit "$result"
}

prepare_legacy_takeover() {
  [ "$TAKE_OVER_LEGACY" = "1" ] || return 0
  blue "Quiescing and reconciling the exact legacy Claude runtime."
  local receipt_dir="$CONVERSATIONS_DIR/state/takeover"
  local requested_receipt="$receipt_dir/install-$(date -u '+%Y%m%dT%H%M%SZ')-$$.json"
  TAKEOVER_RECEIPT="$requested_receipt"
  trap takeover_exit_trap EXIT
  printf '%s\n%s\n%s\n%s\n' \
    "$LEGACY_MAINTENANCE_PHRASE" \
    "$DISCORD_BOT_TOKEN" \
    "$LEGACY_QUARANTINE_ACK" \
    "$LEGACY_QUEUE_PLAN_SHA256" | \
    env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH="$REPO_ROOT/conversations" \
      python3 "$REPO_ROOT/conversations/claude_takeover.py" prepare \
        --take-over-legacy \
        --quarantine-ambiguous \
        --receipt "$requested_receipt" \
        --workspace-root "$WORKSPACE_ROOT" \
        --conversations-dir "$CONVERSATIONS_DIR" \
        --queue-db "$CONVERSATIONS_DIR/state/mq.sqlite3" \
        --backup-root "$CONVERSATIONS_DIR/state/takeover-backups" \
        --plist-dir "$HOME/Library/LaunchAgents" \
        --legacy-approval-root "$WORKSPACE_ROOT/x_System/Assistant/discord-gateway" \
        --new-gateway-state "$REPO_ROOT/discord-gateway/state/gateway.json" \
        --root-channel "$DISCOPARTY_LISTEN_CHANNEL_ID" \
        --owner-user-id "$DISCOPARTY_OWNER_USER_ID" \
        --new-label-prefix "$LABEL_PREFIX" \
        --new-session "$TMUX_SESSION" \
        --repo-root "$REPO_ROOT" \
        >/dev/null || die "Legacy Claude takeover preparation failed."
  [ -f "$requested_receipt" ] || die "Legacy takeover did not create its private receipt."
  green "  Legacy ingress and workers are stopped, backed up, classified, and reconciled."
}

begin_takeover_replacement() {
  [ "$TAKE_OVER_LEGACY" = "1" ] || return 0
  env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$REPO_ROOT/conversations" \
    python3 "$REPO_ROOT/conversations/claude_takeover.py" begin-replacement \
      --receipt "$TAKEOVER_RECEIPT" || \
    die "Could not freeze the replacement acceptance baseline."
}

finalize_legacy_takeover() {
  [ "$TAKE_OVER_LEGACY" = "1" ] || return 0
  blue "Reconciling the final Discord overlap window and committing takeover."
  local final_token
  final_token="$(env -u DISCORD_BOT_TOKEN security find-generic-password \
    -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w 2>/dev/null)" || \
    die "Could not reload the Claude Discord token for final reconciliation."
  [ -n "$final_token" ] || die \
    "Claude Discord token is empty during final reconciliation."
  printf '%s\n%s\n' "$LEGACY_MAINTENANCE_PHRASE" "$final_token" | \
    env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH="$REPO_ROOT/conversations" \
      python3 "$REPO_ROOT/conversations/claude_takeover.py" finalize \
        --receipt "$TAKEOVER_RECEIPT" || {
          final_token=""
          unset final_token
          die "Replacement readiness or final Discord reconciliation failed."
        }
  final_token=""
  unset final_token
  TAKEOVER_COMMITTED=1
  trap - EXIT
  green "  Takeover committed. Automatic legacy restart is now permanently disabled."
}

prompt() {
  local var="$1" label="$2" default="${3:-}"
  if [ "$NON_INTERACTIVE" = "1" ]; then
    local cur
    cur="$(eval "echo \${$var:-}")"
    [ -n "$cur" ] || die "$var is required in --non-interactive mode (process environment)."
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
  command -v jq   >/dev/null 2>&1 || die "jq not found on PATH. Install via 'brew install jq'."
  [ -x "$CLAUDE_BIN" ] || die "Claude Code CLI not found at $CLAUDE_BIN."
  PYTHONPATH="$SCRIPT_DIR/conversations" \
    python3 "$SCRIPT_DIR/conversations/claude_cli.py" verify \
      --path "$CLAUDE_BIN" >/dev/null || \
    die "Claude Code CLI is not the exact reviewed M5 build."
  [ -x "$BUN_BIN" ] || die "Bun not found at $BUN_BIN. The official Discord plugin requires Bun."
  PYTHONPATH="$SCRIPT_DIR/conversations" \
    python3 "$SCRIPT_DIR/conversations/bun_runtime.py" verify \
      --path "$BUN_BIN" >/dev/null || \
    die "Bun is not the exact reviewed M5 build."
  PYTHONPATH="$SCRIPT_DIR/conversations" \
    python3 "$SCRIPT_DIR/conversations/listener_contract.py" verify \
      --path "$SCRIPT_DIR/cx-chat-listener/CLAUDE.md" >/dev/null || \
    die "The pinned Claude listener system prompt is missing or changed."
  command -v security >/dev/null 2>&1 || die "macOS 'security' tool not found (not on macOS?)."
  command -v launchctl >/dev/null 2>&1 || die "macOS 'launchctl' tool not found (not on macOS?)."
  green "  python3 $pyver, websockets, Claude Code, Bun, tmux, jq, security, launchctl: OK"
}

install_claude_plugin_runtime() {
  blue "Preparing the reviewed offline Claude Discord runtime."
  local command="install-runtime"
  [ "$SCRATCH" = "0" ] || command="verify"
  PYTHONPATH="$SCRIPT_DIR/conversations" \
    python3 "$SCRIPT_DIR/conversations/claude_plugin.py" "$command" >/dev/null || \
    die "Claude Discord offline runtime is unavailable or failed verification."
  green "  Plugin dependencies and Bun entrypoint are pinned for offline launch."
}

ensure_claude_discord_plugin() {
  blue "Checking the reviewed Anthropic Discord channel plugin."
  if ! "$CLAUDE_BIN" plugin list 2>/dev/null | grep -q 'discord@claude-plugins-official'; then
    [ "$SCRATCH" = "0" ] || \
      die "Scratch check failed: discord@claude-plugins-official is not installed."
    "$CLAUDE_BIN" plugin install discord@claude-plugins-official --scope user --yes >/dev/null
  fi
  "$CLAUDE_BIN" plugin list 2>/dev/null | grep -q 'discord@claude-plugins-official' || \
    die "The official Claude Discord plugin is not installed."
  PYTHONPATH="$SCRIPT_DIR/conversations" \
    python3 "$SCRIPT_DIR/conversations/claude_plugin.py" verify >/dev/null || \
    die "Claude Discord plugin is not an exact reviewed artifact. Review and bump the allowlist before updating it."
  green "  Official Discord channel plugin 0.0.4 is installed and digest-pinned."
}

# ----- token resolution -----

resolve_bot_token() {
  if [ -n "${DISCORD_BOT_TOKEN:-}" ]; then
    say "  Using DISCORD_BOT_TOKEN from environment."
    return 0
  fi
  local existing
  existing=$(env -u DISCORD_BOT_TOKEN security find-generic-password \
    -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w 2>/dev/null || true)
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
  env -u DISCORD_BOT_TOKEN security delete-generic-password \
    -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1 || true
  printf '%s\n' "$DISCORD_BOT_TOKEN" | env -u DISCORD_BOT_TOKEN security add-generic-password \
    -s "$KEYCHAIN_SERVICE" \
    -a "$KEYCHAIN_ACCOUNT" \
    -w \
    -U >/dev/null
  green "  Stored at service=$KEYCHAIN_SERVICE account=$KEYCHAIN_ACCOUNT."
}

clear_installer_token() {
  # Do not let the installer credential enter tmux's long-lived server
  # environment or any launchctl/bootstrap child. Runtime components resolve
  # their own narrow Keychain credential when they start.
  DISCORD_BOT_TOKEN=""
  unset DISCORD_BOT_TOKEN
}

# ----- cross-provider separation -----

load_cross_provider_state() {
  # Parse the preserved provider configuration before the installer creates
  # directories, installs plugins, changes Keychain, writes config, or touches
  # launchd. A pipe-delimited, fixed-width record avoids evaluating TOML data
  # as shell source.
  local target="$REPO_ROOT/config.toml"
  local record
  record="$(
    env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 \
      python3 - "$target" <<'PY'
import re
import sys
import tomllib
from pathlib import Path

path = Path(sys.argv[1])
empty = "-"
fields = ["0"] + [empty] * 9
if not path.exists():
    print("|".join(fields))
    raise SystemExit(0)

try:
    with path.open("rb") as stream:
        data = tomllib.load(stream)
except (OSError, tomllib.TOMLDecodeError) as exc:
    raise SystemExit("existing config.toml cannot be parsed safely") from exc

codex = data.get("codex", {})
if not isinstance(codex, dict):
    raise SystemExit("existing [codex] configuration is not a TOML table")
enabled = codex.get("enabled", False)
if type(enabled) is not bool:
    raise SystemExit("existing codex.enabled must be a TOML Boolean")
if not enabled:
    print("|".join(fields))
    raise SystemExit(0)

snowflake = re.compile(r"^[1-9][0-9]{16,19}$")
channel = str(codex.get("channel_id", ""))
if not snowflake.fullmatch(channel):
    raise SystemExit("enabled Codex provider has an invalid channel_id")

def keychain_binding(name: str, default: str) -> str:
    if name not in codex:
        return default
    value = codex[name]
    if not isinstance(value, str):
        raise SystemExit(f"enabled Codex provider has a non-string {name}")
    return value

service = keychain_binding("keychain_service", "discoparty-secret")
account = keychain_binding("keychain_account", "discord-bot-token-codex")
for label, value in (("keychain_service", service), ("keychain_account", account)):
    if (
        not value
        or len(value) > 256
        or "|" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SystemExit(f"enabled Codex provider has an invalid {label}")

discord = data.get("discord", {})
if not isinstance(discord, dict):
    raise SystemExit("existing [discord] configuration is not a TOML table")

def prior_id(name: str) -> str:
    value = str(discord.get(name, ""))
    return value if snowflake.fullmatch(value) else empty

fields = [
    "1",
    channel,
    service,
    account,
    prior_id("guild_id"),
    prior_id("chat_channel_id"),
    prior_id("errors_channel_id"),
    prior_id("owner_user_id"),
    prior_id("bot_user_id"),
    prior_id("application_id"),
]
print("|".join(fields))
PY
  )" || die "Could not inspect the preserved Codex provider before installation."

  IFS='|' read -r \
    CROSS_CODEX_ENABLED \
    CROSS_CODEX_CHANNEL_ID \
    CROSS_CODEX_KEYCHAIN_SERVICE \
    CROSS_CODEX_KEYCHAIN_ACCOUNT \
    CROSS_OLD_CLAUDE_GUILD_ID \
    CROSS_OLD_CLAUDE_CHAT_CHANNEL_ID \
    CROSS_OLD_CLAUDE_ERRORS_CHANNEL_ID \
    CROSS_OLD_CLAUDE_OWNER_USER_ID \
    CROSS_OLD_CLAUDE_BOT_USER_ID \
    CROSS_OLD_CLAUDE_APPLICATION_ID <<< "$record"

  case "${CROSS_CODEX_ENABLED:-}" in
    0|1) ;;
    *) die "Preserved provider inspection returned an invalid result." ;;
  esac
}

validate_cross_provider_channels() {
  [ "${CROSS_CODEX_ENABLED:-0}" = "1" ] || return 0
  [ "$DISCOPARTY_LISTEN_CHANNEL_ID" != "$CROSS_CODEX_CHANNEL_ID" ] || \
    die "Claude and Codex must use different Discord channels."
  [ "$DISCOPARTY_ERRORS_CHANNEL_ID" != "$CROSS_CODEX_CHANNEL_ID" ] || \
    die "The Claude errors channel must not be the Codex channel."
}

validate_cross_provider_tokens() {
  [ "${CROSS_CODEX_ENABLED:-0}" = "1" ] || return 0
  local codex_token
  codex_token="$(
    env -u DISCORD_BOT_TOKEN \
      security find-generic-password \
        -s "$CROSS_CODEX_KEYCHAIN_SERVICE" \
        -a "$CROSS_CODEX_KEYCHAIN_ACCOUNT" \
        -w 2>/dev/null
  )" || die "Enabled Codex provider token is missing from its configured Keychain item."
  [ -n "$codex_token" ] || \
    die "Enabled Codex provider token is empty in its configured Keychain item."

  if printf '%s\0%s\0' "$DISCORD_BOT_TOKEN" "$codex_token" | \
    env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 python3 -c '
import hmac
import sys

raw = sys.stdin.buffer.read(16386)
parts = raw.split(b"\0")
if len(raw) > 16384 or len(parts) != 3 or parts[-1] != b"":
    raise SystemExit(2)
left, right = parts[:2]
if any(character in b" \t\r\n\v\f" for character in left + right):
    raise SystemExit(2)
if not left or not right or len(left) > 4096 or len(right) > 4096:
    raise SystemExit(2)
raise SystemExit(0 if hmac.compare_digest(left, right) else 1)
'; then
    codex_token=""
    unset codex_token
    die "Claude and Codex must use different Discord bot tokens."
  else
    local compare_status=$?
    codex_token=""
    unset codex_token
    [ "$compare_status" = "1" ] || \
      die "Claude/Codex token separation could not be verified safely."
  fi
}

codex_provider_is_running() {
  local launchctl_bin
  launchctl_bin="$(command -v launchctl 2>/dev/null || true)"
  [ -n "$launchctl_bin" ] || \
    die "launchctl is required to verify the enabled Codex provider state."
  local label
  for label in \
    com.discoparty.codex-discord-bridge \
    com.thesystem.codex-discord-bridge; do
    if env -u DISCORD_BOT_TOKEN "$launchctl_bin" \
      print "gui/$UID/$label" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

validate_running_codex_routing() {
  codex_provider_is_running || return 0
  local unchanged=1
  [ "$CROSS_OLD_CLAUDE_GUILD_ID" = "$DISCOPARTY_DISCORD_GUILD_ID" ] || unchanged=0
  [ "$CROSS_OLD_CLAUDE_CHAT_CHANNEL_ID" = "$DISCOPARTY_LISTEN_CHANNEL_ID" ] || unchanged=0
  [ "$CROSS_OLD_CLAUDE_ERRORS_CHANNEL_ID" = "$DISCOPARTY_ERRORS_CHANNEL_ID" ] || unchanged=0
  [ "$CROSS_OLD_CLAUDE_OWNER_USER_ID" = "$DISCOPARTY_OWNER_USER_ID" ] || unchanged=0
  [ "$CROSS_OLD_CLAUDE_BOT_USER_ID" = "$DISCOPARTY_DISCORD_BOT_USER_ID" ] || unchanged=0
  [ "$CROSS_OLD_CLAUDE_APPLICATION_ID" = "$DISCOPARTY_DISCORD_APPLICATION_ID" ] || unchanged=0
  [ "$unchanged" = "1" ] || die \
    "Codex is running; stop it before changing Claude Discord routing or identity."
}

preflight_discord_identity() {
  blue "Pinning the Claude Discord bot, application, and guild identity."
  local identity
  identity="$(
    printf '%s\n' "$DISCORD_BOT_TOKEN" | \
      env -u DISCORD_BOT_TOKEN \
      PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH="$REPO_ROOT/conversations" \
      python3 "$REPO_ROOT/conversations/discord_identity.py" \
        --token-stdin \
        --chat-channel-id "$DISCOPARTY_LISTEN_CHANNEL_ID" \
        --errors-channel-id "$DISCOPARTY_ERRORS_CHANNEL_ID"
  )" || die "Claude Discord identity preflight failed."
  IFS=$'\t' read -r \
    DISCOPARTY_DISCORD_GUILD_ID \
    DISCOPARTY_DISCORD_BOT_USER_ID \
    DISCOPARTY_DISCORD_APPLICATION_ID <<< "$(
      printf '%s' "$identity" | \
        env -u DISCORD_BOT_TOKEN PYTHONDONTWRITEBYTECODE=1 python3 -c '
import json, sys
value = json.load(sys.stdin)
print(value["guild_id"], value["bot_user_id"], value["application_id"], sep="\t")
'
    )"
  export DISCOPARTY_DISCORD_GUILD_ID
  export DISCOPARTY_DISCORD_BOT_USER_ID
  export DISCOPARTY_DISCORD_APPLICATION_ID
  green "  Discord principal and guild are pinned."
}

preflight_discord_permissions() {
  local state_mode="${1:-strict}"
  local -a permission_args=(
    verify
    --token-stdin
    --guild-id "$DISCOPARTY_DISCORD_GUILD_ID"
    --chat-channel-id "$DISCOPARTY_LISTEN_CHANNEL_ID"
    --errors-channel-id "$DISCOPARTY_ERRORS_CHANNEL_ID"
    --bot-user-id "$DISCOPARTY_DISCORD_BOT_USER_ID"
    --application-id "$DISCOPARTY_DISCORD_APPLICATION_ID"
    --conversations-dir "$CONVERSATIONS_DIR"
  )
  case "$state_mode" in
    strict) ;;
    allow-legacy-readonly) permission_args+=(--allow-legacy-readonly-state) ;;
    *) die "Unknown Discord permission preflight mode: $state_mode" ;;
  esac
  blue "Verifying the Claude Discord bot's least-privilege boundary."
  printf '%s\n' "$DISCORD_BOT_TOKEN" | \
    env -u DISCORD_BOT_TOKEN \
      PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH="$REPO_ROOT/conversations" \
      python3 "$REPO_ROOT/conversations/discord_permissions.py" \
        "${permission_args[@]}" \
        >/dev/null || die "Claude Discord least-privilege preflight failed."
  green "  Discord identity, guild membership, channels, threads, and permissions are verified."
}

harden_claude_state_modes() {
  blue "Hardening Claude transcript, registry, and queue state modes."
  env -u DISCORD_BOT_TOKEN \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$REPO_ROOT/conversations" \
    python3 "$REPO_ROOT/conversations/discord_permissions.py" harden-state \
      --conversations-dir "$CONVERSATIONS_DIR" \
      >/dev/null || die "Claude state mode migration failed."
  green "  Claude local state is current-user private."
}

preflight_shared_skills() {
  blue "Verifying the explicit shared Vault skill source."
  PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$REPO_ROOT/conversations" \
    python3 "$REPO_ROOT/conversations/shared_skills.py" verify \
      --root "$WORKSPACE_ROOT" >/dev/null || \
    die "Workspace root must expose the reviewed shared Vault skills without enabled plugins."
  green "  Claude skill discovery is limited to the configured shared Vault root."
}

# ----- config.toml -----

confirm_config_write_and_authority() {
  local target="$REPO_ROOT/config.toml"
  if [ -f "$target" ] && [ "$REINSTALL" != "1" ] && [ "$NON_INTERACTIVE" != "1" ]; then
    local overwrite
    read -r -p "  $target exists. Replace its Claude settings? [y/N]: " overwrite
    case "$overwrite" in
      y|Y|yes|Yes|YES) ;;
      *) die "Existing config.toml was not approved for replacement; no installation changes were made." ;;
    esac
  fi

  local existing_mode="missing"
  if [ -f "$target" ]; then
    existing_mode="$(python3 - "$target" <<'PY'
import sys
import tomllib
from pathlib import Path

with Path(sys.argv[1]).open("rb") as stream:
    value = tomllib.load(stream).get("runtime", {}).get(
        "use_dangerously_skip_permissions", False
    )
if not isinstance(value, bool):
    raise SystemExit("existing Claude authority mode is not a TOML boolean")
print("true" if value else "false")
PY
)" || die "Existing config.toml has an invalid Claude authority mode."
  fi

  if [ "${DISCOPARTY_CLAUDE_FULL_AUTHORITY:-}" = "1" ]; then
    CLAUDE_FULL_AUTHORITY=1
  elif [ "$existing_mode" = "true" ]; then
    CLAUDE_FULL_AUTHORITY=1
    say "  Preserving the existing explicit full-local-authority setting."
  elif [ "$NON_INTERACTIVE" = "1" ]; then
    die "Claude listener requires explicit full local authority. Set DISCOPARTY_CLAUDE_FULL_AUTHORITY=1 after reviewing the risk."
  else
    yellow "  The Claude listener executes owner-approved Discord work with full access to this Mac account."
    yellow "  Discord content can therefore cause local file, process, and application actions."
    local acceptance
    read -r -p "  Type FULL LOCAL AUTHORITY to accept and start it: " acceptance
    [ "$acceptance" = "FULL LOCAL AUTHORITY" ] || \
      die "Full local authority was not explicitly accepted; no installation changes were made."
    CLAUDE_FULL_AUTHORITY=1
  fi
}

write_config_toml() {
  local target="$REPO_ROOT/config.toml"
  [ "$CLAUDE_FULL_AUTHORITY" = "1" ] || die "Claude full authority was not accepted."
  local codex_block=""
  if [ -f "$target" ]; then
    codex_block="$(python3 - "$target" <<'PY'
import sys
import tomllib
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text()
data = tomllib.loads(text)
if "codex" not in data:
    raise SystemExit(0)
if not isinstance(data["codex"], dict):
    raise SystemExit("existing codex configuration is not a TOML table")


def table_name(line: str) -> str | None:
    stripped = line.lstrip()
    if stripped.startswith("[["):
        end = stripped.find("]]", 2)
        return None if end < 0 else stripped[2:end].strip()
    if stripped.startswith("["):
        end = stripped.find("]", 1)
        return None if end < 0 else stripped[1:end].strip()
    return None


def top_level(name: str) -> str:
    return name.split(".", 1)[0].strip().strip("\"'")


lines = text.splitlines()
starts = [
    index
    for index, line in enumerate(lines)
    if (name := table_name(line)) is not None and name.strip().strip("\"'") == "codex"
]
if len(starts) != 1:
    raise SystemExit("cannot safely locate exactly one existing [codex] table")

start = starts[0]
end = len(lines)
for index in range(start + 1, len(lines)):
    name = table_name(lines[index])
    if name is not None and top_level(name) != "codex":
        end = index
        break

print("\n".join(lines[start:end]).rstrip())
PY
)"
  fi

  local temporary
  temporary="$(mktemp "${target}.tmp.XXXXXX")"
  cat > "$temporary" <<EOF
# Generated by install.sh on $(date -u "+%Y-%m-%dT%H:%M:%SZ")

[paths]
workspace_root = "$WORKSPACE_ROOT"
conversations_dir = "$CONVERSATIONS_DIR"

[discord]
guild_id = "$DISCOPARTY_DISCORD_GUILD_ID"
chat_channel_id = "$DISCOPARTY_LISTEN_CHANNEL_ID"
errors_channel_id = "$DISCOPARTY_ERRORS_CHANNEL_ID"
owner_user_id = "$DISCOPARTY_OWNER_USER_ID"
bot_user_id = "$DISCOPARTY_DISCORD_BOT_USER_ID"
application_id = "$DISCOPARTY_DISCORD_APPLICATION_ID"
token_env_var = "DISCORD_BOT_TOKEN"
keychain_service = "$KEYCHAIN_SERVICE"
keychain_account = "$KEYCHAIN_ACCOUNT"
plugin_state_dir = "$HOME/Library/Application Support/Discoparty/claude-discord"

[runtime]
timezone = "${DISCOPARTY_TIMEZONE:-UTC}"
max_messages_per_minute = 5
max_messages_per_hour = 30
max_concurrent_workers = 3
use_dangerously_skip_permissions = true
EOF
  if [ -n "$codex_block" ]; then
    printf '\n%s\n' "$codex_block" >> "$temporary"
  fi
  if ! python3 - "$temporary" <<'PY'
import sys
import tomllib
from pathlib import Path

with Path(sys.argv[1]).open("rb") as stream:
    tomllib.load(stream)
PY
  then
    rm -f "$temporary"
    die "Generated config.toml is invalid; the existing file was left unchanged."
  fi
  mv -f "$temporary" "$target"
  green "  Wrote $target."
}

install_claude_discord_access() {
  blue "Removing any retired plaintext token copy and installing the static owner allowlist."
  PYTHONPATH="$REPO_ROOT/conversations" \
    python3 "$REPO_ROOT/conversations/discord_access.py" install >/dev/null
  CLAUDE_ACCESS_INSTALLED=1
  export CLAUDE_ACCESS_INSTALLED
  green "  Claude Discord ingress is limited to the configured owner and #chat."
  green "  No Discord token is stored in the plugin state directory."
}

install_claude_vault_policy() {
  local state_root="$HOME/Library/Application Support/Discoparty/claude-discord"
  blue "Sealing the canonical Vault P0 policy for the Claude listener and workers."
  env -u DISCORD_BOT_TOKEN \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="$REPO_ROOT/conversations" \
    python3 "$REPO_ROOT/conversations/listener_contract.py" \
      seal-runtime-policy \
      --vault-root "$WORKSPACE_ROOT" \
      --runtime-root "$state_root" \
      --bootstrap-workspace "$REPO_ROOT/cx-chat-listener" \
      --path "$REPO_ROOT/cx-chat-listener/CLAUDE.md" \
      >/dev/null || die "Could not seal the canonical Vault P0 policy."
  green "  Claude startup is bound to the private source and snapshot hashes."
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
    "$REPO_ROOT/launchd/templates/com.discoparty.cx-chat-healthcheck.plist.template" \
    "$LABEL_PREFIX.cx-chat-healthcheck" \
    "$agents_dir/$LABEL_PREFIX.cx-chat-healthcheck.plist" \
    "$python_bin"

  render_plist \
    "$REPO_ROOT/launchd/templates/com.discoparty.discord-gateway-client.plist.template" \
    "$LABEL_PREFIX.discord-gateway-client" \
    "$agents_dir/$LABEL_PREFIX.discord-gateway-client.plist" \
    "$python_bin"
}

remove_stale_marker_watcher() {
  # The legacy watcher competes with request_approval.py for the same marker
  # and can consume a Reject decision first. It is not part of the supported
  # runtime; remove it before installing the gateway and listener services.
  local label="$LABEL_PREFIX.discord-marker-watcher"
  local domain="gui/$UID"
  local plist="$HOME/Library/LaunchAgents/$label.plist"
  blue "Removing the obsolete Discord marker watcher."
  if env -u DISCORD_BOT_TOKEN launchctl \
    print "$domain/$label" >/dev/null 2>&1; then
    env -u DISCORD_BOT_TOKEN launchctl \
      bootout "$domain/$label" >/dev/null 2>&1 || \
      die "Could not unload obsolete $label; installation stopped."
    if env -u DISCORD_BOT_TOKEN launchctl \
      print "$domain/$label" >/dev/null 2>&1; then
      die "Obsolete $label is still loaded after bootout."
    fi
  fi
  [ ! -d "$plist" ] || die "Obsolete marker watcher plist path is a directory: $plist"
  rm -f "$plist" || die "Could not remove obsolete marker watcher plist: $plist"
  [ ! -e "$plist" ] && [ ! -L "$plist" ] || \
    die "Obsolete marker watcher plist still exists: $plist"
  if env -u DISCORD_BOT_TOKEN launchctl \
    print "$domain/$label" >/dev/null 2>&1; then
    die "Obsolete $label remained loaded after cleanup."
  fi
  green "  Obsolete marker watcher is absent."
}

bootstrap_agents() {
  if [ "$SCRATCH" = "1" ]; then
    yellow "  --scratch mode: skipping launchctl bootstrap."
    return 0
  fi
  blue "Bootstrapping launchd agents."
  local agents_dir="$HOME/Library/LaunchAgents"
  for component in cx-chat-healthcheck discord-gateway-client; do
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
  blue "Starting and proving listener readiness for '$TMUX_SESSION'."
  [ -x "$REPO_ROOT/cx-launcher.sh" ] || die "cx-launcher.sh is not executable."
  DISCOPARTY_REPO_ROOT="$REPO_ROOT" \
    DISCOPARTY_CONFIG="$REPO_ROOT/config.toml" \
    DISCOPARTY_TMUX_SESSION="$TMUX_SESSION" \
    /bin/bash "$REPO_ROOT/launchd/cx-chat-healthcheck.sh" || \
    die "Claude listener did not prove exact session and protocol readiness."
  green "  Listener session '$TMUX_SESSION' is running with the pinned protocol."
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

assert_no_legacy_claude_footprint() {
  # The pre-Disco Party deployment consumes the same Discord events through
  # com.thesystem jobs and the cx-chat tmux listener. Never install a second
  # consumer beside it; migration requires its own staged rollback procedure.
  local -a found=()
  local label plist
  for label in \
    com.thesystem.cx-chat-healthcheck \
    com.thesystem.cx-chat-listener \
    com.thesystem.cx-chat-queue-monitor \
    com.thesystem.cx-chat-archive-sync \
    com.thesystem.discord-gateway-client \
    com.thesystem.discord-marker-watcher; do
    plist="$HOME/Library/LaunchAgents/$label.plist"
    if [ -e "$plist" ] || [ -L "$plist" ]; then
      found+=("$label.plist")
    elif env -u DISCORD_BOT_TOKEN launchctl \
      print "gui/$UID/$label" >/dev/null 2>&1; then
      found+=("$label (loaded)")
    fi
  done
  if env -u DISCORD_BOT_TOKEN tmux has-session -t '=cx-chat' >/dev/null 2>&1; then
    found+=("tmux:cx-chat")
  fi
  local process_id process_command
  while read -r process_id process_command; do
    [[ "$process_id" =~ ^[0-9]+$ ]] || continue
    [ "$process_id" != "$$" ] || continue
    case "$process_command" in
      *"/TheSystem/x_System/Assistant/conversations/scripts/queue/drainer.py"*|\
      *"/TheSystem/x_System/Assistant/conversations/scripts/queue/monitor.py"*|\
      *"/TheSystem/x_System/Assistant/conversations/scripts/sync-discord-archive-state.py"*|\
      *"/TheSystem/x_System/Assistant/scripts/run-cron.sh cx-chat-archive-sync"*)
        found+=("process:$process_id")
        ;;
    esac
  done < <(/bin/ps -axo pid=,command= 2>/dev/null || true)
  [ "${#found[@]}" = "0" ] || die \
    "Legacy Claude Discord footprint detected (${found[*]}). Stop and migrate it explicitly before installing Disco Party; automatic takeover is disabled."
}

# ----- main -----

main() {
  # Keep a caller-supplied credential available to this shell without passing
  # it through every prerequisite, parser, launchctl, or plugin child.
  export -n DISCORD_BOT_TOKEN 2>/dev/null || true

  say "Disco Party installer (label prefix: $LABEL_PREFIX, scratch: $SCRATCH)"
  say

  if [ -e "$SCRIPT_DIR/.discoparty.env" ] || [ -L "$SCRIPT_DIR/.discoparty.env" ]; then
    die ".discoparty.env is not loaded because credential files are forbidden. Move non-secret defaults to the process environment and store bot tokens only in Keychain."
  fi

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
  if [ "$TAKE_OVER_LEGACY" != "1" ]; then
    assert_no_legacy_claude_footprint
  fi

  collect_takeover_authorization

  prompt REPO_ROOT "Repo root" "$DEFAULT_REPO_ROOT"
  REPO_ROOT="${REPO_ROOT/#~/$HOME}"
  [ -d "$REPO_ROOT" ] || die "Repo root does not exist: $REPO_ROOT"
  confirm_config_write_and_authority
  load_cross_provider_state

  local default_workspace="$HOME/.discoparty"
  if [ -d "$HOME/TheSystem/x_System/Skills" ]; then
    default_workspace="$HOME/TheSystem"
  fi
  prompt WORKSPACE_ROOT "Shared Vault root" "$default_workspace"
  WORKSPACE_ROOT="${WORKSPACE_ROOT/#~/$HOME}"
  if [ "$TAKE_OVER_LEGACY" = "1" ]; then
    CONVERSATIONS_DIR="${DISCOPARTY_CONVERSATIONS_DIR:-$WORKSPACE_ROOT/x_System/Assistant/conversations}"
  else
    CONVERSATIONS_DIR="${DISCOPARTY_CONVERSATIONS_DIR:-$WORKSPACE_ROOT/conversations}"
  fi
  CONVERSATIONS_DIR="${CONVERSATIONS_DIR/#~/$HOME}"
  preflight_shared_skills
  collect_quarantine_authorization

  prompt DISCOPARTY_LISTEN_CHANNEL_ID "Discord listen channel id" ""
  prompt DISCOPARTY_ERRORS_CHANNEL_ID "Discord errors channel id" "${DISCOPARTY_LISTEN_CHANNEL_ID:-}"
  prompt DISCOPARTY_OWNER_USER_ID "Discord owner user id (your user id)" ""
  prompt DISCOPARTY_TIMEZONE "Timezone (IANA name)" "America/New_York"
  validate_cross_provider_channels

  resolve_bot_token
  export -n DISCORD_BOT_TOKEN 2>/dev/null || true
  validate_cross_provider_tokens
  preflight_discord_identity
  preflight_discord_permissions allow-legacy-readonly
  validate_running_codex_routing

  # All cross-provider checks above are read-only. Persistent installation
  # changes begin only after channels, credentials, permissions, and the
  # running-provider routing boundary have passed.
  prepare_legacy_takeover
  remove_stale_marker_watcher
  ensure_claude_discord_plugin
  install_claude_plugin_runtime
  mkdir -p "$CONVERSATIONS_DIR"
  harden_claude_state_modes
  write_config_toml
  install_claude_discord_access
  install_claude_vault_policy
  preflight_discord_permissions strict
  store_token_in_keychain
  clear_installer_token
  verify_listener_cwd || true
  install_plists
  begin_takeover_replacement
  bootstrap_agents
  start_listener_session
  finalize_legacy_takeover

  green
  green "Done."
  say
  say "Summary:"
  say "  Repo root:        $REPO_ROOT"
  say "  Workspace root:   $WORKSPACE_ROOT"
  say "  Conversations:    $CONVERSATIONS_DIR"
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
