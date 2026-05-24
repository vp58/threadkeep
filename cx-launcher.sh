#!/usr/bin/env bash
# cx-launcher.sh
#
# Helper script that the tmux session started by the healthcheck runs to
# launch Claude Code with the Discord plugin attached. This wrapper exists
# so the launch command lives in one place and so the bot token can be
# resolved from the macOS Keychain (or fallback sources) before exec.
#
# Resolution order for DISCORD_BOT_TOKEN:
#   1. If DISCORD_BOT_TOKEN is already set in the environment, use it.
#   2. macOS Keychain (security find-generic-password) under
#      service "threadkeep-secret", account "discord-bot-token".
#   3. THREADKEEP_TOKEN_FILE, if set and the file exists and is readable.
#
# The script exec's the Claude Code CLI in subscription (interactive) mode.
# Threadkeep deliberately runs Claude Code as a subscription session, not
# via the Anthropic API or the Agent SDK, to avoid API consumption costs.

set -u

REPO_ROOT="${THREADKEEP_REPO_ROOT:-$(cd "$(dirname "$0")" && pwd)}"
export THREADKEEP_REPO_ROOT="$REPO_ROOT"
export THREADKEEP_CONFIG="${THREADKEEP_CONFIG:-$REPO_ROOT/config.toml}"

KEYCHAIN_SERVICE="${THREADKEEP_KEYCHAIN_SERVICE:-threadkeep-secret}"
KEYCHAIN_ACCOUNT="${THREADKEEP_KEYCHAIN_ACCOUNT:-discord-bot-token}"

resolve_token() {
  if [ -n "${DISCORD_BOT_TOKEN:-}" ]; then
    echo "$DISCORD_BOT_TOKEN"
    return 0
  fi
  if command -v security >/dev/null 2>&1; then
    local val
    val=$(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w 2>/dev/null || true)
    if [ -n "$val" ]; then
      echo "$val"
      return 0
    fi
  fi
  if [ -n "${THREADKEEP_TOKEN_FILE:-}" ] && [ -r "$THREADKEEP_TOKEN_FILE" ]; then
    head -n1 "$THREADKEEP_TOKEN_FILE"
    return 0
  fi
  return 1
}

TOKEN=$(resolve_token || true)
if [ -z "${TOKEN:-}" ]; then
  echo "cx-launcher: no Discord bot token found." >&2
  echo "  Tried: DISCORD_BOT_TOKEN env, Keychain ($KEYCHAIN_SERVICE/$KEYCHAIN_ACCOUNT), THREADKEEP_TOKEN_FILE." >&2
  exit 2
fi
export DISCORD_BOT_TOKEN="$TOKEN"

CLAUDE_BIN="${CLAUDE_BIN:-claude}"
if ! command -v "$CLAUDE_BIN" >/dev/null 2>&1; then
  echo "cx-launcher: '$CLAUDE_BIN' not on PATH. Install Claude Code CLI first." >&2
  echo "  See https://docs.claude.com/claude-code for install instructions." >&2
  exit 3
fi

USE_SKIP_PERMISSIONS=0
if command -v python3 >/dev/null 2>&1; then
  USE_SKIP_PERMISSIONS=$(PYTHONPATH="$REPO_ROOT/conversations" python3 - <<'PY' 2>/dev/null || echo 0
from config import CONFIG
print("1" if CONFIG.runtime.use_dangerously_skip_permissions else "0")
PY
)
fi

CLAUDE_ARGS=("--channels" "plugin:discord@claude-plugins-official")
if [ "$USE_SKIP_PERMISSIONS" = "1" ]; then
  CLAUDE_ARGS=("--dangerously-skip-permissions" "${CLAUDE_ARGS[@]}")
fi

cd "$REPO_ROOT"
exec "$CLAUDE_BIN" "${CLAUDE_ARGS[@]}"
