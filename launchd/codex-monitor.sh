#!/usr/bin/env bash

# Read-only local view of the Codex Discord job ledger. The LaunchAgent owns
# the bridge process. Closing this monitor does not stop Discord intake.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${DISCOPARTY_REPO_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PYTHON_BIN="${DISCOPARTY_PYTHON_BIN:-$(command -v python3)}"

export DISCOPARTY_REPO_ROOT="$REPO_ROOT"
export DISCOPARTY_CONFIG="${DISCOPARTY_CONFIG:-$REPO_ROOT/config.toml}"
export PYTHONPATH="$REPO_ROOT"
export PYTHONUNBUFFERED=1

# The monitor only reads SQLite. It never needs provider or Discord secrets.
unset OPENAI_API_KEY DISCOPARTY_CODEX_DISCORD_BOT_TOKEN DISCORD_BOT_TOKEN || true

cd "$REPO_ROOT"
exec "$PYTHON_BIN" -m codex_discord_bridge.monitor "$@"
