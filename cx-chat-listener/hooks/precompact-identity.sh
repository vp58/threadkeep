#!/usr/bin/env bash
# precompact-identity.sh
#
# Claude Code PreCompact hook. Fires right before /compact runs. Two jobs:
#
#   1. Touch a sentinel file so we can observe when the hook fired.
#   2. Emit the cx-chat listener identity verbatim on stdout, wrapped in a
#      JSON `hookSpecificOutput.additionalContext` block so Claude Code
#      injects it into the compaction summary. This guarantees the cx-chat
#      protocol survives /compact, even if the cwd CLAUDE.md mechanism is
#      somehow bypassed.
#
# Gated on cwd: only runs when the session cwd is the cx-chat-listener subdir
# OF THE CONFIGURED THREADKEEP REPO. Other Claude Code sessions are unaffected.
#
# To register this hook, copy or symlink the rendered settings entry from
# `docs/SETUP.md` step "Identity persistence hooks" into your user-scoped
# `~/.claude/settings.local.json`. The installer can do this for you via the
# `--install-hooks` flag (see install.sh).
#
# Input on stdin (JSON):
#   {
#     "session_id": "...",
#     "transcript_path": "...",
#     "cwd": "...",
#     "hook_event_name": "PreCompact",
#     "trigger": "manual" | "auto",
#     "custom_instructions": "..."
#   }

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTENER_DIR="$(cd "$HERE/.." && pwd)"
IDENTITY_FILE="$LISTENER_DIR/CLAUDE.md"
SENTINEL="${THREADKEEP_PRECOMPACT_SENTINEL:-/tmp/threadkeep-cx-chat-precompact-marker}"

INPUT=$(cat)

CWD=$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get("cwd",""))
except Exception:
    print("")' 2>/dev/null)

case "$CWD" in
  "$LISTENER_DIR"|"$LISTENER_DIR"/*)
    ;;
  *)
    printf '{}\n'
    exit 0
    ;;
esac

date "+%Y-%m-%d %H:%M:%S %Z" > "$SENTINEL" 2>/dev/null || true

if [ ! -r "$IDENTITY_FILE" ]; then
  printf '{}\n'
  exit 0
fi

IDENTITY_FILE="$IDENTITY_FILE" python3 <<'PY'
import json, os
identity = open(os.environ["IDENTITY_FILE"]).read()
payload = {
    "hookSpecificOutput": {
        "hookEventName": "PreCompact",
        "additionalContext": (
            "CX-CHAT IDENTITY RESET (PreCompact hook): you are the Threadkeep "
            "cx-chat listener. Top-level posts in the configured listen channel "
            "go through dispatch.py and spawn a worker via the Agent tool. "
            "Never reply inline. Full protocol below.\n\n"
            + identity
        ),
    }
}
print(json.dumps(payload))
PY

exit 0
