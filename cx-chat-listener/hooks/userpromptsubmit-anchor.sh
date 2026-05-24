#!/usr/bin/env bash
# userpromptsubmit-anchor.sh
#
# Claude Code UserPromptSubmit hook. Fires on every user prompt before the
# model processes it. We use it as a defensive per-message identity anchor:
# if cwd is the cx-chat-listener subdir, we inject one terse line reminding
# the session it is cx-chat. Cheap belt-and-suspenders on top of the cwd
# CLAUDE.md and PreCompact mechanisms.
#
# Gated on cwd: only runs when the session cwd is the cx-chat-listener subdir
# OF THE CONFIGURED THREADKEEP REPO. Other Claude Code sessions are unaffected.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTENER_DIR="$(cd "$HERE/.." && pwd)"

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

python3 <<'PY'
import json
payload = {
    "hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": (
            "Remember: you are the Threadkeep cx-chat listener. Top-level "
            "posts in the configured listen channel go through dispatch.py, "
            "never reply inline."
        ),
    }
}
print(json.dumps(payload))
PY

exit 0
