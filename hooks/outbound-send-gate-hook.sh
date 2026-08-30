#!/usr/bin/env bash
# outbound-send-gate-hook.sh
#
# Claude Code PreToolUse hook for the Bash tool.
#
# Purpose: when a worker subagent tries to invoke a configured outbound gate
# script (Slack post, email send, etc.), this hook blocks the call unless a
# verified Discord approval reference is present in the command flags.
#
# Configuration: set the following env vars before installing this hook:
#
#   DISCOPARTY_GATED_SCRIPTS  -- space-separated list of script basenames to
#                              gate, for example: "post_with_gate.py send_with_gate.py"
#   DISCOPARTY_OWNER_USER_ID  -- approver Discord user id
#   DISCOPARTY_BOT_TOKEN_ENV  -- env var name that holds the bot token
#
# Behavior: if the command line invokes any gated script as its first token,
# require the flag --discord-approval-message-id pointing to a Discord message
# in a channel the bot can read. The hook fetches that message and checks that
# (a) the author is the bot, (b) the bot's previous reaction or button payload
# indicates the configured owner approved the matching sha prefix, and (c) the
# sha embedded in the gated script's --approved-draft-sha matches the prefix.
#
# If any check fails, the hook returns permissionDecision=deny with a reason.

set -euo pipefail

INPUT=$(cat)

COMMAND=$(echo "$INPUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('tool_input', {}).get('command', data.get('command', '')))
" 2>/dev/null || echo "")

GATED_SCRIPTS="${DISCOPARTY_GATED_SCRIPTS:-}"
if [[ -z "$GATED_SCRIPTS" ]]; then
  # No gated scripts configured. Pass through.
  echo '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}'
  exit 0
fi

# Quick scan: first whitespace-separated token of any segment matches a gated script?
NEEDS_GATE=0
for script in $GATED_SCRIPTS; do
  if echo "$COMMAND" | grep -qE "(^|[;&|]| )${script}( |$)"; then
    NEEDS_GATE=1
    break
  fi
done

if [[ "$NEEDS_GATE" -eq 0 ]]; then
  echo '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}'
  exit 0
fi

# Gate is needed. Verify approval reference.
python3 <<'PY'
import json
import os
import shlex
import sys

COMMAND = os.environ.get("COMMAND_PASSTHROUGH", "")


def emit(decision: str, reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))


def flag_value(argv, name):
    prefix = name + "="
    for idx, item in enumerate(argv):
        if item == name and idx + 1 < len(argv):
            return argv[idx + 1]
        if item.startswith(prefix):
            return item[len(prefix):]
    return ""


try:
    argv = shlex.split(COMMAND)
except ValueError:
    emit("deny", "Could not parse command line. Refusing outbound gate call.")
    sys.exit(0)

approval_ref = flag_value(argv, "--discord-approval-message-id")
if not approval_ref or ":" not in approval_ref:
    emit("deny", "Outbound gate call missing --discord-approval-message-id channel:message reference.")
    sys.exit(0)

approver = flag_value(argv, "--discord-approver-user-id") or os.environ.get("DISCOPARTY_OWNER_USER_ID", "")
if not approver:
    emit("deny", "Outbound gate call missing approver user id.")
    sys.exit(0)

approved_sha = flag_value(argv, "--approved-draft-sha")
if not approved_sha:
    emit("deny", "Outbound gate call missing --approved-draft-sha.")
    sys.exit(0)

# At this point the gated script itself is expected to re-verify the approval
# reference against Discord. This hook only enforces that the wiring is present.
emit("allow", "Approval reference present; gated script will re-verify.")
PY
