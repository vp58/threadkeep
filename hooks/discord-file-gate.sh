#!/usr/bin/env bash
# Discord file attachment gate.
#
# Claude Code PreToolUse hook for mcp__plugin_discord_discord__reply. Allows
# the Discord plugin to attach files only when every path in
# tool_input.files lives under one of the explicitly approved root
# directories. Without this gate, a prompt-injected Discord message could
# coerce a worker into uploading arbitrary local files as attachments.
#
# Configuration: edit ALLOWED_PREFIXES below to match the local install.
# Each prefix is matched as a literal path prefix (so include the trailing
# slash). ".." segments are rejected outright to block path traversal.
#
# Hook output convention:
#   - Allow:  `exit 0` with empty stdout. Claude Code's hook schema treats an
#             empty stdout as "no opinion, allow". Returning a JSON allow object
#             from a PreToolUse hook fails schema validation on current builds.
#   - Block:  `exit 0` with a JSON `{"decision":"block","reason":"..."}` body.

set -u

ALLOWED_PREFIXES=(
  "__HOME__/Desktop/"
  "__HOME__/Downloads/"
  "/tmp/"
)

INPUT=$(cat)

FILES_JSON=$(printf '%s' "$INPUT" | jq -c '.tool_input.files? // []' 2>/dev/null)
if [ -z "$FILES_JSON" ] || [ "$FILES_JSON" = "[]" ] || [ "$FILES_JSON" = "null" ]; then
  # No attachments. Allow.
  exit 0
fi

block() {
  reason=$1
  printf '{"decision":"block","reason":%s}' "$(printf '%s' "$reason" | jq -Rs .)"
  exit 0
}

while IFS= read -r path; do
  [ -z "$path" ] && continue
  case "$path" in
    *..*) block "DISCORD FILE ATTACHMENT BLOCKED: Path '$path' contains '..' (traversal not allowed)." ;;
    /*) ;;
    *) block "DISCORD FILE ATTACHMENT BLOCKED: Path '$path' is not absolute. Allowlist only matches absolute paths." ;;
  esac
  matched=0
  for prefix in "${ALLOWED_PREFIXES[@]}"; do
    # Expand a literal __HOME__ token at runtime so the file is portable.
    expanded=${prefix//__HOME__/$HOME}
    case "$path" in
      "$expanded"*) matched=1; break ;;
    esac
  done
  if [ $matched -eq 0 ]; then
    block "DISCORD FILE ATTACHMENT BLOCKED: Path '$path' is not in the approved allowlist. Edit hooks/discord-file-gate.sh to add a new root."
  fi
done < <(printf '%s' "$FILES_JSON" | jq -r '.[]')

# All paths in tool_input.files passed the allowlist. Allow.
exit 0
