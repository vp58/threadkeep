#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_ROOT="$(mktemp -d "$HOME/.threadkeep-codex-uninstall-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

TEST_HOME="$TEST_ROOT/home"
TEST_REPO="$TEST_HOME/repo"
FAKE_BIN="$TEST_ROOT/bin"
PLIST="$TEST_HOME/Library/LaunchAgents/com.threadkeep.codex-discord-bridge.plist"
KEYCHAIN="$TEST_HOME/.fake-keychain-discord-bot-token-codex"
CHATGPT_LOGIN="$TEST_HOME/.fake-codex-chatgpt-login"
LAUNCH_STATE="$TEST_ROOT/launch-state"
ORDER_LOG="$TEST_ROOT/order.log"
SECRET_VALUE='must-not-reach-an-uninstall-child'
mkdir -p "$TEST_REPO" "$FAKE_BIN" "$(dirname "$PLIST")"
cp "$REPO_ROOT/uninstall.sh" "$TEST_REPO/uninstall.sh"
chmod 755 "$TEST_REPO/uninstall.sh"
touch "$TEST_REPO/config.toml"

cat > "$FAKE_BIN/assert-clean" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for name in DISCORD_BOT_TOKEN THREADKEEP_CODEX_DISCORD_BOT_TOKEN OPENAI_API_KEY; do
  [ "${!name+x}" != "x" ] || exit 91
done
for entry in $(/usr/bin/env); do
  [[ "$entry" != *"must-not-reach-an-uninstall-child"* ]] || exit 92
done
EOF

cat > "$FAKE_BIN/launchctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
"$THREADKEEP_TEST_ASSERT_CLEAN"
printf 'launchctl %s\n' "$*" >> "$THREADKEEP_TEST_ORDER_LOG"
case "${1:-}" in
  print) [ "$(cat "$THREADKEEP_TEST_LAUNCH_STATE" 2>/dev/null || true)" = loaded ] ;;
  bootout) printf '%s\n' stopped > "$THREADKEEP_TEST_LAUNCH_STATE" ;;
  *) exit 2 ;;
esac
EOF

cat > "$FAKE_BIN/security" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
"$THREADKEEP_TEST_ASSERT_CLEAN"
printf 'security %s\n' "$*" >> "$THREADKEEP_TEST_ORDER_LOG"
case "${1:-}" in
  find-generic-password) [ -f "$THREADKEEP_TEST_KEYCHAIN" ] ;;
  delete-generic-password) rm -f "$THREADKEEP_TEST_KEYCHAIN" ;;
  *) exit 2 ;;
esac
EOF

cat > "$FAKE_BIN/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
"$THREADKEEP_TEST_ASSERT_CLEAN"
[ "${1:-}" = -m ]
[ "${2:-}" = codex_discord_bridge.codex_auth ]
[ "${3:-}" = logout-configured ]
[ "$HOME" = "$THREADKEEP_TEST_EXPECT_REAL_HOME" ]
[ "$THREADKEEP_CONFIG" = "$THREADKEEP_TEST_EXPECT_CONFIG" ]
printf '%s\n' logout >> "$THREADKEEP_TEST_ORDER_LOG"
[ "${THREADKEEP_TEST_AUTH_LOGOUT_FAIL:-0}" != 1 ] || exit 95
rm -f "$THREADKEEP_TEST_AUTH_LOGOUT_MARKER"
printf '%s\n' 'Isolated ChatGPT logout verified.'
EOF

cat > "$FAKE_BIN/tmux" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
"$THREADKEEP_TEST_ASSERT_CLEAN"
case "${1:-}" in
  has-session) exit 1 ;;
  *) exit 2 ;;
esac
EOF
chmod 755 "$FAKE_BIN"/*

COMMON_ENV=(
  "HOME=$TEST_HOME"
  "PATH=$FAKE_BIN:/usr/bin:/bin"
  "THREADKEEP_TEST_MODE=1"
  "THREADKEEP_TEST_SECURITY_BIN=$FAKE_BIN/security"
  "THREADKEEP_TEST_LAUNCHCTL_BIN=$FAKE_BIN/launchctl"
  "THREADKEEP_TEST_PYTHON_BIN=$FAKE_BIN/python3"
  "THREADKEEP_TEST_ASSERT_CLEAN=$FAKE_BIN/assert-clean"
  "THREADKEEP_TEST_EXPECT_REAL_HOME=$TEST_HOME"
  "THREADKEEP_TEST_EXPECT_CONFIG=$TEST_REPO/config.toml"
  "THREADKEEP_TEST_AUTH_LOGOUT_MARKER=$CHATGPT_LOGIN"
  "THREADKEEP_TEST_LAUNCH_STATE=$LAUNCH_STATE"
  "THREADKEEP_TEST_KEYCHAIN=$KEYCHAIN"
  "THREADKEEP_TEST_ORDER_LOG=$ORDER_LOG"
)

printf '%s\n' loaded > "$LAUNCH_STATE"
printf '%s\n' plist > "$PLIST"
printf '%s\n' discord-token > "$KEYCHAIN"
printf '%s\n' logged-in > "$CHATGPT_LOGIN"
env "${COMMON_ENV[@]}" \
  THREADKEEP_CODEX_DISCORD_BOT_TOKEN="$SECRET_VALUE" \
  "$TEST_REPO/uninstall.sh" --codex --non-interactive \
  > "$TEST_ROOT/default.log"
test ! -e "$PLIST"
test ! -e "$KEYCHAIN"
test ! -e "$CHATGPT_LOGIN"
bootout_line="$(grep -n -m 1 '^launchctl bootout ' "$ORDER_LOG" | cut -d: -f1)"
logout_line="$(grep -n -m 1 '^logout$' "$ORDER_LOG" | cut -d: -f1)"
[ "$bootout_line" -lt "$logout_line" ]
grep -Fq 'Official Codex logout completed' "$TEST_ROOT/default.log"

printf '%s\n' loaded > "$LAUNCH_STATE"
printf '%s\n' plist > "$PLIST"
printf '%s\n' discord-token > "$KEYCHAIN"
printf '%s\n' logged-in > "$CHATGPT_LOGIN"
if env "${COMMON_ENV[@]}" THREADKEEP_TEST_AUTH_LOGOUT_FAIL=1 \
  "$TEST_REPO/uninstall.sh" --codex --non-interactive \
  > "$TEST_ROOT/logout-failure.log" 2>&1; then
  echo 'uninstaller accepted an ambiguous ChatGPT logout' >&2
  exit 1
fi
test ! -e "$PLIST"
test -e "$KEYCHAIN"
test -e "$CHATGPT_LOGIN"
grep -Fq 'Could not remove and verify the isolated ChatGPT login' \
  "$TEST_ROOT/logout-failure.log"

: > "$ORDER_LOG"
printf '%s\n' stopped > "$LAUNCH_STATE"
env "${COMMON_ENV[@]}" \
  "$TEST_REPO/uninstall.sh" --codex --non-interactive \
    --keep-keychain --keep-chatgpt-login \
  > "$TEST_ROOT/keep.log"
test -e "$KEYCHAIN"
test -e "$CHATGPT_LOGIN"
! grep -Fq '^logout$' "$ORDER_LOG"
grep -Fq 'isolated ChatGPT login was retained' "$TEST_ROOT/keep.log"

echo 'Codex uninstall auth lifecycle smoke test: PASS'
