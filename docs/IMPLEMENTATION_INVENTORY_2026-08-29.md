# Disco Party dual Discord orchestrator implementation inventory

Date: 2026-08-29

This is the exact local file surface for the dual Claude and Codex Discord implementation. It is an audit inventory, not a deployment record. No live service, credential, Discord permission, commit, push, or website deployment is implied.

## Codex provider

Adds the separate #chatgpt Gateway, durable App Server worker, ChatGPT subscription authentication, exact M5 Max and CLI pins, independent destination-trust and execution-authority policies, explicit full-access acceptance, optional exact private-channel proof, four hash-bound shared skills, best-effort redact-never-withhold output filtering, sealed hooks, monitor, installer lifecycle, and tests.

- **Added:** `codex-discord/evals/live_approval_eval.py`
- **Added:** `codex-discord/tests/test_auth_lifecycle.py`
- **Added:** `codex-discord/tests/test_bridge.py`
- **Added:** `codex-discord/tests/test_direct_transport.py`
- **Added:** `codex-discord/tests/test_discord_permissions.py`
- **Added:** `codex-discord/tests/test_install_codex.sh`
- **Added:** `codex-discord/tests/test_uninstall_codex.sh`
- **Added:** `codex_discord_bridge/__init__.py`
- **Added:** `codex_discord_bridge/appserver.py`
- **Added:** `codex_discord_bridge/codex_auth.py`
- **Added:** `codex_discord_bridge/codex_policy.py`
- **Added:** `codex_discord_bridge/config.py`
- **Added:** `codex_discord_bridge/discord_io.py`
- **Added:** `codex_discord_bridge/discord_permissions.py`
- **Added:** `codex_discord_bridge/identify_budget.py`
- **Added:** `codex_discord_bridge/ingress.py`
- **Added:** `codex_discord_bridge/main.py`
- **Added:** `codex_discord_bridge/monitor.py`
- **Added:** `codex_discord_bridge/preflight.py`
- **Added:** `codex_discord_bridge/process_supervisor.py`
- **Added:** `codex_discord_bridge/shared_hooks.py`
- **Added:** `codex_discord_bridge/shared_skills.py`
- **Added:** `codex_discord_bridge/store.py`
- **Added:** `codex_discord_bridge/trusted_instructions.py`
- **Added:** `install-codex.sh`
- **Added:** `launchd/codex-monitor.sh`
- **Added:** `launchd/templates/com.discoparty.codex-discord-bridge.plist.template`
- **Added:** `requirements-macos-arm64.lock`

## Claude provider and shared Discord core

Hardens the existing Claude #chat lane, public-channel permissions, transport, liveness, durable queue, takeover, review semantics, token handling, and shared utilities without adding an outbound sender.

- **Modified:** `agent/cx-chat.md`
- **Modified:** `approval/create_thread.py`
- **Modified:** `approval/react.py`
- **Modified:** `approval/request_approval.py`
- **Modified:** `approval/request_approval_responder.py`
- **Modified:** `approval/send_message.py`
- **Added:** `conversations/bun_runtime.py`
- **Added:** `conversations/claude_cli.py`
- **Added:** `conversations/claude_plugin.py`
- **Added:** `conversations/claude_takeover.py`
- **Modified:** `conversations/cli.py`
- **Modified:** `conversations/config.py`
- **Added:** `conversations/discord_access.py`
- **Added:** `conversations/discord_destination.py`
- **Added:** `conversations/discord_http.py`
- **Added:** `conversations/discord_identity.py`
- **Added:** `conversations/discord_permissions.py`
- **Added:** `conversations/discord_secret.py`
- **Modified:** `conversations/dispatch.py`
- **Modified:** `conversations/lib.py`
- **Added:** `conversations/listener_contract.py`
- **Added:** `conversations/public_output.py`
- **Modified:** `conversations/queue/README.md`
- **Modified:** `conversations/queue/drainer.py`
- **Modified:** `conversations/queue/idempotency.py`
- **Modified:** `conversations/queue/intake.py`
- **Modified:** `conversations/queue/monitor.py`
- **Modified:** `conversations/queue/mq.py`
- **Modified:** `conversations/queue/tests/fake_discord/create_thread.py`
- **Modified:** `conversations/queue/tests/fake_discord/react.py`
- **Modified:** `conversations/queue/tests/run_tests.py`
- **Added:** `conversations/queue/tests/test_claude_takeover.py`
- **Added:** `conversations/safe_files.py`
- **Added:** `conversations/shared_skills.py`
- **Added:** `conversations/vault_policy.py`
- **Modified:** `cx-chat-listener/CLAUDE.md`
- **Modified:** `cx-launcher.sh`
- **Modified:** `discord-gateway/client.py`
- **Added:** `discord-gateway/interaction_store.py`
- **Modified:** `discord-gateway/marker-watcher.py`
- **Modified:** `discord-gateway/router.py`
- **Added:** `discord-gateway/tests/test_claude_helpers.py`
- **Added:** `discord-gateway/tests/test_claude_security.py`
- **Modified:** `discord-gateway/tests/test_client.py`
- **Added:** `discord-gateway/tests/test_discord_permissions.py`
- **Added:** `discord-gateway/tests/test_interaction_store.py`
- **Modified:** `discord-gateway/tests/test_marker_watcher.py`
- **Added:** `discord-gateway/tests/test_request_approval.py`
- **Modified:** `discord-gateway/tests/test_router.py`
- **Modified:** `examples/slack_gate.py`
- **Modified:** `install.sh`
- **Modified:** `launchd/cx-chat-healthcheck.sh`
- **Modified:** `uninstall.sh`

## Repository configuration and CI

Adds dual-provider configuration, dependency pinning, ignores, examples, and automated regression coverage.

- **Modified:** `.env.example`
- **Modified:** `.github/workflows/test.yml`
- **Modified:** `.gitignore`
- **Modified:** `config.example.toml`
- **Modified:** `requirements.txt`

## Documentation and audit

Documents the dual-lane design, setup, security decision, current official feature research, operating limits, release gates, and verification evidence.

- **Modified:** `CHANGELOG.md`
- **Modified:** `CONTRIBUTING.md`
- **Modified:** `README.md`
- **Modified:** `docs/ARCHITECTURE.md`
- **Modified:** `docs/FAQ.md`
- **Added:** `docs/IMPLEMENTATION_INVENTORY_2026-08-29.md`
- **Modified:** `docs/SECURITY.md`
- **Added:** `docs/SECURITY_REVIEW_2026-08-29.md`
- **Modified:** `docs/SETUP.md`

## Canonical Vault files

These files make the policy, hooks, operational memory, and ELI5 plus VinayTalks routing shared across Claude and Codex.

- **Modified:** `/Users/vinaypatankar/TheSystem/.claude/hooks/em-dash-write-validator.py`
- **Modified:** `/Users/vinaypatankar/TheSystem/.claude/hooks/security-validator.sh`
- **Added:** `/Users/vinaypatankar/TheSystem/.claude/hooks/security_validator.py`
- **Modified:** `/Users/vinaypatankar/TheSystem/CLAUDE.md`
- **Modified:** `/Users/vinaypatankar/TheSystem/Atlas/Reference/Claude Code Guide.md`
- **Modified:** `/Users/vinaypatankar/TheSystem/x_System/Assistant/MEMORY.md`
- **Modified:** `/Users/vinaypatankar/TheSystem/x_System/Assistant/daily/2026-08-29.md`
- **Modified:** `/Users/vinaypatankar/TheSystem/x_System/Scripts/outbound-send-gate-hook.sh`
- **Modified:** `/Users/vinaypatankar/TheSystem/x_System/Scripts/outbound_send_gate_hook.py`
- **Added:** `/Users/vinaypatankar/TheSystem/x_System/Scripts/tests/test_shared_hook_guards.py`

## VinayTalks artifact

This file explains the architecture, flow, security decision, official research, and rollout status in the required visual format.

- **Modified:** `/Users/vinaypatankar/Websites/vinaytalks/src/pages/codex-discord-m5-8c3f72a1/index.astro`
