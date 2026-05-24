# Threadkeep security

This document covers the trust model, secret handling, and how to report a vulnerability.

## Scope of trust

Threadkeep runs locally on a single owner's machine. It is not a multi-tenant service. The trust model is built on three asymmetries:

1. The owner's machine is trusted. Anything that can run as the owner's user can read Threadkeep state, the Discord token, and the conversation transcripts. This is unavoidable for a local install.
2. The owner's Discord user id is the only honored approver. The router (`discord-gateway/router.py`) refuses every interaction whose user id does not match `config.discord.owner_user_id` and ACKs with an ephemeral "Not authorized" reply.
3. Every inbound Discord message is untrusted input. The listener's job is to treat the message body as data to be passed to a worker, not as instructions to itself. The worker prompt template in `agent/cx-chat.md` explicitly tells the subagent to treat Discord content as untrusted.

## What we protect against

- A non-owner user in the same Discord channel cannot trigger any outbound send. They can post messages and create conversations, but their button presses are silently rejected.
- A prompt-injected Discord message cannot cause the worker to send arbitrary outbound messages. The outbound gate scripts require a `--discord-approval-message-id` reference that points to a real Discord button-press interaction by the configured owner.
- A prompt-injected Discord message cannot cause the worker to attach arbitrary local files to a Discord reply. The `hooks/discord-file-gate.sh` PreToolUse hook restricts file attachments to an explicit allowlist of directory prefixes and rejects path traversal.
- A compromised Slack or email gate script cannot fake an approval. The script gets `--pending-json` (with the draft sha) and `--discord-approval-message-id`, and it is expected to re-verify the reference against Discord before sending.
- Replay or substitution of an old approval cannot succeed if the gate script re-verifies the sha against the draft it is about to send (which it should).

## What we do not protect against

- Local malware running as the owner's user. They have full access to the Keychain entry, the conversation files, and the bot token. If your machine is compromised, Threadkeep is compromised.
- A Discord account takeover of the owner. If an attacker has the owner's Discord session, they can tap Approve on anything.
- Bot token leakage outside Threadkeep. If your bot token leaks (via a screenshot, a misconfigured repo, etc.) anyone with it can impersonate your bot. Rotate immediately if you suspect a leak.
- Code execution by the Claude Code worker. The default install does NOT run the worker with `--dangerously-skip-permissions`. Permission prompts will surface in your Claude Code UI. Do not flip the flag unless you understand what you are giving up.

## Secret storage

The Discord bot token is stored in the macOS Keychain by `install.sh`:

- Service: `threadkeep-secret`
- Account: `discord-bot-token`

The launcher (`cx-launcher.sh`) reads it via `security find-generic-password` at session start and exports it as `DISCORD_BOT_TOKEN` for the Claude Code process. The launchd plists do not embed the token. The token never lands on disk in plaintext.

You can rotate the token with:

```
security delete-generic-password -s threadkeep-secret -a discord-bot-token
security add-generic-password -s threadkeep-secret -a discord-bot-token -w
```

Or re-run `bash install.sh --reinstall`.

If you are not on macOS, you are responsible for sourcing `DISCORD_BOT_TOKEN` into the daemon environment yourself, e.g. via a secret manager (`pass`, `gopass`, `vaultenv`) or a `.env` file with strict permissions.

## Outbound send gating

The default install does NOT enable any outbound gate. Workers can post Discord messages in their assigned threads, but they cannot send Slack, email, or anything else.

If you want a worker to be able to send outbound, you write a small adapter script and point `THREADKEEP_SLACK_GATE` or `THREADKEEP_EMAIL_GATE` at it. Your gate script is the final authority. It must:

1. Parse `--pending-json` and extract the operation, target, draft body, and draft sha.
2. Re-verify the draft sha against the actual draft body it is about to send.
3. Re-verify the `--discord-approval-message-id` against Discord (fetch the message, check it is owned by the bot, check the approve button was tapped by the configured owner).
4. Run any consistency checks your domain requires (length limits, tone, recipient allowlist).
5. Call the underlying provider API.

If your gate script does (1) through (4) faithfully, the worker cannot bypass it via prompt injection.

## Reporting a vulnerability

If you believe you have found a security issue in Threadkeep, please email the maintainer directly rather than filing a public GitHub issue. Use the email listed on the GitHub profile of the repo owner.

Please include:

1. A description of the issue and the impact you believe it has.
2. Steps to reproduce, ideally a minimal proof-of-concept.
3. Your suggested remediation, if you have one.

We will acknowledge receipt within a few business days, work on a fix, and credit you in the release notes unless you prefer otherwise.

## Threat areas we care most about

- Anything that lets a non-owner Discord user trigger an outbound send.
- Anything that lets a prompt-injected message coerce the worker into attaching arbitrary local files.
- Anything that lets a marker file be forged or substituted without the gateway client noticing.
- Anything that leaks the bot token through logs, error messages, or stack traces.

If you find an issue in one of these areas it is high priority and we will treat the report accordingly.
