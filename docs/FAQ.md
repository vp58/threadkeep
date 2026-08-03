# FAQ

## What is Threadkeep?

Threadkeep is a persistent Discord conversation orchestrator for Claude Code. It listens in one Discord channel, creates a thread for each top-level message, writes the conversation to markdown, and dispatches the actual work to a background subagent.

## Do I need Claude Code?

Yes. Threadkeep is a harness around Claude Code and the Claude Code Discord plugin. It does not provide a model runtime by itself.

## Does Threadkeep send email or Slack messages by default?

No. Outbound sends require an adapter you provide and an explicit approval flow. The marker watcher only runs a configured gate script after the owner approves the pending action through Discord.

## Can I use more than one Discord channel?

The current listener is designed around one configured listen channel plus threads it created. This keeps the ownership model simple and prevents the bot from acting in channels it should ignore.

## Can multiple people approve actions?

Not yet. The router checks one configured owner Discord user id. Multi-approver support would need a clear policy for who can approve which action.

## Why do button presses do nothing?

Usually the gateway client is not running, the bot was invited without `applications.commands`, or the user pressing the button is not the configured owner. Check `~/.threadkeep/discord-gateway/logs/client.log` first.

## Where are conversations stored?

Conversation markdown files live under the configured workspace root, usually `~/.threadkeep/conversations/`. The JSON registry maps Discord thread ids to those local session files.

## Is Linux supported?

The Python code and systemd templates are portable, but `install.sh` is currently macOS-first because it configures launchd and macOS Keychain. Linux setup is documented as a manual sketch in `docs/SETUP.md`.

## Is it safe to run with `--dangerously-skip-permissions`?

It is not recommended as the default. Threadkeep ships with a stricter posture: worker actions should pass through Claude Code permission prompts and outbound sends should be review-gated.

## How do I report a security issue?

Follow the disclosure flow in `docs/SECURITY.md`. Do not open a public GitHub issue for security reports.
