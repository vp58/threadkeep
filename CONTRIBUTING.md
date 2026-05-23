# Contributing to Claude Disclawd

Thanks for taking the time to look at this project. This file describes how to file issues, propose changes, and what code style we follow.

## Filing an issue

Open a GitHub issue at https://github.com/vp58/claude-disclawd/issues. Please include:

- What you were trying to do
- What you expected to happen
- What actually happened
- Your OS, Python version, and Claude Code version
- Relevant log excerpts from `discord-gateway/logs/` or the listener tmux session

If the issue is security-related, do not file a public issue. See `SECURITY.md` for the disclosure flow.

## Proposing a change

Small, focused pull requests are easier to review than large ones. If you have a big change in mind, open an issue first to discuss the approach.

1. Fork the repo.
2. Create a branch off `main`.
3. Make your change.
4. Update the relevant docs in `docs/` if behavior changed.
5. Add or update tests under `discord-gateway/tests/` when you can.
6. Open a pull request with a clear description and any context the reviewer needs.

## Code style

- Python: standard library where possible. The only required runtime dependency is `websockets` for the gateway client. The rest of the scripts run on stdlib.
- Use absolute imports, type hints where they add clarity, and small focused functions.
- Bash scripts use `set -euo pipefail`.
- No em dashes in user-facing strings or comments. Use commas, periods, or restructure.
- Configuration goes through `conversations/config.py`. Do not hardcode paths or ids in new code.

## Testing

The test suite under `discord-gateway/tests/` uses pytest. Run:

```
python3 -m pytest discord-gateway/tests/
```

These tests mock Discord and the filesystem. There is no live integration test in the standard suite.

For end to end testing against a real Discord server, see `docs/SETUP.md` for how to provision a sandbox server with a throwaway bot.

## What we are not looking for

- Features that require running the worker with elevated permissions by default. Safety posture is intentionally strict.
- Adding new third-party platform integrations to the marker watcher. The watcher is intentionally provider-agnostic. Bring your own outbound script.
- New required dependencies without a strong reason.

## Code of Conduct

This project follows the Contributor Covenant. See `CODE_OF_CONDUCT.md`.
