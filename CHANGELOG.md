# Changelog

All notable changes to Threadkeep will be documented in this file.

This project follows the spirit of Keep a Changelog and uses semantic versioning once tagged releases begin.

## [Unreleased]

### Added

- GitHub Actions CI for Python 3.11, 3.12, and 3.13.
- Root Code of Conduct.
- FAQ covering setup, security, multi-channel behavior, and approval buttons.
- Minimal outbound gate example for Slack-style adapters.
- README badges, contents, and first-message walkthrough.

## [0.1.0-pre] - 2026-05-24

### Added

- Public Threadkeep repo with install path, uninstall path, launchd templates, systemd templates, setup docs, architecture docs, security docs, issue templates, and PR template.
- Persistent Discord listener and worker-dispatch pattern extracted from the original private deployment.
- Discord approval gateway and marker watcher for review-gated outbound sends.
- Identity persistence hooks for Claude Code listener sessions.
