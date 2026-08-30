"""Narrow Discord credential loading and child-environment isolation."""
from __future__ import annotations

import os
import pwd
import stat
# The only child is the fixed absolute macOS Keychain client, without a shell.
import subprocess  # nosec B404
from collections.abc import Mapping
from pathlib import Path

try:
    from .config import CONFIG
except ImportError:  # Direct script/PYTHONPATH compatibility for Claude launchers.
    from config import CONFIG


_SECRET_NAMES = {
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CODEX_API_KEY",
    "DISCORD_BOT_TOKEN",
    "OPENAI_API_KEY",
    "THREADKEEP_CODEX_DISCORD_BOT_TOKEN",
}


def _validate_token(value: str) -> str:
    token = value.strip()
    if not token or len(token) > 4096 or any(character.isspace() for character in token):
        raise RuntimeError("Discord bot credential is empty or malformed")
    return token


def _keychain_token() -> str:
    security = Path("/usr/bin/security")
    if not security.is_file():
        raise RuntimeError("macOS Keychain client is unavailable")
    account = pwd.getpwuid(os.getuid())
    home = Path(account.pw_dir)
    try:
        canonical_home = home.resolve(strict=True)
        metadata = home.lstat()
    except OSError as exc:
        raise RuntimeError("Current-user home directory is unavailable") from exc
    if (
        not home.is_absolute()
        or canonical_home != home
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError("Current-user home directory is not canonical and private")
    environment = {
        "HOME": str(canonical_home),
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
    }
    # The executable and argv shape are fixed and no shell is involved.
    result = subprocess.run(  # nosec B603
        [
            str(security),
            "find-generic-password",
            "-s",
            CONFIG.discord.keychain_service,
            "-a",
            CONFIG.discord.keychain_account,
            "-w",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env=environment,
        start_new_session=True,
    )
    if result.returncode != 0:
        raise RuntimeError("Discord bot credential is missing from macOS Keychain")
    return _validate_token(result.stdout)


def load_discord_token(*, allow_environment: bool = False) -> str:
    """Load the Claude Discord bot token without logging or returning its source."""

    if allow_environment:
        raise RuntimeError("Discord bot credentials may be loaded only from Keychain")
    return _keychain_token()


def sanitized_child_environment(
    source: Mapping[str, str] | None = None,
    *,
    keep: set[str] | None = None,
) -> dict[str, str]:
    """Return a reviewed environment with orchestration credentials removed."""

    allowed = {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "SHELL",
        "TMPDIR",
        "TZ",
        "USER",
        "LOGNAME",
        "SSH_AUTH_SOCK",
        "XPC_FLAGS",
        "XPC_SERVICE_NAME",
        "__CFBundleIdentifier",
    }
    allowed.update(keep or set())
    values = os.environ if source is None else source
    result = {name: value for name, value in values.items() if name in allowed}
    for name in _SECRET_NAMES | {CONFIG.discord.token_env_var}:
        result.pop(name, None)
    result.setdefault("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
    result.setdefault("HOME", str(Path.home()))
    return result
