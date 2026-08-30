"""Install Claude's static Discord policy and launch it without disk secrets."""
from __future__ import annotations

import argparse
import json
import os
import pwd
import re
import secrets
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NoReturn

import claude_cli
import claude_plugin
import listener_contract
from config import CONFIG
from discord_secret import load_discord_token

SNOWFLAKE = re.compile(r"[1-9][0-9]{16,19}\Z")
SAFE_TERM = re.compile(r"[A-Za-z0-9._+-]{1,64}\Z")
CLEAN_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
DISCORD_EGRESS_TOOLS = (
    "mcp__plugin_discord_discord__reply,"
    "mcp__plugin_discord_discord__edit_message,"
    "mcp__plugin_discord_discord__react,"
    "mcp__plugin_discord_discord__fetch_messages,"
    "mcp__plugin_discord_discord__download_attachment"
)
# This constant is a retired filename, not credential material.
LEGACY_TOKEN_NAME = ".env"  # nosec B105
ACCESS_NAME = "access.json"
FORBIDDEN_WRAPPER_ENVIRONMENT = {
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CODEX_API_KEY",
    "DISCORD_BOT_TOKEN",
    "OPENAI_API_KEY",
    "THREADKEEP_CODEX_DISCORD_BOT_TOKEN",
    "TMPDIR",
}


def _snowflake(value: str, label: str) -> str:
    if not SNOWFLAKE.fullmatch(value):
        raise RuntimeError(f"Threadkeep {label} must be a Discord snowflake")
    return value


def expected_access() -> dict[str, Any]:
    owner = _snowflake(CONFIG.discord.owner_user_id, "owner_user_id")
    channel = _snowflake(CONFIG.discord.chat_channel_id, "chat_channel_id")
    return {
        # The official plugin applies dmPolicy before its guild-channel branch.
        # "disabled" would therefore drop even allowlisted guild traffic.
        "dmPolicy": "allowlist",
        # The global list controls DMs and permission-button principals. Keep
        # it empty so Discord DMs are deterministically dropped. Guild traffic
        # is admitted only by the per-channel owner list below.
        "allowFrom": [],
        "groups": {
            channel: {
                "requireMention": False,
                "allowFrom": [owner],
            }
        },
        "pending": {},
        "ackReaction": "",
        "replyToMode": "off",
        "textChunkLimit": 1900,
        "chunkMode": "newline",
    }


def _account() -> pwd.struct_passwd:
    return pwd.getpwuid(os.getuid())


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _validate_directory_descriptor(
    descriptor: int, *, exact_private_mode: bool
) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError(
            "Claude Discord state ancestry is not safe and current-user owned"
        )
    if exact_private_mode and stat.S_IMODE(metadata.st_mode) != 0o700:
        os.fchmod(descriptor, 0o700)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
            raise RuntimeError("Claude Discord state directory is not private")


def _expected_private_directory() -> Path:
    home = Path(_account().pw_dir)
    if not home.is_absolute() or home.resolve(strict=False) != home:
        raise RuntimeError("Current-user home directory is not canonical")
    expected = (
        home
        / "Library"
        / "Application Support"
        / "Threadkeep"
        / "claude-discord"
    )
    configured = CONFIG.discord.plugin_state_dir.expanduser()
    if not configured.is_absolute() or configured != expected:
        raise RuntimeError(
            "Claude Discord state directory must be the dedicated Threadkeep path"
        )

    # Compare lexical absolute paths here. Resolving the not-yet-created state
    # path could traverse an attacker-controlled ancestor before it is checked.
    expected_value = os.path.abspath(expected)
    for unsafe in (
        Path(__file__).resolve().parents[1],
        CONFIG.paths.workspace_root.expanduser().absolute(),
        CONFIG.paths.conversations_dir.expanduser().absolute(),
    ):
        try:
            common = os.path.commonpath((expected_value, os.path.abspath(unsafe)))
        except ValueError:
            continue
        if common in {expected_value, os.path.abspath(unsafe)}:
            raise RuntimeError("Claude Discord state overlaps executable or workspace data")
    return expected


@contextmanager
def _private_directory_descriptor() -> Iterator[tuple[Path, int]]:
    """Create/open the state tree without ever following an unchecked symlink."""

    expected = _expected_private_directory()
    home = Path(_account().pw_dir)
    try:
        current_descriptor = os.open(home, _directory_flags())
    except OSError as exc:
        raise RuntimeError("Current-user home directory cannot be opened safely") from exc
    try:
        _validate_directory_descriptor(current_descriptor, exact_private_mode=False)
        components = (
            "Library",
            "Application Support",
            "Threadkeep",
            "claude-discord",
        )
        for index, component in enumerate(components):
            try:
                next_descriptor = os.open(
                    component, _directory_flags(), dir_fd=current_descriptor
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_descriptor)
                    next_descriptor = os.open(
                        component, _directory_flags(), dir_fd=current_descriptor
                    )
                except OSError as exc:
                    raise RuntimeError(
                        "Claude Discord state directory cannot be created safely"
                    ) from exc
            except OSError as exc:
                raise RuntimeError(
                    "Claude Discord state ancestry cannot be opened safely"
                ) from exc
            try:
                _validate_directory_descriptor(
                    next_descriptor, exact_private_mode=index >= 2
                )
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        yield expected, current_descriptor
    finally:
        os.close(current_descriptor)


@contextmanager
def _private_runtime_tmp(
    directory: Path, directory_descriptor: int
) -> Iterator[tuple[Path, int]]:
    """Open the dedicated token-bearing process temp directory safely."""

    name = "runtime-tmp"
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=directory_descriptor)
    except FileNotFoundError:
        try:
            os.mkdir(name, mode=0o700, dir_fd=directory_descriptor)
            descriptor = os.open(
                name, _directory_flags(), dir_fd=directory_descriptor
            )
        except OSError as exc:
            raise RuntimeError(
                "Claude Discord runtime temp directory cannot be created safely"
            ) from exc
    except OSError as exc:
        raise RuntimeError(
            "Claude Discord runtime temp directory cannot be opened safely"
        ) from exc
    try:
        _validate_directory_descriptor(descriptor, exact_private_mode=True)
        yield directory / name, descriptor
    finally:
        os.close(descriptor)


def _private_directory() -> Path:
    """Return the verified state path; retained for callers that need its name."""

    with _private_directory_descriptor() as (path, _descriptor):
        return path


def _assert_legacy_token_absent(directory_descriptor: int) -> None:
    try:
        os.stat(
            LEGACY_TOKEN_NAME,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise RuntimeError(
        "Claude Discord refuses to run while the legacy plaintext token file exists"
    )


def _atomic_write_bytes(name: str, content: bytes) -> Path:
    with _private_directory_descriptor() as (directory, directory_descriptor):
        if name != ACCESS_NAME:
            raise RuntimeError("Claude Discord refused an unexpected state filename")
        temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name, flags, 0o600, dir_fd=directory_descriptor
            )
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                os.fchmod(stream.fileno(), 0o600)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(
                temporary_name,
                name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
            raise
        return directory / name


def _atomic_write(name: str, payload: dict[str, Any]) -> Path:
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return _atomic_write_bytes(name, content)


def remove_legacy_token_file() -> Path:
    """Remove a stale plugin .env without reading or following its contents."""

    with _private_directory_descriptor() as (directory, directory_descriptor):
        path = directory / LEGACY_TOKEN_NAME
        try:
            metadata = os.stat(
                LEGACY_TOKEN_NAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return path
        if stat.S_ISLNK(metadata.st_mode):
            # Removing the directory entry is safe and never follows its target.
            pass
        elif (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise RuntimeError(
                "Claude Discord legacy token path is not safe to remove automatically"
            )
        os.unlink(LEGACY_TOKEN_NAME, dir_fd=directory_descriptor)
        os.fsync(directory_descriptor)
        _assert_legacy_token_absent(directory_descriptor)
        return path


# Compatibility for one release so existing uninstall commands clean up rather
# than failing before they remove the retired plaintext copy.
remove_token = remove_legacy_token_file


def install() -> Path:
    # Upgrade cleanup happens before any access policy write or listener launch.
    remove_legacy_token_file()
    path = _atomic_write(ACCESS_NAME, expected_access())
    verify()
    return path


def verify() -> Path:
    with _private_directory_descriptor() as (directory, directory_descriptor):
        _assert_legacy_token_absent(directory_descriptor)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(ACCESS_NAME, flags, dir_fd=directory_descriptor)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size > 64_000
            ):
                raise RuntimeError("Claude Discord access file is not private and owned")
            raw = os.read(descriptor, 64_001)
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or after.st_nlink != 1
            ):
                raise RuntimeError("Claude Discord access file changed while reading")
        finally:
            os.close(descriptor)
        _assert_legacy_token_absent(directory_descriptor)
        if len(raw) > 64_000:
            raise RuntimeError("Claude Discord access file is too large")
        if json.loads(raw.decode("utf-8")) != expected_access():
            raise RuntimeError("Claude Discord access file is not the owner-only policy")
        return directory / ACCESS_NAME


def expected_claude_arguments(
    *, repo_root: Path | None = None, workspace_root: Path | None = None
) -> list[str]:
    repo = (repo_root or Path(__file__).resolve().parents[1]).resolve(strict=False)
    workspace = (
        workspace_root or CONFIG.paths.workspace_root.expanduser()
    ).resolve(strict=False)
    runtime_prompt = (
        CONFIG.discord.plugin_state_dir.expanduser()
        / listener_contract.POLICY_DIRECTORY_NAME
        / listener_contract.RUNTIME_PROMPT_NAME
    ).resolve(strict=False)
    common = [
        "--channels",
        "plugin:discord@claude-plugins-official",
        "--append-system-prompt-file",
        str(runtime_prompt),
        "--append-subagent-system-prompt",
        listener_contract.SUBAGENT_POLICY_PROMPT,
        "--add-dir",
        str(repo),
        "--add-dir",
        str(workspace),
        "--strict-mcp-config",
        "--setting-sources",
        "",
        "--no-chrome",
        "--disallowedTools",
        DISCORD_EGRESS_TOOLS,
    ]
    if CONFIG.runtime.use_dangerously_skip_permissions:
        return [
            "--dangerously-skip-permissions",
            "--permission-mode",
            "bypassPermissions",
            *common,
        ]
    return [
        "--restricted",
        "--permission-mode",
        "dontAsk",
        "--tools",
        "Read,Glob,Grep",
        *common,
    ]


def _validated_text(value: str, label: str, *, maximum: int = 1024) -> str:
    if not value or len(value) > maximum or any(
        character in value for character in "\0\r\n"
    ):
        raise RuntimeError(f"Claude Discord {label} is malformed")
    return value


def _validate_wrapper_environment(source: Mapping[str, str], repo: Path) -> str:
    account = _account()
    expected = {
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "SHELL": "/bin/zsh",
        "PATH": CLEAN_PATH,
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "THREADKEEP_REPO_ROOT": str(repo),
        "THREADKEEP_CONFIG": str(repo / "config.toml"),
        "PYTHONPATH": str(repo / "conversations"),
    }
    for name, value in expected.items():
        if source.get(name) != value:
            raise RuntimeError("Claude credential launcher environment is not reviewed")
    if FORBIDDEN_WRAPPER_ENVIRONMENT.intersection(source):
        raise RuntimeError("Claude credential launcher inherited a forbidden secret")
    term = source.get("TERM", "")
    if not SAFE_TERM.fullmatch(term):
        raise RuntimeError("Claude credential launcher TERM is malformed")
    return term


def _validate_config_file(repo: Path) -> None:
    path = repo / "config.toml"
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeError("Threadkeep configuration is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_nlink != 1
    ):
        raise RuntimeError("Threadkeep configuration metadata is unsafe")


def _reviewed_child_environment(
    *,
    repo: Path,
    plugin_bin: Path,
    runtime_tmp: Path,
    runtime_policy: listener_contract.ClaudeRuntimePolicy,
    source: Mapping[str, str],
) -> dict[str, str]:
    term = _validate_wrapper_environment(source, repo)
    _validate_config_file(repo)
    if CONFIG.discord.token_env_var != "DISCORD_BOT_TOKEN":  # nosec B105
        raise RuntimeError("Claude Discord token environment name is not reviewed")
    if not CONFIG.runtime.use_dangerously_skip_permissions:
        raise RuntimeError(
            "Claude Discord unattended listener requires explicit full local authority"
        )
    workspace = CONFIG.paths.workspace_root.expanduser().resolve(strict=True)
    state = CONFIG.discord.plugin_state_dir.expanduser()
    _snowflake(CONFIG.discord.guild_id, "guild_id")
    _snowflake(CONFIG.discord.chat_channel_id, "chat_channel_id")
    _snowflake(CONFIG.discord.errors_channel_id, "errors_channel_id")
    _snowflake(CONFIG.discord.owner_user_id, "owner_user_id")
    _snowflake(CONFIG.discord.bot_user_id, "bot_user_id")
    _snowflake(CONFIG.discord.application_id, "application_id")
    timezone = _validated_text(CONFIG.runtime.timezone, "timezone", maximum=128)
    account = _account()
    environment = {
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "SHELL": "/bin/zsh",
        "PATH": f"{plugin_bin}:{CLEAN_PATH}",
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "TMPDIR": str(runtime_tmp),
        "TERM": term,
        "THREADKEEP_REPO_ROOT": str(repo),
        "THREADKEEP_CONFIG": str(repo / "config.toml"),
        "DISABLE_UPDATES": "1",
        "DISCORD_STATE_DIR": str(state),
        "DISCORD_ACCESS_MODE": "static",
        "TZ": timezone,
        "REPO_ROOT": str(repo),
        "LISTEN_CHANNEL": CONFIG.discord.chat_channel_id,
        "ERRORS_CHANNEL": CONFIG.discord.errors_channel_id,
        "OWNER_USER_ID": CONFIG.discord.owner_user_id,
        "THREADKEEP_WORKSPACE_ROOT": str(workspace),
        "THREADKEEP_SHARED_SKILLS_ROOT": str(workspace),
        "DISPATCH": str(repo / "conversations" / "dispatch.py"),
        "CONVO": str(repo / "conversations" / "cli.py"),
        "SEND": str(repo / "approval" / "send_message.py"),
        "REQUEST_APPROVAL": str(repo / "approval" / "request_approval.py"),
        "SAFE_FILES": str(repo / "conversations" / "safe_files.py"),
        "INTAKE": str(repo / "conversations" / "queue" / "intake.py"),
        "DRAINER": str(repo / "conversations" / "queue" / "drainer.py"),
        "THREADKEEP_POLICY_VERIFY": str(
            repo / "conversations" / "listener_contract.py"
        ),
    }
    environment.update(runtime_policy.environment())
    return environment


def exec_reviewed_claude(
    claude_binary: Path,
    plugin_bin_directory: Path,
    *,
    source: Mapping[str, str] | None = None,
) -> NoReturn:
    """Replace this process with Claude; the token exists only in its env."""

    values = os.environ if source is None else source
    repo = Path(__file__).resolve().parents[1]
    # Reject ambient credentials before opening or creating any state path.
    _validate_wrapper_environment(values, repo)
    verify()
    cli_result = claude_cli.verify(claude_binary)
    reviewed_binary = Path(str(cli_result["canonical_path"]))
    reviewed_runtime_bin = claude_plugin.verify_runtime() / "bin"
    try:
        supplied_runtime_bin = plugin_bin_directory.expanduser().resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("Claude Discord plugin runtime path is unavailable") from exc
    if supplied_runtime_bin != reviewed_runtime_bin.resolve(strict=True):
        raise RuntimeError("Claude Discord plugin runtime path is not reviewed")
    # Hold both already-verified private directories open through exec. This is
    # deliberately the final credential-producing operation. Nothing after it
    # writes state, prints output, invokes a shell, or puts the token in argv.
    with (
        _private_directory_descriptor() as (directory, directory_descriptor),
        _private_runtime_tmp(
            directory, directory_descriptor
        ) as (runtime_tmp, _runtime_tmp_descriptor),
    ):
        # The listener cwd is the policy bootstrap workspace. The Vault is
        # still inside Claude's effective full-local authority through the
        # explicit add-dir and permission mode.
        runtime_policy = listener_contract.validate_runtime_policy(
            vault_root=CONFIG.paths.workspace_root.expanduser(),
            runtime_root=directory,
            bootstrap_workspace=repo / "cx-chat-listener",
        )
        arguments = expected_claude_arguments(
            repo_root=repo,
            workspace_root=CONFIG.paths.workspace_root.expanduser(),
        )
        observed_prompt = Path(
            arguments[arguments.index("--append-system-prompt-file") + 1]
        ).resolve(strict=False)
        if observed_prompt != runtime_policy.prompt_path.resolve(strict=False):
            raise RuntimeError("Claude runtime policy prompt path is not reviewed")
        child_environment = _reviewed_child_environment(
            repo=repo,
            plugin_bin=supplied_runtime_bin,
            runtime_tmp=runtime_tmp,
            runtime_policy=runtime_policy,
            source=values,
        )
        _assert_legacy_token_absent(directory_descriptor)
        token = load_discord_token(allow_environment=False)
        _assert_legacy_token_absent(directory_descriptor)
        child_environment["DISCORD_BOT_TOKEN"] = token
        try:
            # The executable is the exact verified binary and no shell is involved.
            os.execve(  # nosec B606
                reviewed_binary,
                [str(reviewed_binary), *arguments],
                child_environment,
            )
        except OSError:
            raise RuntimeError(
                "Reviewed Claude listener could not be executed"
            ) from None
        raise RuntimeError("Reviewed Claude listener exec unexpectedly returned")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "install",
            "verify",
            "remove-legacy-token",
            "remove-token",
            "exec-claude",
        ),
    )
    parser.add_argument("--claude-bin", type=Path)
    parser.add_argument("--plugin-bin-dir", type=Path)
    args = parser.parse_args()
    if args.command == "install":
        path = install()
    elif args.command in {"remove-legacy-token", "remove-token"}:
        path = remove_legacy_token_file()
    elif args.command == "exec-claude":
        if args.claude_bin is None or args.plugin_bin_dir is None:
            parser.error("exec-claude requires --claude-bin and --plugin-bin-dir")
        exec_reviewed_claude(args.claude_bin, args.plugin_bin_dir)
    else:
        path = verify()
    print(json.dumps({"ok": True, "path": str(path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
