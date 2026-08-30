"""Configuration loading for Disco Party.

Config source order:
1. DISCOPARTY_CONFIG path, when set
2. config.toml in the repo root
3. .env.example as a non-secret fallback for static checks
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class PathsConfig:
    workspace_root: Path
    conversations_dir: Path
    log_file: Path | None


@dataclass(frozen=True)
class DiscordConfig:
    guild_id: str
    chat_channel_id: str
    errors_channel_id: str
    owner_user_id: str
    bot_user_id: str
    application_id: str
    token_env_var: str
    keychain_service: str
    keychain_account: str
    plugin_state_dir: Path


@dataclass(frozen=True)
class RuntimeConfig:
    timezone: str
    max_messages_per_minute: int
    max_messages_per_hour: int
    max_concurrent_workers: int
    use_dangerously_skip_permissions: bool


@dataclass(frozen=True)
class CodexConfig:
    enabled: bool
    guild_id: str
    channel_id: str
    owner_user_id: str
    bot_user_id: str
    application_id: str
    channel_trust: str
    working_directory: Path
    state_dir: Path
    codex_home: Path
    codex_bin: Path
    sandbox_mode: str
    full_computer_access_accepted: bool
    instructions_file: Path | None
    shared_skills_root: Path
    keychain_service: str
    keychain_account: str
    max_messages_per_minute: int
    max_messages_per_hour: int
    max_concurrent_workers: int
    max_pending_jobs: int
    max_input_chars: int
    retention_days: int
    max_database_bytes: int


@dataclass(frozen=True)
class Config:
    paths: PathsConfig
    discord: DiscordConfig
    runtime: RuntimeConfig
    codex: CodexConfig


def _config_path() -> Path:
    env_path = os.environ.get("DISCOPARTY_CONFIG")
    if env_path:
        return Path(env_path).expanduser()
    local = REPO_ROOT / "config.toml"
    if local.exists():
        return local
    return REPO_ROOT / "config.example.toml"


def _expand_path(value: str | None) -> Path | None:
    if not value:
        return None
    return Path(value).expanduser()


def _path_from(raw: dict, key: str, fallback: Path | None = None) -> Path:
    value = raw.get(key)
    path = _expand_path(value) if value else fallback
    if path is None:
        raise ValueError(f"missing required paths.{key} in discoparty config")
    return path


def _env_bool(name: str, fallback: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return fallback
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def _toml_bool(table: dict, key: str, fallback: bool) -> bool:
    if key not in table:
        return fallback
    value = table[key]
    if type(value) is not bool:
        raise ValueError(f"{key} must be a TOML Boolean")
    return value


def _env_int(name: str, fallback: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw is not None else int(fallback)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_config() -> Config:
    path = _config_path()
    data = tomllib.loads(path.read_text()) if path.exists() else {}

    paths_raw = data.get("paths", {})
    discord_raw = data.get("discord", {})
    runtime_raw = data.get("runtime", {})
    codex_raw = data.get("codex", {})

    codex_enabled = _env_bool(
        "DISCOPARTY_CODEX_ENABLED",
        _toml_bool(codex_raw, "enabled", False),
    )

    workspace_root = _expand_path(os.environ.get("DISCOPARTY_VAULT_ROOT")) or _path_from(
        paths_raw, "workspace_root", REPO_ROOT
    )
    conversations_dir = _expand_path(os.environ.get("DISCOPARTY_CONVERSATIONS_DIR")) or _path_from(
        paths_raw, "conversations_dir", workspace_root / "conversations"
    )
    log_file = _expand_path(os.environ.get("DISCOPARTY_LOG_FILE")) or _expand_path(
        paths_raw.get("log_file")
    )
    runtime_minute_limit = int(runtime_raw.get("max_messages_per_minute", 5))
    runtime_hour_limit = int(runtime_raw.get("max_messages_per_hour", 30))

    if codex_enabled:
        codex_working_directory = _expand_path(
            os.environ.get("DISCOPARTY_CODEX_WORKING_DIRECTORY")
        ) or _expand_path(codex_raw.get("working_directory")) or workspace_root
        codex_state_dir = _expand_path(
            os.environ.get("DISCOPARTY_CODEX_STATE_DIR")
        ) or _expand_path(codex_raw.get("state_dir")) or (
            Path.home() / "Library/Application Support/Discoparty/codex-discord"
        )
        codex_home = _expand_path(
            os.environ.get("DISCOPARTY_CODEX_HOME")
        ) or _expand_path(codex_raw.get("codex_home")) or codex_state_dir / "home/.codex"
        codex_instructions_file = _expand_path(
            os.environ.get("DISCOPARTY_CODEX_INSTRUCTIONS_FILE")
        ) or _expand_path(codex_raw.get("instructions_file"))
        codex_shared_skills_root = _expand_path(
            os.environ.get("DISCOPARTY_CODEX_SHARED_SKILLS_ROOT")
        ) or _expand_path(codex_raw.get("shared_skills_root")) or (
            workspace_root / "x_System/Skills"
        )
        codex_bin = _expand_path(os.environ.get("DISCOPARTY_CODEX_BIN")) or _expand_path(
            codex_raw.get("codex_bin")
        ) or Path("/opt/homebrew/bin/codex")
        codex_sandbox_mode = os.environ.get("DISCOPARTY_CODEX_SANDBOX_MODE") or str(
            codex_raw.get("sandbox_mode") or "workspace-write"
        )
        if codex_sandbox_mode not in {"workspace-write", "danger-full-access"}:
            raise ValueError(
                "codex.sandbox_mode must be 'workspace-write' or 'danger-full-access'"
            )
        codex_channel_trust = (
            os.environ.get("DISCOPARTY_CODEX_CHANNEL_TRUST")
            or str(codex_raw.get("channel_trust") or "public")
        ).strip().lower()
        if codex_channel_trust not in {"public", "owner_private"}:
            raise ValueError(
                "codex.channel_trust must be 'public' or 'owner_private'"
            )
        codex_full_computer_access_accepted = _env_bool(
            "DISCOPARTY_CODEX_FULL_COMPUTER_ACCESS_ACCEPTED",
            _toml_bool(codex_raw, "full_computer_access_accepted", False),
        )
        codex_max_messages_per_minute = _env_int(
            "DISCOPARTY_CODEX_MAX_MESSAGES_PER_MINUTE",
            codex_raw.get("max_messages_per_minute", runtime_minute_limit),
            minimum=1,
            maximum=120,
        )
        codex_max_messages_per_hour = _env_int(
            "DISCOPARTY_CODEX_MAX_MESSAGES_PER_HOUR",
            codex_raw.get("max_messages_per_hour", runtime_hour_limit),
            minimum=1,
            maximum=2_000,
        )
        codex_max_concurrent_workers = _env_int(
            "DISCOPARTY_CODEX_MAX_CONCURRENT_WORKERS",
            codex_raw.get("max_concurrent_workers", 3),
            minimum=1,
            maximum=4,
        )
        codex_max_pending_jobs = _env_int(
            "DISCOPARTY_CODEX_MAX_PENDING_JOBS",
            codex_raw.get("max_pending_jobs", 100),
            minimum=1,
            maximum=10_000,
        )
        codex_max_input_chars = _env_int(
            "DISCOPARTY_CODEX_MAX_INPUT_CHARS",
            codex_raw.get("max_input_chars", 12_000),
            minimum=1,
            maximum=100_000,
        )
        codex_retention_days = _env_int(
            "DISCOPARTY_CODEX_RETENTION_DAYS",
            codex_raw.get("retention_days", 30),
            minimum=1,
            maximum=365,
        )
        codex_max_database_bytes = _env_int(
            "DISCOPARTY_CODEX_MAX_DATABASE_BYTES",
            codex_raw.get("max_database_bytes", 268_435_456),
            minimum=1_048_576,
            maximum=4_294_967_296,
        )
    else:
        # Claude does not consume any Codex setting. Keep disabled-provider
        # values inert so a stale or future Codex option cannot stop Claude's
        # Gateway, router, or queue from importing the shared configuration.
        codex_working_directory = workspace_root
        codex_state_dir = (
            Path.home() / "Library/Application Support/Discoparty/codex-discord"
        )
        codex_home = codex_state_dir / "home/.codex"
        codex_instructions_file = None
        codex_shared_skills_root = workspace_root / "x_System/Skills"
        codex_bin = Path("/opt/homebrew/bin/codex")
        codex_sandbox_mode = "workspace-write"
        codex_channel_trust = "public"
        codex_full_computer_access_accepted = False
        codex_max_messages_per_minute = 5
        codex_max_messages_per_hour = 30
        codex_max_concurrent_workers = 3
        codex_max_pending_jobs = 100
        codex_max_input_chars = 12_000
        codex_retention_days = 30
        codex_max_database_bytes = 268_435_456

    return Config(
        paths=PathsConfig(
            workspace_root=workspace_root,
            conversations_dir=conversations_dir,
            log_file=log_file,
        ),
        discord=DiscordConfig(
            guild_id=os.environ.get("DISCOPARTY_DISCORD_GUILD_ID")
            or str(discord_raw.get("guild_id", "")),
            chat_channel_id=os.environ.get("DISCOPARTY_LISTEN_CHANNEL_ID")
            or str(discord_raw.get("chat_channel_id", "")),
            errors_channel_id=os.environ.get("DISCOPARTY_ERRORS_CHANNEL_ID")
            or str(discord_raw.get("errors_channel_id", "")),
            owner_user_id=os.environ.get("DISCOPARTY_OWNER_USER_ID")
            or str(discord_raw.get("owner_user_id", "")),
            bot_user_id=os.environ.get("DISCOPARTY_DISCORD_BOT_USER_ID")
            or str(discord_raw.get("bot_user_id", "")),
            application_id=os.environ.get("DISCOPARTY_DISCORD_APPLICATION_ID")
            or str(discord_raw.get("application_id", "")),
            token_env_var=str(discord_raw.get("token_env_var") or "DISCORD_BOT_TOKEN"),
            keychain_service=str(
                discord_raw.get("keychain_service") or "discoparty-secret"
            ),
            keychain_account=str(
                discord_raw.get("keychain_account") or "discord-bot-token"
            ),
            plugin_state_dir=(
                _expand_path(os.environ.get("DISCOPARTY_DISCORD_PLUGIN_STATE_DIR"))
                or _expand_path(discord_raw.get("plugin_state_dir"))
                or Path.home()
                / "Library/Application Support/Discoparty/claude-discord"
            ),
        ),
        runtime=RuntimeConfig(
            timezone=os.environ.get("DISCOPARTY_TIMEZONE")
            or str(runtime_raw.get("timezone") or "UTC"),
            max_messages_per_minute=runtime_minute_limit,
            max_messages_per_hour=runtime_hour_limit,
            max_concurrent_workers=int(runtime_raw.get("max_concurrent_workers", 3)),
            use_dangerously_skip_permissions=bool(
                _toml_bool(runtime_raw, "use_dangerously_skip_permissions", False)
            ),
        ),
        codex=CodexConfig(
            enabled=codex_enabled,
            guild_id=os.environ.get("DISCOPARTY_CODEX_GUILD_ID")
            or str(codex_raw.get("guild_id", "")),
            channel_id=os.environ.get("DISCOPARTY_CODEX_CHANNEL_ID")
            or str(codex_raw.get("channel_id", "")),
            owner_user_id=os.environ.get("DISCOPARTY_CODEX_OWNER_USER_ID")
            or str(codex_raw.get("owner_user_id", "")),
            bot_user_id=os.environ.get("DISCOPARTY_CODEX_BOT_USER_ID")
            or str(codex_raw.get("bot_user_id", "")),
            application_id=os.environ.get("DISCOPARTY_CODEX_APPLICATION_ID")
            or str(codex_raw.get("application_id", "")),
            channel_trust=codex_channel_trust,
            working_directory=codex_working_directory,
            state_dir=codex_state_dir,
            codex_home=codex_home,
            codex_bin=codex_bin,
            sandbox_mode=codex_sandbox_mode,
            full_computer_access_accepted=codex_full_computer_access_accepted,
            instructions_file=codex_instructions_file,
            shared_skills_root=codex_shared_skills_root,
            keychain_service=str(
                codex_raw.get("keychain_service") or "discoparty-secret"
            ),
            keychain_account=str(
                codex_raw.get("keychain_account") or "discord-bot-token-codex"
            ),
            max_messages_per_minute=codex_max_messages_per_minute,
            max_messages_per_hour=codex_max_messages_per_hour,
            max_concurrent_workers=codex_max_concurrent_workers,
            max_pending_jobs=codex_max_pending_jobs,
            max_input_chars=codex_max_input_chars,
            retention_days=codex_retention_days,
            max_database_bytes=codex_max_database_bytes,
        ),
    )


CONFIG = load_config()


def configured_timezone() -> ZoneInfo:
    try:
        return ZoneInfo(CONFIG.runtime.timezone)
    except Exception:
        return ZoneInfo("UTC")
