"""Configuration loading for Claude Disclawd.

Config source order:
1. DISCLAWD_CONFIG path, when set
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
    chat_channel_id: str
    errors_channel_id: str
    owner_user_id: str
    token_env_var: str
    token_file: Path | None


@dataclass(frozen=True)
class RuntimeConfig:
    timezone: str
    max_messages_per_minute: int
    max_messages_per_hour: int
    max_concurrent_workers: int
    use_dangerously_skip_permissions: bool


@dataclass(frozen=True)
class Config:
    paths: PathsConfig
    discord: DiscordConfig
    runtime: RuntimeConfig


def _config_path() -> Path:
    env_path = os.environ.get("DISCLAWD_CONFIG")
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
        raise ValueError(f"missing required paths.{key} in disclawd config")
    return path


def load_config() -> Config:
    path = _config_path()
    data = tomllib.loads(path.read_text()) if path.exists() else {}

    paths_raw = data.get("paths", {})
    discord_raw = data.get("discord", {})
    runtime_raw = data.get("runtime", {})

    workspace_root = _expand_path(os.environ.get("DISCLAWD_VAULT_ROOT")) or _path_from(
        paths_raw, "workspace_root", REPO_ROOT
    )
    conversations_dir = _expand_path(os.environ.get("DISCLAWD_CONVERSATIONS_DIR")) or _path_from(
        paths_raw, "conversations_dir", workspace_root / "conversations"
    )
    log_file = _expand_path(os.environ.get("DISCLAWD_LOG_FILE")) or _expand_path(
        paths_raw.get("log_file")
    )
    token_file = _expand_path(os.environ.get("DISCLAWD_TOKEN_FILE")) or _expand_path(
        discord_raw.get("token_file")
    )

    return Config(
        paths=PathsConfig(
            workspace_root=workspace_root,
            conversations_dir=conversations_dir,
            log_file=log_file,
        ),
        discord=DiscordConfig(
            chat_channel_id=os.environ.get("DISCLAWD_LISTEN_CHANNEL_ID")
            or str(discord_raw.get("chat_channel_id", "")),
            errors_channel_id=os.environ.get("DISCLAWD_ERRORS_CHANNEL_ID")
            or str(discord_raw.get("errors_channel_id", "")),
            owner_user_id=os.environ.get("DISCLAWD_OWNER_USER_ID")
            or str(discord_raw.get("owner_user_id", "")),
            token_env_var=str(discord_raw.get("token_env_var") or "DISCORD_BOT_TOKEN"),
            token_file=token_file,
        ),
        runtime=RuntimeConfig(
            timezone=os.environ.get("DISCLAWD_TIMEZONE")
            or str(runtime_raw.get("timezone") or "UTC"),
            max_messages_per_minute=int(runtime_raw.get("max_messages_per_minute", 5)),
            max_messages_per_hour=int(runtime_raw.get("max_messages_per_hour", 30)),
            max_concurrent_workers=int(runtime_raw.get("max_concurrent_workers", 3)),
            use_dangerously_skip_permissions=bool(
                runtime_raw.get("use_dangerously_skip_permissions", False)
            ),
        ),
    )


CONFIG = load_config()


def configured_timezone() -> ZoneInfo:
    try:
        return ZoneInfo(CONFIG.runtime.timezone)
    except Exception:
        return ZoneInfo("UTC")
