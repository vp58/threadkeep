from __future__ import annotations

from dataclasses import dataclass
from .config import Config


@dataclass(frozen=True)
class MessageEvent:
    event_id: str
    guild_id: str | None
    channel_id: str
    author_id: str
    author_is_bot: bool
    webhook_id: str | None
    content: str
    event_type: str = "MESSAGE_CREATE"
    receiving_bot_id: str = ""
    application_id: str = ""
    policy_version: int = 1
    message_type: int = 0


class RejectedEvent(ValueError):
    pass


def authorize(event: MessageEvent, config: Config) -> MessageEvent:
    checks = (
        (event.event_id.isdecimal(), "invalid event ID"),
        (event.event_type == "MESSAGE_CREATE", "wrong event type"),
        (event.receiving_bot_id == config.bot_user_id, "wrong receiving bot"),
        (event.application_id == config.application_id, "wrong application"),
        (event.policy_version == 1, "wrong policy version"),
        (event.message_type in {0, 19}, "unsupported message type"),
        (event.guild_id == config.guild_id, "wrong guild"),
        (event.channel_id == config.channel_id, "wrong channel"),
        (event.author_id == config.owner_user_id, "wrong author"),
        (not event.author_is_bot, "bot author"),
        (event.webhook_id is None, "webhook author"),
        (bool(event.content.strip()), "empty content"),
        (len(event.content) <= config.max_input_chars, "content exceeds input limit"),
    )
    for allowed, reason in checks:
        if not allowed:
            raise RejectedEvent(reason)
    return event
