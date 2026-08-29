"""Mocked tests for the Claude Discord least-privilege verifier."""
from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "conversations"))

from discord_permissions import (  # noqa: E402
    ADMINISTRATOR,
    ATTACH_FILES,
    CHANNEL_OBFUSCATED,
    CHAT_REQUIRED_PERMISSION_BITS,
    CHAT_REQUIRED_PERMISSIONS,
    CREATE_PRIVATE_THREADS,
    CREATE_PUBLIC_THREADS,
    FORBIDDEN_CHANNEL_PERMISSION_BITS,
    FORBIDDEN_GUILD_PERMISSION_BITS,
    GUILD_CATEGORY,
    MANAGE_THREADS,
    PUBLIC_CHAT_FORBIDDEN_PERMISSION_BITS,
    PUBLIC_THREAD,
    PermissionConfig,
    VIEW_CHANNEL,
    harden_registered_state,
    load_registered_threads,
    verify_discord_permissions,
)


GUILD_ID = "111111111111111111"
CHAT_ID = "222222222222222222"
ERRORS_ID = "333333333333333333"
BOT_ID = "444444444444444444"
APPLICATION_ID = "555555555555555555"
BOT_ROLE_ID = "666666666666666666"
GUILD_OWNER_ID = "777777777777777777"
THREAD_ID = "888888888888888888"


class FakeRequest:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, token: str, method: str, path: str) -> object:
        self.calls.append((token, method, path))
        if token != "token" or method != "GET" or path not in self.responses:
            raise AssertionError(f"unexpected Discord request: {method} {path}")
        return copy.deepcopy(self.responses[path])


def overwrite(target_id: str, target_type: int, *, allow: int = 0, deny: int = 0):
    return {
        "id": target_id,
        "type": target_type,
        "allow": str(allow),
        "deny": str(deny),
    }


def root_channel(channel_id: str, *, parent_id: str | None = None):
    return {
        "id": channel_id,
        "guild_id": GUILD_ID,
        "type": 0,
        "flags": 0,
        "parent_id": parent_id,
        "permission_overwrites": [],
    }


def archived_response(threads: list[dict] | None = None, *, has_more: bool = False):
    return {"threads": threads or [], "members": [], "has_more": has_more}


def valid_responses() -> dict[str, object]:
    chat = root_channel(CHAT_ID)
    errors = root_channel(ERRORS_ID)
    return {
        "/users/@me": {"id": BOT_ID, "bot": True},
        "/oauth2/applications/@me": {
            "id": APPLICATION_ID,
            "bot": {"id": BOT_ID},
        },
        "/users/@me/guilds?limit=2": [{"id": GUILD_ID}],
        f"/channels/{CHAT_ID}": chat,
        f"/channels/{ERRORS_ID}": errors,
        f"/guilds/{GUILD_ID}": {
            "id": GUILD_ID,
            "owner_id": GUILD_OWNER_ID,
            "roles": [
                {"id": GUILD_ID, "permissions": str(VIEW_CHANNEL)},
                {"id": BOT_ROLE_ID, "permissions": str(CHAT_REQUIRED_PERMISSIONS)},
            ],
        },
        f"/guilds/{GUILD_ID}/members/{BOT_ID}": {
            "user": {"id": BOT_ID},
            "roles": [BOT_ROLE_ID],
            "pending": False,
            "communication_disabled_until": None,
        },
        f"/guilds/{GUILD_ID}/channels": [chat, errors],
        f"/guilds/{GUILD_ID}/threads/active": {"threads": [], "members": []},
        f"/channels/{CHAT_ID}/threads/archived/public?limit=100": archived_response(),
        f"/channels/{ERRORS_ID}/threads/archived/public?limit=100": archived_response(),
        f"/channels/{CHAT_ID}/users/@me/threads/archived/private?limit=1": archived_response(),
        f"/channels/{ERRORS_ID}/users/@me/threads/archived/private?limit=1": archived_response(),
    }


def config(conversations_dir: Path = Path("/unused")) -> PermissionConfig:
    return PermissionConfig(
        guild_id=GUILD_ID,
        chat_channel_id=CHAT_ID,
        errors_channel_id=ERRORS_ID,
        bot_user_id=BOT_ID,
        application_id=APPLICATION_ID,
        conversations_dir=conversations_dir,
    )


def thread_payload(
    thread_id: str = THREAD_ID,
    *,
    parent_id: str = CHAT_ID,
    thread_type: int = PUBLIC_THREAD,
    archived: bool = False,
    archive_timestamp: str = "2026-08-01T00:00:00+00:00",
) -> dict:
    return {
        "id": thread_id,
        "guild_id": GUILD_ID,
        "parent_id": parent_id,
        "type": thread_type,
        "thread_metadata": {
            "archived": archived,
            "archive_timestamp": archive_timestamp,
        },
    }


class ClaudeDiscordPermissionTests(unittest.TestCase):
    def verify(
        self,
        responses: dict[str, object],
        *,
        registered_threads: set[str] | None = None,
    ):
        request = FakeRequest(responses)
        result = verify_discord_permissions(
            "token",
            config(),
            request=request,
            registered_threads=registered_threads or set(),
        )
        return result, request

    def test_reviewed_permissions_and_read_only_request_sequence(self) -> None:
        result, request = self.verify(valid_responses())
        self.assertEqual(CHAT_REQUIRED_PERMISSIONS, 0x0000004800018C40)
        self.assertIn("ATTACH_FILES", CHAT_REQUIRED_PERMISSION_BITS)
        self.assertIn("CREATE_PUBLIC_THREADS", CHAT_REQUIRED_PERMISSION_BITS)
        self.assertEqual(result["guild_id"], GUILD_ID)
        self.assertEqual(result["visible_thread_count"], 0)
        self.assertTrue(request.calls)
        self.assertTrue(all(method == "GET" for _, method, _ in request.calls))

    def test_bot_must_belong_to_exactly_one_configured_guild(self) -> None:
        for guilds in ([], [{"id": GUILD_ID}, {"id": "999999999999999999"}], [{"id": "999999999999999999"}]):
            with self.subTest(guilds=guilds):
                responses = valid_responses()
                responses["/users/@me/guilds?limit=2"] = guilds
                with self.assertRaisesRegex(RuntimeError, "exactly the configured guild"):
                    self.verify(responses)

    def test_exact_bot_and_application_are_required(self) -> None:
        responses = valid_responses()
        responses["/users/@me"]["id"] = "999999999999999999"  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "bot identity"):
            self.verify(responses)

        responses = valid_responses()
        responses["/oauth2/applications/@me"]["id"] = "999999999999999999"  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "application identity"):
            self.verify(responses)

        responses = valid_responses()
        responses["/oauth2/applications/@me"]["bot"]["id"] = "999999999999999999"  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "different bot"):
            self.verify(responses)

    def test_chat_must_be_public_to_everyone(self) -> None:
        responses = valid_responses()
        chat = responses[f"/channels/{CHAT_ID}"]
        assert isinstance(chat, dict)
        chat["permission_overwrites"] = [overwrite(GUILD_ID, 0, deny=VIEW_CHANNEL)]
        with self.assertRaisesRegex(RuntimeError, "not public"):
            self.verify(responses)

    def test_everyone_cannot_create_or_manage_threads_in_public_chat(self) -> None:
        expected = {
            "MANAGE_THREADS": MANAGE_THREADS,
            "CREATE_PUBLIC_THREADS": CREATE_PUBLIC_THREADS,
            "CREATE_PRIVATE_THREADS": CREATE_PRIVATE_THREADS,
        }
        self.assertEqual(PUBLIC_CHAT_FORBIDDEN_PERMISSION_BITS, expected)
        for name, permission in expected.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                chat = responses[f"/channels/{CHAT_ID}"]
                assert isinstance(chat, dict)
                chat["permission_overwrites"] = [
                    overwrite(GUILD_ID, 0, allow=permission)
                ]
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_each_required_chat_permission_is_enforced(self) -> None:
        for name, permission in CHAT_REQUIRED_PERMISSION_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                chat = responses[f"/channels/{CHAT_ID}"]
                assert isinstance(chat, dict)
                chat["permission_overwrites"] = [
                    overwrite(BOT_ID, 1, deny=permission)
                ]
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_each_forbidden_guild_permission_is_rejected(self) -> None:
        for name, permission in FORBIDDEN_GUILD_PERMISSION_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                guild = responses[f"/guilds/{GUILD_ID}"]
                assert isinstance(guild, dict)
                guild["roles"][1]["permissions"] = str(  # type: ignore[index]
                    CHAT_REQUIRED_PERMISSIONS | permission
                )
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_each_forbidden_channel_permission_is_rejected(self) -> None:
        self.assertNotIn("ATTACH_FILES", FORBIDDEN_CHANNEL_PERMISSION_BITS)
        for name, permission in FORBIDDEN_CHANNEL_PERMISSION_BITS.items():
            if permission in FORBIDDEN_GUILD_PERMISSION_BITS.values():
                continue
            with self.subTest(permission=name):
                responses = valid_responses()
                chat = responses[f"/channels/{CHAT_ID}"]
                assert isinstance(chat, dict)
                chat["permission_overwrites"] = [
                    overwrite(BOT_ID, 1, allow=permission)
                ]
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_bot_must_not_be_owner_admin_pending_or_timed_out(self) -> None:
        responses = valid_responses()
        guild = responses[f"/guilds/{GUILD_ID}"]
        assert isinstance(guild, dict)
        guild["owner_id"] = BOT_ID
        with self.assertRaisesRegex(RuntimeError, "must not own"):
            self.verify(responses)

        responses = valid_responses()
        guild = responses[f"/guilds/{GUILD_ID}"]
        assert isinstance(guild, dict)
        guild["roles"][1]["permissions"] = str(ADMINISTRATOR)  # type: ignore[index]
        with self.assertRaisesRegex(RuntimeError, "ADMINISTRATOR"):
            self.verify(responses)

        responses = valid_responses()
        member = responses[f"/guilds/{GUILD_ID}/members/{BOT_ID}"]
        assert isinstance(member, dict)
        member["pending"] = True
        with self.assertRaisesRegex(RuntimeError, "pending"):
            self.verify(responses)

        responses = valid_responses()
        member = responses[f"/guilds/{GUILD_ID}/members/{BOT_ID}"]
        assert isinstance(member, dict)
        member["communication_disabled_until"] = "2999-01-01T00:00:00+00:00"
        with self.assertRaisesRegex(RuntimeError, "active timeout"):
            self.verify(responses)

    def test_only_roots_and_necessary_parent_categories_may_be_visible(self) -> None:
        responses = valid_responses()
        unrelated = root_channel("999999999999999999")
        channels = responses[f"/guilds/{GUILD_ID}/channels"]
        assert isinstance(channels, list)
        channels.append(unrelated)
        with self.assertRaisesRegex(RuntimeError, "unrelated guild channel"):
            self.verify(responses)

        responses = valid_responses()
        unrelated = root_channel("999999999999999999")
        unrelated["permission_overwrites"] = [
            overwrite(BOT_ID, 1, deny=VIEW_CHANNEL)
        ]
        channels = responses[f"/guilds/{GUILD_ID}/channels"]
        assert isinstance(channels, list)
        channels.append(unrelated)
        self.verify(responses)

        responses = valid_responses()
        for root_id in (CHAT_ID, ERRORS_ID):
            root = responses[f"/channels/{root_id}"]
            assert isinstance(root, dict)
            root["parent_id"] = "999999999999999999"
        channels = responses[f"/guilds/{GUILD_ID}/channels"]
        assert isinstance(channels, list)
        channels.append(
            {
                "id": "999999999999999999",
                "guild_id": GUILD_ID,
                "type": GUILD_CATEGORY,
                "parent_id": None,
                "permission_overwrites": [],
            }
        )
        self.verify(responses)

    def test_registered_public_active_thread_is_allowed(self) -> None:
        responses = valid_responses()
        active = responses[f"/guilds/{GUILD_ID}/threads/active"]
        assert isinstance(active, dict)
        active["threads"] = [thread_payload()]
        result, _ = self.verify(responses, registered_threads={THREAD_ID})
        self.assertEqual(result["visible_thread_count"], 1)

    def test_unregistered_or_nonpublic_active_thread_is_rejected(self) -> None:
        responses = valid_responses()
        active = responses[f"/guilds/{GUILD_ID}/threads/active"]
        assert isinstance(active, dict)
        active["threads"] = [thread_payload()]
        with self.assertRaisesRegex(RuntimeError, "unregistered"):
            self.verify(responses)

        responses = valid_responses()
        active = responses[f"/guilds/{GUILD_ID}/threads/active"]
        assert isinstance(active, dict)
        active["threads"] = [thread_payload(thread_type=12)]
        with self.assertRaisesRegex(RuntimeError, "non-public"):
            self.verify(responses, registered_threads={THREAD_ID})

        responses = valid_responses()
        active = responses[f"/guilds/{GUILD_ID}/threads/active"]
        assert isinstance(active, dict)
        active["threads"] = [thread_payload(parent_id=ERRORS_ID)]
        with self.assertRaisesRegex(RuntimeError, "another channel"):
            self.verify(responses, registered_threads={THREAD_ID})

    def test_registered_archived_thread_and_pagination_are_allowed(self) -> None:
        second_thread = "999999999999999999"
        first = thread_payload(archived=True)
        second = thread_payload(
            second_thread,
            archived=True,
            archive_timestamp="2026-07-01T00:00:00+00:00",
        )
        responses = valid_responses()
        responses[
            f"/channels/{CHAT_ID}/threads/archived/public?limit=100"
        ] = archived_response([first], has_more=True)
        responses[
            f"/channels/{CHAT_ID}/threads/archived/public?limit=100&before=2026-08-01T00%3A00%3A00%2B00%3A00"
        ] = archived_response([second])
        result, _ = self.verify(
            responses, registered_threads={THREAD_ID, second_thread}
        )
        self.assertEqual(result["visible_thread_count"], 2)

    def test_unregistered_public_or_any_private_archived_thread_is_rejected(self) -> None:
        responses = valid_responses()
        responses[
            f"/channels/{CHAT_ID}/threads/archived/public?limit=100"
        ] = archived_response([thread_payload(archived=True)])
        with self.assertRaisesRegex(RuntimeError, "unregistered"):
            self.verify(responses)

        responses = valid_responses()
        responses[
            f"/channels/{CHAT_ID}/users/@me/threads/archived/private?limit=1"
        ] = archived_response(
            [thread_payload(thread_type=12, archived=True)]
        )
        with self.assertRaisesRegex(RuntimeError, "private archived"):
            self.verify(responses)

    def test_obfuscated_root_is_rejected(self) -> None:
        responses = valid_responses()
        chat = responses[f"/channels/{CHAT_ID}"]
        assert isinstance(chat, dict)
        chat["flags"] = CHANNEL_OBFUSCATED
        with self.assertRaisesRegex(RuntimeError, "obfuscated"):
            self.verify(responses)


class RegisteredThreadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "conversations"
        (self.root / "active").mkdir(parents=True)
        self.session_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        self.conversation = self.root / "active" / f"{self.session_id}.md"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_registration(self, *, thread_id: str = THREAD_ID, registry_thread: str = THREAD_ID) -> None:
        self.conversation.write_text(
            "\n".join(
                [
                    "---",
                    f"claude_session_id: {self.session_id}",
                    f"discord_channel_id: {CHAT_ID}",
                    f"discord_thread_id: {thread_id}",
                    "---",
                    "# Conversation",
                ]
            )
            + "\n"
        )
        self.conversation.chmod(0o600)
        registry = self.root / "_registry.json"
        registry.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "conversations": {
                        self.session_id: {
                            "session_id": self.session_id,
                            "thread_id": registry_thread,
                            "channel_id": CHAT_ID,
                        }
                    },
                    "by_thread": {registry_thread: self.session_id},
                    "last_regenerated": None,
                }
            )
        )
        registry.chmod(0o600)

    def test_exact_registry_and_conversation_binding_is_loaded_read_only(self) -> None:
        self.write_registration()
        before = (self.root / "_registry.json").read_bytes()
        self.assertEqual(load_registered_threads(self.root, CHAT_ID), {THREAD_ID})
        self.assertEqual((self.root / "_registry.json").read_bytes(), before)

    def test_registry_file_disagreement_fails_closed(self) -> None:
        self.write_registration(registry_thread="999999999999999999")
        with self.assertRaisesRegex(RuntimeError, "disagree"):
            load_registered_threads(self.root, CHAT_ID)

    def test_missing_registry_is_allowed_only_when_no_thread_is_registered(self) -> None:
        self.assertEqual(load_registered_threads(self.root, CHAT_ID), set())
        self.write_registration()
        (self.root / "_registry.json").unlink()
        with self.assertRaisesRegex(RuntimeError, "registry is missing"):
            load_registered_threads(self.root, CHAT_ID)

    def test_symlinked_registry_or_conversation_is_rejected(self) -> None:
        self.write_registration()
        registry = self.root / "_registry.json"
        external = Path(self.temporary.name) / "external-registry.json"
        registry.replace(external)
        registry.symlink_to(external)
        with self.assertRaisesRegex(RuntimeError, "must not use symlinks"):
            load_registered_threads(self.root, CHAT_ID)

        registry.unlink()
        external.replace(registry)
        external_conversation = Path(self.temporary.name) / "external.md"
        self.conversation.replace(external_conversation)
        self.conversation.symlink_to(external_conversation)
        with self.assertRaisesRegex(RuntimeError, "must not use symlinks"):
            load_registered_threads(self.root, CHAT_ID)

    def test_world_readable_registration_is_rejected(self) -> None:
        self.write_registration()
        registry = self.root / "_registry.json"
        registry.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "mode 0600"):
            load_registered_threads(self.root, CHAT_ID)

    def test_safe_legacy_mode_migration_hardens_registry_transcript_and_db(self) -> None:
        self.write_registration()
        registry = self.root / "_registry.json"
        state = self.root / "state"
        state.mkdir(mode=0o755)
        database = state / "mq.sqlite3"
        database.write_bytes(b"sqlite")
        for path in (registry, self.conversation, database):
            path.chmod(0o644)
        self.assertEqual(
            load_registered_threads(
                self.root, CHAT_ID, allow_legacy_readonly=True
            ),
            {THREAD_ID},
        )
        result = harden_registered_state(self.root)
        self.assertGreaterEqual(result["files"], 3)
        for path in (registry, self.conversation, database):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(load_registered_threads(self.root, CHAT_ID), {THREAD_ID})

    def test_unsafe_writable_legacy_state_is_not_migrated(self) -> None:
        self.write_registration()
        registry = self.root / "_registry.json"
        registry.chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, "unsafe legacy mode"):
            harden_registered_state(self.root)

        registry.chmod(0o600)
        self.conversation.chmod(0o666)
        with self.assertRaisesRegex(RuntimeError, "mode 0600"):
            load_registered_threads(self.root, CHAT_ID)


if __name__ == "__main__":
    unittest.main()
