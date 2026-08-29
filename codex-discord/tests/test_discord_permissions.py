import asyncio
import copy
from datetime import datetime, timedelta, timezone
import unittest

from codex_discord_bridge.config import Config
from codex_discord_bridge.discord_permissions import (
    ADD_REACTIONS,
    ADMINISTRATOR,
    CHANNEL_OBFUSCATED,
    FORBIDDEN_GUILD_PERMISSION_BITS,
    FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS,
    FORBIDDEN_TARGET_PERMISSION_BITS,
    GUILD_CATEGORY,
    PUBLIC_THREAD,
    REQUIRED_PERMISSION_BITS,
    REQUIRED_PERMISSIONS,
    SEND_MESSAGES,
    SEND_MESSAGES_IN_THREADS,
    VIEW_CHANNEL,
    verify_discord_permissions,
)


GUILD_ID = "100"
CHANNEL_ID = "200"
OWNER_ID = "300"
BOT_ID = "400"
APPLICATION_ID = "500"
BOT_ROLE_ID = "600"
GUILD_OWNER_ID = "700"

CFG = Config(
    GUILD_ID,
    CHANNEL_ID,
    OWNER_ID,
    BOT_ID,
    APPLICATION_ID,
)


class FakeRequest:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def __call__(self, token, method, path):
        self.calls.append((token, method, path))
        if method != "GET" or path not in self.responses:
            raise AssertionError(f"unexpected Discord request: {method} {path}")
        return copy.deepcopy(self.responses[path])


def valid_responses():
    thread_guard = sum(FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.values())
    target_channel = {
        "id": CHANNEL_ID,
        "guild_id": GUILD_ID,
        "type": 0,
        "flags": 0,
        "parent_id": None,
        "permission_overwrites": [
            overwrite(GUILD_ID, 0, deny=thread_guard),
            overwrite(BOT_ID, 1, allow=REQUIRED_PERMISSION_BITS["CREATE_PUBLIC_THREADS"]),
        ],
    }
    return {
        "/users/@me": {"id": BOT_ID, "bot": True},
        "/oauth2/applications/@me": {
            "id": APPLICATION_ID,
            "bot": {"id": BOT_ID},
        },
        f"/channels/{CHANNEL_ID}": target_channel,
        f"/guilds/{GUILD_ID}": {
            "id": GUILD_ID,
            "owner_id": GUILD_OWNER_ID,
            "roles": [
                {"id": GUILD_ID, "permissions": str(VIEW_CHANNEL)},
                {"id": BOT_ROLE_ID, "permissions": str(REQUIRED_PERMISSIONS)},
            ],
        },
        f"/guilds/{GUILD_ID}/members/{BOT_ID}": {
            "user": {"id": BOT_ID},
            "roles": [BOT_ROLE_ID],
            "pending": False,
            "communication_disabled_until": None,
        },
        f"/guilds/{GUILD_ID}/channels": [target_channel],
        f"/guilds/{GUILD_ID}/threads/active": {
            "threads": [],
            "members": [],
        },
    }


def overwrite(target_id, target_type, *, allow=0, deny=0):
    return {
        "id": target_id,
        "type": target_type,
        "allow": str(allow),
        "deny": str(deny),
    }


class DiscordPermissionTests(unittest.TestCase):
    def verify(self, responses, config=CFG):
        request = FakeRequest(responses)
        result = asyncio.run(verify_discord_permissions("token", config, request=request))
        return result, request

    def test_all_required_permissions_are_allowed(self):
        result, request = self.verify(valid_responses())
        self.assertIsNone(result)
        self.assertEqual(
            [path for _, _, path in request.calls],
            [
                "/users/@me",
                "/oauth2/applications/@me",
                f"/channels/{CHANNEL_ID}",
                f"/guilds/{GUILD_ID}",
                f"/guilds/{GUILD_ID}/members/{BOT_ID}",
                f"/guilds/{GUILD_ID}/channels",
                f"/guilds/{GUILD_ID}/threads/active",
            ],
        )
        self.assertEqual(REQUIRED_PERMISSIONS, 0x0000004800010C40)

    def test_each_denied_required_permission_fails(self):
        self.assertEqual(
            set(REQUIRED_PERMISSION_BITS),
            {
                "ADD_REACTIONS",
                "VIEW_CHANNEL",
                "SEND_MESSAGES",
                "READ_MESSAGE_HISTORY",
                "CREATE_PUBLIC_THREADS",
                "SEND_MESSAGES_IN_THREADS",
            },
        )
        for name, permission in REQUIRED_PERMISSION_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
                    overwrite(BOT_ID, 1, deny=permission)
                ]
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_private_everyone_baseline_fails_even_when_bot_can_view(self):
        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
            overwrite(GUILD_ID, 0, deny=VIEW_CHANNEL),
            overwrite(BOT_ID, 1, allow=VIEW_CHANNEL),
        ]
        with self.assertRaisesRegex(RuntimeError, "public Discord channel"):
            self.verify(responses)

    def test_owner_private_requires_and_accepts_a_private_everyone_baseline(self):
        responses = valid_responses()
        thread_guard = sum(FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.values())
        responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
            overwrite(GUILD_ID, 0, deny=VIEW_CHANNEL | thread_guard),
            overwrite(
                BOT_ID,
                1,
                allow=(
                    VIEW_CHANNEL
                    | REQUIRED_PERMISSION_BITS["CREATE_PUBLIC_THREADS"]
                ),
            ),
        ]
        private_config = Config(
            GUILD_ID,
            CHANNEL_ID,
            OWNER_ID,
            BOT_ID,
            APPLICATION_ID,
            channel_trust="owner_private",
        )
        self.assertIsNone(self.verify(responses, private_config)[0])

        public_responses = valid_responses()
        with self.assertRaisesRegex(RuntimeError, "owner_private"):
            self.verify(public_responses, private_config)

    def test_public_members_cannot_manage_or_create_threads(self):
        self.assertEqual(
            set(FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS),
            {"MANAGE_THREADS", "CREATE_PUBLIC_THREADS", "CREATE_PRIVATE_THREADS"},
        )
        for name, permission in FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                guard = sum(FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.values())
                responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
                    overwrite(GUILD_ID, 0, allow=permission, deny=guard),
                    overwrite(
                        BOT_ID,
                        1,
                        allow=REQUIRED_PERMISSION_BITS["CREATE_PUBLIC_THREADS"],
                    ),
                ]
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_everyone_overwrite_must_explicitly_deny_each_thread_power(self):
        guard = sum(FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.values())
        for name, permission in FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"][0] = (
                    overwrite(GUILD_ID, 0, deny=guard & ~permission)
                )
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_other_role_allow_cannot_restore_thread_powers(self):
        other_role_id = "601"
        for name, permission in FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                responses[f"/guilds/{GUILD_ID}"]["roles"].append(
                    {"id": other_role_id, "permissions": "0"}
                )
                responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"].append(
                    overwrite(other_role_id, 0, allow=permission)
                )
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_other_member_allow_cannot_restore_thread_powers(self):
        other_member_id = "800"
        for name, permission in FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"].append(
                    overwrite(other_member_id, 1, allow=permission)
                )
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_bot_role_allow_cannot_restore_thread_powers(self):
        for name, permission in FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"].append(
                    overwrite(BOT_ROLE_ID, 0, allow=permission)
                )
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_only_bot_member_allow_restores_create_public_threads(self):
        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
            responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"][0],
            overwrite(BOT_ROLE_ID, 0, allow=REQUIRED_PERMISSION_BITS["CREATE_PUBLIC_THREADS"]),
        ]
        with self.assertRaisesRegex(RuntimeError, "bot member overwrite"):
            self.verify(responses)

    def test_bot_member_cannot_restore_manage_or_private_threads(self):
        for name in ("MANAGE_THREADS", "CREATE_PRIVATE_THREADS"):
            with self.subTest(permission=name):
                responses = valid_responses()
                responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"][1] = (
                    overwrite(
                        BOT_ID,
                        1,
                        allow=(
                            REQUIRED_PERMISSION_BITS["CREATE_PUBLIC_THREADS"]
                            | FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS[name]
                        ),
                    )
                )
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_unrelated_harmless_public_permission_is_preserved(self):
        responses = valid_responses()
        use_external_emojis = 1 << 18
        responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"].append(
            overwrite("800", 1, allow=use_external_emojis)
        )
        self.verify(responses)

    def test_administrator_is_rejected_as_excess_privilege(self):
        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}"]["roles"][1]["permissions"] = str(
            ADMINISTRATOR
        )
        responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
            overwrite(BOT_ROLE_ID, 0, deny=REQUIRED_PERMISSIONS),
            overwrite(BOT_ID, 1, deny=REQUIRED_PERMISSIONS),
        ]
        with self.assertRaisesRegex(RuntimeError, "forbidden guild permissions.*ADMINISTRATOR"):
            self.verify(responses)

    def test_each_forbidden_guild_permission_is_rejected(self):
        for name, permission in FORBIDDEN_GUILD_PERMISSION_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                responses[f"/guilds/{GUILD_ID}"]["roles"][1]["permissions"] = str(
                    REQUIRED_PERMISSIONS | permission
                )
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_bot_must_not_own_the_guild(self):
        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}"]["owner_id"] = BOT_ID
        responses[f"/guilds/{GUILD_ID}"]["roles"][1]["permissions"] = "0"
        responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
            overwrite(BOT_ROLE_ID, 0, deny=REQUIRED_PERMISSIONS),
            overwrite(BOT_ID, 1, deny=REQUIRED_PERMISSIONS),
        ]
        with self.assertRaisesRegex(RuntimeError, "must not own"):
            self.verify(responses)

    def test_channel_overwrite_cannot_grant_forbidden_permissions(self):
        responses = valid_responses()
        manage_webhooks = 1 << 29
        responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
            overwrite(BOT_ID, 1, allow=manage_webhooks)
        ]
        with self.assertRaisesRegex(
            RuntimeError, "forbidden effective channel permissions.*MANAGE_WEBHOOKS"
        ):
            self.verify(responses)

    def test_each_forbidden_target_permission_is_rejected(self):
        for name, permission in FORBIDDEN_TARGET_PERMISSION_BITS.items():
            with self.subTest(permission=name):
                responses = valid_responses()
                responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
                    overwrite(BOT_ID, 1, allow=permission)
                ]
                with self.assertRaisesRegex(RuntimeError, name):
                    self.verify(responses)

    def test_unrelated_visible_channel_is_rejected(self):
        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}/channels"].append(
            {
                "id": "201",
                "guild_id": GUILD_ID,
                "type": 0,
                "parent_id": None,
                "permission_overwrites": [],
            }
        )
        with self.assertRaisesRegex(RuntimeError, "unrelated guild channel"):
            self.verify(responses)

    def test_unrelated_hidden_channel_is_allowed(self):
        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}/channels"].append(
            {
                "id": "201",
                "guild_id": GUILD_ID,
                "type": 0,
                "parent_id": None,
                "permission_overwrites": [
                    overwrite(BOT_ID, 1, deny=VIEW_CHANNEL)
                ],
            }
        )
        self.verify(responses)

    def test_only_target_parent_category_may_be_visible(self):
        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["parent_id"] = "250"
        responses[f"/guilds/{GUILD_ID}/channels"].append(
            {
                "id": "250",
                "guild_id": GUILD_ID,
                "type": GUILD_CATEGORY,
                "parent_id": None,
                "permission_overwrites": [],
            }
        )
        self.verify(responses)

        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}/channels"].append(
            {
                "id": "251",
                "guild_id": GUILD_ID,
                "type": GUILD_CATEGORY,
                "parent_id": None,
                "permission_overwrites": [],
            }
        )
        with self.assertRaisesRegex(RuntimeError, "unrelated guild channel"):
            self.verify(responses)

    def test_target_parent_must_be_an_enumerated_category(self):
        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["parent_id"] = "250"
        with self.assertRaisesRegex(RuntimeError, "omitted.*parent category"):
            self.verify(responses)

        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["parent_id"] = "250"
        responses[f"/guilds/{GUILD_ID}/channels"].append(
            {
                "id": "250",
                "guild_id": GUILD_ID,
                "type": 0,
                "parent_id": None,
                "permission_overwrites": [
                    overwrite(BOT_ID, 1, deny=VIEW_CHANNEL)
                ],
            }
        )
        with self.assertRaisesRegex(RuntimeError, "must be a GUILD_CATEGORY"):
            self.verify(responses)

    def test_only_public_threads_beneath_target_may_be_accessible(self):
        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}/threads/active"]["threads"] = [
            {
                "id": "800",
                "guild_id": GUILD_ID,
                "type": PUBLIC_THREAD,
                "parent_id": CHANNEL_ID,
            }
        ]
        self.verify(responses)

        for thread_type, parent_id in ((12, CHANNEL_ID), (PUBLIC_THREAD, "201")):
            with self.subTest(thread_type=thread_type, parent_id=parent_id):
                responses = valid_responses()
                responses[f"/guilds/{GUILD_ID}/threads/active"]["threads"] = [
                    {
                        "id": "800",
                        "guild_id": GUILD_ID,
                        "type": thread_type,
                        "parent_id": parent_id,
                    }
                ]
                with self.assertRaisesRegex(RuntimeError, "unrelated active thread"):
                    self.verify(responses)

    def test_role_aggregation_and_member_overwrite_precedence(self):
        second_role = "601"
        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}"]["roles"].append(
            {"id": second_role, "permissions": "0"}
        )
        responses[f"/guilds/{GUILD_ID}/members/{BOT_ID}"]["roles"].append(
            second_role
        )
        responses[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
            overwrite(
                GUILD_ID,
                0,
                deny=(
                    SEND_MESSAGES
                    | sum(FORBIDDEN_PUBLIC_MEMBER_THREAD_BITS.values())
                ),
            ),
            overwrite(
                BOT_ROLE_ID,
                0,
                deny=ADD_REACTIONS | SEND_MESSAGES_IN_THREADS,
            ),
            overwrite(second_role, 0, allow=ADD_REACTIONS),
            overwrite(
                BOT_ID,
                1,
                allow=(
                    SEND_MESSAGES
                    | SEND_MESSAGES_IN_THREADS
                    | REQUIRED_PERMISSION_BITS["CREATE_PUBLIC_THREADS"]
                ),
            ),
        ]
        self.verify(responses)

    def test_malformed_payloads_fail_closed(self):
        cases = []

        malformed_role_permissions = valid_responses()
        malformed_role_permissions[f"/guilds/{GUILD_ID}"]["roles"][1][
            "permissions"
        ] = REQUIRED_PERMISSIONS
        cases.append(("permissions", malformed_role_permissions))

        missing_role = valid_responses()
        missing_role[f"/guilds/{GUILD_ID}"]["roles"].pop()
        cases.append(("unknown guild role", missing_role))

        duplicate_overwrite = valid_responses()
        duplicate_overwrite[f"/channels/{CHANNEL_ID}"]["permission_overwrites"] = [
            overwrite(BOT_ID, 1),
            overwrite(BOT_ID, 1),
        ]
        cases.append(("duplicate", duplicate_overwrite))

        unknown_overwrite_type = valid_responses()
        unknown_overwrite_type[f"/channels/{CHANNEL_ID}"][
            "permission_overwrites"
        ] = [overwrite(BOT_ID, 2)]
        cases.append(("unknown permission overwrite type", unknown_overwrite_type))

        unknown_role_overwrite = valid_responses()
        unknown_role_overwrite[f"/channels/{CHANNEL_ID}"][
            "permission_overwrites"
        ] = [overwrite("999", 0)]
        cases.append(("unknown guild role", unknown_role_overwrite))

        malformed_timeout = valid_responses()
        malformed_timeout[f"/guilds/{GUILD_ID}/members/{BOT_ID}"][
            "communication_disabled_until"
        ] = "tomorrow"
        cases.append(("communication_disabled_until", malformed_timeout))

        for expected, responses in cases:
            with self.subTest(expected=expected), self.assertRaisesRegex(
                RuntimeError, expected
            ):
                self.verify(responses)

    def test_pending_member_is_rejected(self):
        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}/members/{BOT_ID}"]["pending"] = True
        with self.assertRaisesRegex(RuntimeError, "pending"):
            self.verify(responses)

    def test_active_timeout_is_rejected_and_expired_timeout_is_allowed(self):
        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}/members/{BOT_ID}"][
            "communication_disabled_until"
        ] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        with self.assertRaisesRegex(RuntimeError, "active timeout"):
            self.verify(responses)

        responses[f"/guilds/{GUILD_ID}/members/{BOT_ID}"][
            "communication_disabled_until"
        ] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.verify(responses)

    def test_wrong_bot_and_application_identities_are_rejected(self):
        responses = valid_responses()
        responses["/users/@me"]["id"] = "401"
        with self.assertRaisesRegex(RuntimeError, "bot identity"):
            self.verify(responses)

        responses = valid_responses()
        responses["/oauth2/applications/@me"]["id"] = "501"
        with self.assertRaisesRegex(RuntimeError, "application identity"):
            self.verify(responses)

        responses = valid_responses()
        responses["/oauth2/applications/@me"]["bot"]["id"] = "401"
        with self.assertRaisesRegex(RuntimeError, "different bot"):
            self.verify(responses)

        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}/members/{BOT_ID}"]["user"]["id"] = "401"
        with self.assertRaisesRegex(RuntimeError, "different bot"):
            self.verify(responses)

    def test_wrong_guild_and_channel_response_are_rejected(self):
        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["guild_id"] = "101"
        with self.assertRaisesRegex(RuntimeError, "different guild"):
            self.verify(responses)

        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["id"] = "201"
        with self.assertRaisesRegex(RuntimeError, "different channel"):
            self.verify(responses)

        responses = valid_responses()
        responses[f"/guilds/{GUILD_ID}"]["id"] = "101"
        with self.assertRaisesRegex(RuntimeError, "different guild"):
            self.verify(responses)

    def test_wrong_channel_type_is_rejected(self):
        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["type"] = 5
        with self.assertRaisesRegex(RuntimeError, "GUILD_TEXT"):
            self.verify(responses)

    def test_obfuscated_channel_is_rejected(self):
        responses = valid_responses()
        responses[f"/channels/{CHANNEL_ID}"]["flags"] = CHANNEL_OBFUSCATED
        with self.assertRaisesRegex(RuntimeError, "obfuscated"):
            self.verify(responses)


if __name__ == "__main__":
    unittest.main()
