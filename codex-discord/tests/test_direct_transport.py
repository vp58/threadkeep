"""Regression tests for direct-only Discord credential transport."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus
from websockets.http11 import Response

from codex_discord_bridge import discord_io


REPO_ROOT = Path(__file__).resolve().parents[2]


class DirectDiscordTransportTests(unittest.TestCase):
    def test_proxy_configuration_is_rejected(self) -> None:
        with (
            mock.patch.object(
                discord_io.urllib.request,
                "getproxies",
                return_value={"https": "https://proxy.invalid"},
            ),
            self.assertRaisesRegex(RuntimeError, "refuses ambient proxy"),
        ):
            discord_io._require_direct_discord_transport()

    def test_gateway_explicitly_disables_proxy_discovery(self) -> None:
        source = (REPO_ROOT / "codex_discord_bridge" / "discord_io.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("proxy=None", source)

    def test_gateway_refuses_cross_origin_redirects(self) -> None:
        connector = discord_io._NoRedirectWebSocketConnect(
            discord_io.GATEWAY,
            proxy=None,
        )
        redirect = InvalidStatus(
            Response(
                302,
                "Found",
                Headers({"Location": "wss://attacker.invalid/gateway"}),
            )
        )
        self.assertIs(connector.process_redirect(redirect), redirect)

    def test_resume_gateway_is_limited_to_discord_wss_hosts(self) -> None:
        self.assertEqual(
            discord_io._gateway_resume_url("wss://gateway-us-east1-b.discord.gg"),
            "wss://gateway-us-east1-b.discord.gg/?v=10&encoding=json",
        )
        for value in (
            "wss://attacker.invalid",
            "ws://gateway.discord.gg",
            "wss://gateway.discord.gg.attacker.invalid",
            "wss://user@gateway.discord.gg",
            "wss://gateway.discord.gg/path",
            "wss://gateway.discord.gg?redirect=1",
        ):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                discord_io._gateway_resume_url(value)

    def test_http_transport_uses_an_explicit_empty_proxy_handler(self) -> None:
        request = discord_io.urllib.request.Request("https://discord.com/api/v10/test")
        opener = mock.Mock()
        with mock.patch.object(
            discord_io.urllib.request, "build_opener", return_value=opener
        ) as build_opener:
            discord_io._direct_urlopen(request, timeout=20)
        handler = build_opener.call_args.args[0]
        self.assertIsInstance(handler, discord_io.urllib.request.ProxyHandler)
        self.assertEqual(handler.proxies, {})
        self.assertIsInstance(
            build_opener.call_args.args[1], discord_io._NoRedirectHandler
        )
        opener.open.assert_called_once_with(request, timeout=20)

    def test_http_transport_refuses_redirect_before_forwarding_headers(self) -> None:
        request = discord_io.urllib.request.Request(
            "https://discord.com/api/v10/test",
            headers={"Authorization": "Bot test-only-value"},
        )
        handler = discord_io._NoRedirectHandler()
        with self.assertRaises(discord_io.urllib.error.HTTPError) as raised:
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {"Location": "https://attacker.invalid/collect"},
                "https://attacker.invalid/collect",
            )
        self.assertEqual(raised.exception.url, request.full_url)
        raised.exception.close()


if __name__ == "__main__":
    unittest.main()
