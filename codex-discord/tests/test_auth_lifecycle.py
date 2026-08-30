from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from codex_discord_bridge.codex_auth import (
    _logout_configured_chatgpt,
    logout_chatgpt,
    require_chatgpt_logged_out,
)


class CodexAuthLifecycleTests(unittest.TestCase):
    @staticmethod
    def _codex_home(root: Path) -> Path:
        codex_home = root / "state/home/.codex"
        codex_home.mkdir(parents=True, mode=0o700)
        codex_home.chmod(0o700)
        return codex_home

    def test_logout_uses_reviewed_binary_and_verifies_logged_out(self):
        with TemporaryDirectory(prefix=".threadkeep-auth-test-", dir=Path.home()) as tmp:
            codex_home = self._codex_home(Path(tmp))
            native = Path("/reviewed/native/codex")
            completed = (
                subprocess.CompletedProcess([str(native), "logout"], 0, "ok", ""),
                subprocess.CompletedProcess(
                    [str(native), "login", "status"], 0, "Not logged in", ""
                ),
            )
            with (
                patch(
                    "codex_discord_bridge.codex_auth._reviewed_native_binary",
                    return_value=native,
                ),
                patch(
                    "codex_discord_bridge.codex_auth.subprocess.run",
                    side_effect=completed,
                ) as run,
            ):
                logout_chatgpt(
                    Path("/reviewed/launcher"),
                    codex_home=codex_home,
                    tmp_dir=codex_home.parent,
                )

            self.assertEqual(run.call_args_list[0].args[0], [str(native), "logout"])
            self.assertEqual(
                run.call_args_list[1].args[0],
                [str(native), "login", "status"],
            )
            for call in run.call_args_list:
                environment = call.kwargs["env"]
                self.assertEqual(environment["CODEX_HOME"], str(codex_home))
                self.assertNotIn("OPENAI_API_KEY", environment)
                self.assertNotIn("THREADKEEP_CODEX_DISCORD_BOT_TOKEN", environment)

    def test_logout_rejects_filesystem_artifact_created_by_cli(self):
        with TemporaryDirectory(prefix=".threadkeep-auth-test-", dir=Path.home()) as tmp:
            codex_home = self._codex_home(Path(tmp))

            def create_artifact(*args, **kwargs):
                (codex_home / "auth.json").write_text("{}\n")
                return subprocess.CompletedProcess(args[0], 0, "ok", "")

            with (
                patch(
                    "codex_discord_bridge.codex_auth._reviewed_native_binary",
                    return_value=Path("/reviewed/native/codex"),
                ),
                patch(
                    "codex_discord_bridge.codex_auth.subprocess.run",
                    side_effect=create_artifact,
                ),
                self.assertRaisesRegex(RuntimeError, "filesystem Codex credential"),
            ):
                logout_chatgpt(
                    Path("/reviewed/launcher"),
                    codex_home=codex_home,
                    tmp_dir=codex_home.parent,
                )

    def test_logged_out_check_rejects_ambiguous_status(self):
        with TemporaryDirectory(prefix=".threadkeep-auth-test-", dir=Path.home()) as tmp:
            codex_home = self._codex_home(Path(tmp))
            with (
                patch(
                    "codex_discord_bridge.codex_auth._reviewed_native_binary",
                    return_value=Path("/reviewed/native/codex"),
                ),
                patch(
                    "codex_discord_bridge.codex_auth.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, "unknown", ""),
                ),
                self.assertRaisesRegex(RuntimeError, "logout could not be verified"),
            ):
                require_chatgpt_logged_out(
                    Path("/reviewed/launcher"),
                    codex_home=codex_home,
                    tmp_dir=codex_home.parent,
                )

    def test_configured_logout_revalidates_exact_policy_before_and_after(self):
        config = SimpleNamespace(
            codex_bin=Path("/reviewed/launcher"),
            codex_home=Path("/private/state/home/.codex"),
            state_dir=Path("/private/state"),
            working_directory=Path("/workspace"),
            sandbox_mode="danger-full-access",
        )
        with (
            patch(
                "codex_discord_bridge.config.Config.from_threadkeep",
                return_value=config,
            ),
            patch(
                "codex_discord_bridge.codex_policy.validate_isolated_config"
            ) as validate,
            patch("codex_discord_bridge.codex_auth.logout_chatgpt") as logout,
        ):
            _logout_configured_chatgpt()
        self.assertEqual(validate.call_count, 2)
        validate.assert_called_with(
            config.codex_home,
            config.working_directory,
            False,
        )
        logout.assert_called_once_with(
            config.codex_bin,
            codex_home=config.codex_home,
            tmp_dir=config.state_dir / "tmp",
        )


if __name__ == "__main__":
    unittest.main()
