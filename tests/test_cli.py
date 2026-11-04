import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from pwmanager import cli, crypto, vault

# fake passwords for testing
MASTER_PASSWORD = "test-master-password"
ENTRY_PASSWORD = "dummy-pw-123"

real_new_key_settings = crypto.new_key_settings


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.path = os.path.join(self.temp_dir.name, "test.vault")
        self.clipboard = []
        # fast scrypt, fake clipboard, no 15 second wait
        for patcher in (
            mock.patch.object(crypto, "new_key_settings", lambda: real_new_key_settings(n=2 ** 14)),
            mock.patch.object(cli, "copy_to_clipboard", self.clipboard.append),
            mock.patch.object(cli.time, "sleep"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, *args, hidden=(), typed=()):
        output = io.StringIO()
        with mock.patch.object(cli.getpass, "getpass", side_effect=list(hidden)), \
                mock.patch("builtins.input", side_effect=list(typed)), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            exit_code = cli.main(["--vault", self.path, *args])
        # passwords must never be printed
        self.assertNotIn(MASTER_PASSWORD, output.getvalue())
        self.assertNotIn(ENTRY_PASSWORD, output.getvalue())
        return exit_code, output.getvalue()

    def setup_vault(self):
        self.run_cli("init", hidden=[MASTER_PASSWORD, MASTER_PASSWORD])
        self.run_cli("add", "example.com", hidden=[MASTER_PASSWORD, ENTRY_PASSWORD, ENTRY_PASSWORD], typed=["alice"])

    def test_add_and_list(self):
        self.setup_vault()
        exit_code, output = self.run_cli("list", hidden=[MASTER_PASSWORD])
        self.assertEqual(exit_code, 0)
        self.assertIn("example.com  (alice)", output)

    def test_wrong_master_password(self):
        self.setup_vault()
        exit_code, output = self.run_cli("list", hidden=["wrong-password"])
        self.assertEqual(exit_code, 1)
        self.assertNotIn("example.com", output)

    def test_get_uses_clipboard(self):
        self.setup_vault()
        exit_code, output = self.run_cli("get", "example.com", hidden=[MASTER_PASSWORD])
        self.assertEqual(exit_code, 0)
        self.assertEqual(self.clipboard, [ENTRY_PASSWORD, ""])  # copied, then cleared

    def test_delete(self):
        self.setup_vault()
        self.run_cli("delete", "example.com", hidden=[MASTER_PASSWORD], typed=["y"])
        self.assertEqual(vault.unlock(self.path, MASTER_PASSWORD).entries, {})

    def test_short_master_password(self):
        exit_code, output = self.run_cli("init", hidden=["short", "short"])
        self.assertEqual(exit_code, 1)
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()
