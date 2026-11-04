import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from pwmanager import cli, crypto, vault

# fake passwords for testing
MASTER = "test-master-password"
ENTRY_PW = "dummy-pw-123"

real_new_kdf_params = crypto.new_kdf_params


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "test.vault")
        self.clipboard = []
        # fast scrypt, fake clipboard, no 15 second wait
        for p in (
            mock.patch.object(crypto, "new_kdf_params", lambda: real_new_kdf_params(n=2 ** 14)),
            mock.patch.object(cli, "copy_to_clipboard", self.clipboard.append),
            mock.patch.object(cli.time, "sleep"),
        ):
            p.start()
            self.addCleanup(p.stop)

    def run_cli(self, *args, hidden=(), typed=()):
        out = io.StringIO()
        with mock.patch.object(cli.getpass, "getpass", side_effect=list(hidden)), \
                mock.patch("builtins.input", side_effect=list(typed)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = cli.main(["--vault", self.path, *args])
        # passwords must never be printed
        self.assertNotIn(MASTER, out.getvalue())
        self.assertNotIn(ENTRY_PW, out.getvalue())
        return code, out.getvalue()

    def setup_vault(self):
        self.run_cli("init", hidden=[MASTER, MASTER])
        self.run_cli("add", "example.com", hidden=[MASTER, ENTRY_PW, ENTRY_PW], typed=["alice"])

    def test_add_and_list(self):
        self.setup_vault()
        code, out = self.run_cli("list", hidden=[MASTER])
        self.assertEqual(code, 0)
        self.assertIn("example.com  (alice)", out)

    def test_wrong_master_password(self):
        self.setup_vault()
        code, out = self.run_cli("list", hidden=["wrong-password"])
        self.assertEqual(code, 1)
        self.assertNotIn("example.com", out)

    def test_get_uses_clipboard(self):
        self.setup_vault()
        code, out = self.run_cli("get", "example.com", hidden=[MASTER])
        self.assertEqual(code, 0)
        self.assertEqual(self.clipboard, [ENTRY_PW, ""])  # copied, then cleared

    def test_delete(self):
        self.setup_vault()
        self.run_cli("delete", "example.com", hidden=[MASTER], typed=["y"])
        self.assertEqual(vault.unlock(self.path, MASTER).entries, {})

    def test_short_master_password(self):
        code, out = self.run_cli("init", hidden=["short", "short"])
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()
