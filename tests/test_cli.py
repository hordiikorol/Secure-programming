import contextlib
import io
import json
import os
from unittest import mock

from pwmanager import cli, vault
from tests.helpers import ENTRY_PASSWORD, MASTER_PASSWORD, OTHER_MASTER_PASSWORD, TempDirTestCase

SECRETS = (MASTER_PASSWORD, OTHER_MASTER_PASSWORD, ENTRY_PASSWORD, "new-dummy-pw-456")


class CliTests(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.log_path = os.path.join(self.temp_dir.name, "test.log")
        self.clipboard = []
        # fake clipboard, no 15 second wait
        for patcher in (
            mock.patch.object(cli, "copy_to_clipboard", self.clipboard.append),
            mock.patch.object(cli.time, "sleep"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, *args, user="alice", hidden=(), typed=()):
        output = io.StringIO()
        # read_secret gives bytearrays, keep them so tests can check they got wiped
        self.secrets_given = [bytearray(h.encode()) for h in hidden]
        with mock.patch.object(cli, "read_secret", side_effect=list(self.secrets_given)), \
                mock.patch("builtins.input", side_effect=list(typed)), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            exit_code = cli.main(["--vault", self.path, "--log", self.log_path, "--user", user, *args])
        # passwords must never be printed
        for secret in SECRETS:
            self.assertNotIn(secret, output.getvalue())
        return exit_code, output.getvalue()

    def read_log(self):
        with open(self.log_path) as file:
            return file.read()

    def setup_vault(self):
        self.run_cli("init", hidden=[MASTER_PASSWORD, MASTER_PASSWORD])
        self.run_cli("add", "example.com", hidden=[MASTER_PASSWORD, ENTRY_PASSWORD, ENTRY_PASSWORD],
                     typed=["alice"])

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

    def test_unknown_user_looks_like_wrong_password(self):
        self.setup_vault()
        _, unknown = self.run_cli("list", user="nobody", hidden=[MASTER_PASSWORD])
        _, wrong = self.run_cli("list", hidden=["wrong-password"])
        self.assertEqual(unknown, wrong)

    def test_get_uses_clipboard(self):
        self.setup_vault()
        exit_code, output = self.run_cli("get", "example.com", hidden=[MASTER_PASSWORD])
        self.assertEqual(exit_code, 0)
        self.assertEqual(self.clipboard, [ENTRY_PASSWORD, ""])  # copied, then cleared

    def test_edit(self):
        self.setup_vault()
        exit_code, _ = self.run_cli("edit", "example.com",
                                    hidden=[MASTER_PASSWORD, "new-dummy-pw-456", "new-dummy-pw-456"],
                                    typed=["alice2"])
        self.assertEqual(exit_code, 0)
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            self.assertEqual(session.get_entry("example.com"), ("alice2", "new-dummy-pw-456"))

    def test_delete(self):
        self.setup_vault()
        self.run_cli("delete", "example.com", hidden=[MASTER_PASSWORD], typed=["y"])
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            self.assertEqual(session.list_entries(), [])

    def test_delete_needs_yes(self):
        self.setup_vault()
        self.run_cli("delete", "example.com", hidden=[MASTER_PASSWORD], typed=["n"])
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            self.assertEqual(len(session.list_entries()), 1)

    def test_passwd(self):
        self.setup_vault()
        exit_code, _ = self.run_cli("passwd", hidden=[MASTER_PASSWORD, OTHER_MASTER_PASSWORD,
                                                      OTHER_MASTER_PASSWORD])
        self.assertEqual(exit_code, 0)
        exit_code, _ = self.run_cli("list", hidden=[OTHER_MASTER_PASSWORD])
        self.assertEqual(exit_code, 0)

    def test_second_user_cant_see_first_users_entries(self):
        self.setup_vault()
        self.run_cli("register", user="bob", hidden=[OTHER_MASTER_PASSWORD, OTHER_MASTER_PASSWORD])
        exit_code, output = self.run_cli("list", user="bob", hidden=[OTHER_MASTER_PASSWORD])
        self.assertEqual(exit_code, 0)
        self.assertNotIn("example.com", output)
        exit_code, _ = self.run_cli("get", "example.com", user="bob", hidden=[OTHER_MASTER_PASSWORD])
        self.assertEqual(exit_code, 1)
        self.assertEqual(self.clipboard, [])

    def test_short_master_password(self):
        exit_code, _ = self.run_cli("init", hidden=["short", "short"])
        self.assertEqual(exit_code, 1)
        self.assertFalse(os.path.exists(self.path))

    def test_invalid_inputs_are_rejected(self):
        self.setup_vault()
        cases = [
            (("add", "bad\x1b[2Jname"), {}),
            (("get", ""), {}),
            (("list",), {"user": "../../etc/passwd"}),
            (("list",), {"user": "alice; rm -rf ~"}),
        ]
        for args, extra in cases:
            with self.subTest(args=args, extra=extra):
                exit_code, output = self.run_cli(*args, hidden=[MASTER_PASSWORD], **extra)
                self.assertEqual(exit_code, 1)
                self.assertIn("error:", output)
                self.assertNotIn("\x1b", output)

    def test_bad_vault_path(self):
        exit_code, output = self.run_cli("--vault", "x\x00y", "list")
        self.assertEqual(exit_code, 1)

    def test_unexpected_error_is_generic(self):
        self.setup_vault()
        with mock.patch.object(vault, "login", side_effect=RuntimeError("/secret/internal/path")):
            exit_code, output = self.run_cli("list", hidden=[MASTER_PASSWORD])
        self.assertEqual(exit_code, 1)
        self.assertIn("Something went wrong", output)
        self.assertNotIn("/secret/internal/path", output)
        self.assertNotIn("Traceback", output)
        self.assertNotIn("/secret/internal/path", self.read_log())

    def test_damaged_vault_gives_clean_error(self):
        self.setup_vault()
        with open(self.path) as file:
            vault_file = json.load(file)
        del vault_file["users"]["alice"]["kdf"]["salt"]
        with open(self.path, "w") as file:
            json.dump(vault_file, file)
        exit_code, output = self.run_cli("list", hidden=[MASTER_PASSWORD])
        self.assertEqual(exit_code, 1)
        self.assertNotIn("Traceback", output)

    def test_typed_passwords_are_wiped(self):
        self.setup_vault()
        self.run_cli("list", hidden=[MASTER_PASSWORD])
        self.assertEqual(self.secrets_given[0], bytearray(len(MASTER_PASSWORD)))
        self.run_cli("add", "other.com", hidden=[MASTER_PASSWORD, ENTRY_PASSWORD, ENTRY_PASSWORD],
                     typed=["alice"])
        for buf in self.secrets_given:
            self.assertEqual(buf, bytearray(len(buf)))

    def test_master_password_wiped_on_wrong_password(self):
        self.setup_vault()
        self.run_cli("list", hidden=["wrong-password"])
        self.assertEqual(self.secrets_given[0], bytearray(len("wrong-password")))

    def test_mismatched_passwords(self):
        exit_code, output = self.run_cli("init", hidden=[MASTER_PASSWORD, OTHER_MASTER_PASSWORD])
        self.assertEqual(exit_code, 1)
        self.assertIn("did not match", output)
        self.assertFalse(os.path.exists(self.path))

    def test_log_has_events_but_no_secrets(self):
        self.setup_vault()
        self.run_cli("get", "example.com", hidden=[MASTER_PASSWORD])
        self.run_cli("list", hidden=["wrong-password"])
        self.run_cli("passwd", hidden=[MASTER_PASSWORD, OTHER_MASTER_PASSWORD, OTHER_MASTER_PASSWORD])
        log_text = self.read_log()
        events = [json.loads(line)["event"] for line in log_text.splitlines()]
        for expected in ("vault_created", "login_ok", "entry_added", "entry_viewed",
                         "login_failed", "master_password_changed"):
            self.assertIn(expected, events)
        for secret in (*SECRETS, "example.com"):
            self.assertNotIn(secret, log_text)
        lines = [json.loads(line) for line in log_text.splitlines()]
        for line in lines:
            self.assertIn(line["outcome"], ("success", "failure", "denied"))
            self.assertTrue(line["session"])
        failed = [line for line in lines if line["event"] == "login_failed"]
        self.assertEqual(failed[0]["outcome"], "failure")


if __name__ == "__main__":
    import unittest
    unittest.main()
