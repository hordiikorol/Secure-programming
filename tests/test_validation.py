import os
import tempfile
import unittest

from pwmanager import validation
from pwmanager.validation import ValidationError

# characters that could mess up a terminal or hide what a name really is
NASTY_CHARS = ["\x1b[31m", "\n", "\r", "\t", "\x00", "\x7f", "​", "‮", "\x9b"]


class AccountNameTests(unittest.TestCase):
    def test_good_names(self):
        for name in ("alice", "Bob", "a", "user_1", "first.last", "x-y", "a" * 32):
            with self.subTest(name=name):
                self.assertEqual(validation.check_account_name(name), name)

    def test_bad_names(self):
        for name in ("", " alice", "alice ", "a b", ".hidden", "-rf", "../../etc", "a/b",
                     "a" * 33, "ålice", "alice;rm", None, 5, *NASTY_CHARS):
            with self.subTest(name=name):
                with self.assertRaises(ValidationError):
                    validation.check_account_name(name)


class EntryFieldTests(unittest.TestCase):
    def test_good_entry_names(self):
        for name in ("example.com", "My Bank", "email (work)", "ü-mail", "x"):
            with self.subTest(name=name):
                self.assertEqual(validation.check_entry_name(name), name)

    def test_bad_entry_names(self):
        bad = ["", " ", " leading", "trailing ", "x" * 101, None, b"bytes",
               *[f"evil{char}name" for char in NASTY_CHARS]]
        for name in bad:
            with self.subTest(name=name):
                with self.assertRaises(ValidationError):
                    validation.check_entry_name(name)

    def test_entry_name_limit_is_inclusive(self):
        validation.check_entry_name("x" * 100)

    def test_bad_usernames(self):
        for username in ("", "x" * 201, "bob\n", "\x1b]0;title\x07"):
            with self.subTest(username=username):
                with self.assertRaises(ValidationError):
                    validation.check_entry_username(username)

    def test_password_can_have_spaces(self):
        self.assertEqual(validation.check_entry_password(" pass word "), " pass word ")

    def test_bad_passwords(self):
        for password in ("", "x" * 1025, "pass\nword", "pass\x00word"):
            with self.subTest(password=repr(password)[:20]):
                with self.assertRaises(ValidationError):
                    validation.check_entry_password(password)

    def test_error_message_doesnt_echo_the_value(self):
        with self.assertRaises(ValidationError) as caught:
            validation.check_entry_password("secret\nvalue")
        self.assertNotIn("secret", str(caught.exception))


class MasterPasswordTests(unittest.TestCase):
    def test_good(self):
        validation.check_master_password("correct horse battery", "alice")

    def test_too_short(self):
        with self.assertRaises(ValidationError):
            validation.check_master_password("short", "alice")

    def test_exactly_minimum_length(self):
        validation.check_master_password("x" * 12, "alice")
        with self.assertRaises(ValidationError):
            validation.check_master_password("x" * 11, "alice")

    def test_contains_user_name(self):
        with self.assertRaises(ValidationError):
            validation.check_master_password("ALICE-password-123", "alice")

    def test_control_chars(self):
        with self.assertRaises(ValidationError):
            validation.check_master_password("long-password\x1b123", "alice")

    def test_bytearray_master_password(self):
        # the cli passes the master password as a bytearray, same rules apply
        validation.check_master_password(bytearray(b"correct horse battery"), "alice")
        for bad in (b"short", b"x" * 1025, b"long-password\x1b123", b"long-password\n123",
                    b"my-ALICE-password"):
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(ValidationError):
                    validation.check_master_password(bytearray(bad), "alice")


class PathTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    def test_good_path_becomes_absolute(self):
        path = os.path.join(self.temp_dir.name, "x.vault")
        self.assertEqual(validation.check_file_path(path, "vault"), path)

    def test_bad_paths(self):
        bad = ["", "x" * 5000, "a\x00b", "a\nb", self.temp_dir.name,
               os.path.join(self.temp_dir.name, "missing-folder", "x.vault")]
        for path in bad:
            with self.subTest(path=path[:40]):
                with self.assertRaises(ValidationError):
                    validation.check_file_path(path, "vault")


class ConfirmTests(unittest.TestCase):
    def test_yes(self):
        for answer in ("y", "Y", "yes", " YES "):
            self.assertTrue(validation.is_yes(answer))

    def test_not_yes(self):
        for answer in ("", "n", "no", "yess", "y\x1b", None):
            self.assertFalse(validation.is_yes(answer))


class ContentsTests(unittest.TestCase):
    def good(self):
        return {"owner": "alice", "entries": {
            "site": {"owner": "alice", "username": "a", "password": "p"}}}

    def test_good(self):
        validation.check_contents(self.good(), "alice")

    def test_bad(self):
        cases = []
        wrong_owner = self.good()
        wrong_owner["owner"] = "bob"
        cases.append(wrong_owner)
        entry_wrong_owner = self.good()
        entry_wrong_owner["entries"]["site"]["owner"] = "bob"
        cases.append(entry_wrong_owner)
        extra_field = self.good()
        extra_field["entries"]["site"]["notes"] = "x"
        cases.append(extra_field)
        bad_name = self.good()
        bad_name["entries"]["bad\nname"] = bad_name["entries"].pop("site")
        cases.append(bad_name)
        cases += [[], {"owner": "alice"}, {"owner": "alice", "entries": []}]
        for contents in cases:
            with self.subTest(contents=contents):
                with self.assertRaises(ValidationError):
                    validation.check_contents(contents, "alice")


if __name__ == "__main__":
    unittest.main()
