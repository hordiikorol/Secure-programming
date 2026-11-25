import json
import logging
import os
import stat
import tempfile
import unittest

from pwmanager import logs


class LogTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.addCleanup(logs.shutdown)
        self.path = os.path.join(self.temp_dir.name, "test.log")
        logs.setup(self.path)

    def read_lines(self):
        logs.shutdown()
        with open(self.path) as file:
            return [json.loads(line) for line in file]

    def test_events_are_json_lines(self):
        logs.event("login_ok", user="alice", command="list")
        logs.event("login_failed", user="bob")
        lines = self.read_lines()
        self.assertEqual([line["event"] for line in lines], ["login_ok", "login_failed"])
        self.assertEqual(lines[0]["user"], "alice")
        self.assertIn("time", lines[0])
        self.assertEqual(lines[0]["level"], "info")

    def test_session_and_outcome(self):
        logs.event("login_ok", user="alice")
        logs.event("login_failed", logging.WARNING, user="alice")
        logs.event("access_denied", logging.WARNING, outcome="denied")
        lines = self.read_lines()
        self.assertEqual([line["outcome"] for line in lines], ["success", "failure", "denied"])
        self.assertEqual(len({line["session"] for line in lines}), 1)
        self.assertEqual(len(lines[0]["session"]), 8)

    def test_bad_outcome_refused(self):
        with self.assertRaises(ValueError):
            logs.event("x", outcome="whatever")

    def test_log_file_is_owner_only(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_secret_fields_are_refused(self):
        for field in ("password", "master_password", "key", "entry", "username"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    logs.event("oops", **{field: "dummy-secret"})
        self.assertEqual(self.read_lines(), [])

    def test_only_text_and_numbers(self):
        with self.assertRaises(ValueError):
            logs.event("oops", reason=b"bytes")

    def test_newlines_cant_fake_log_lines(self):
        logs.event("login_failed", reason='x"}\n{"event": "login_ok"')
        lines = self.read_lines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["event"], "login_failed")

    def test_long_values_are_cut(self):
        logs.event("x", reason="a" * 1000)
        self.assertEqual(len(self.read_lines()[0]["reason"]), logs.MAX_FIELD_LENGTH)

    def test_refuses_symlink(self):
        logs.shutdown()
        link = os.path.join(self.temp_dir.name, "link.log")
        os.symlink(self.path, link)
        with self.assertRaises(logs.LogSetupError):
            logs.setup(link)


if __name__ == "__main__":
    unittest.main()
