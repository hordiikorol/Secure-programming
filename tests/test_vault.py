import os
import tempfile
import unittest
from unittest import mock

from pwmanager import crypto, vault

PASSWORD = "test-master-password"  # fake

real_new_kdf_params = crypto.new_kdf_params


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "test.vault")
        # faster scrypt for tests
        p = mock.patch.object(crypto, "new_kdf_params", lambda: real_new_kdf_params(n=2 ** 14))
        p.start()
        self.addCleanup(p.stop)

    def test_create_and_unlock(self):
        vault.create(self.path, PASSWORD)
        self.assertEqual(vault.unlock(self.path, PASSWORD).entries, {})

    def test_wrong_password(self):
        vault.create(self.path, PASSWORD)
        with self.assertRaises(vault.WrongPasswordError):
            vault.unlock(self.path, "wrong-password")

    def test_save_and_unlock_again(self):
        v = vault.create(self.path, PASSWORD)
        v.entries["example.com"] = {"username": "alice", "password": "dummy-pw-123"}
        v.save()
        self.assertEqual(vault.unlock(self.path, PASSWORD).entries["example.com"]["username"], "alice")

    def test_nothing_in_cleartext(self):
        v = vault.create(self.path, PASSWORD)
        v.entries["example.com"] = {"username": "alice", "password": "dummy-pw-123"}
        v.save()
        with open(self.path, "rb") as f:
            content = f.read()
        # no password hash or plaintext in the file
        for text in (PASSWORD, "dummy-pw-123", "alice"):
            self.assertNotIn(text.encode(), content)


if __name__ == "__main__":
    unittest.main()
