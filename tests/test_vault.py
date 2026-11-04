import os
import tempfile
import unittest
from unittest import mock

from pwmanager import crypto, vault

PASSWORD = "test-master-password"  # fake

real_new_key_settings = crypto.new_key_settings


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.path = os.path.join(self.temp_dir.name, "test.vault")
        # faster scrypt for tests
        patcher = mock.patch.object(crypto, "new_key_settings", lambda: real_new_key_settings(n=2 ** 14))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_create_and_unlock(self):
        vault.create(self.path, PASSWORD)
        self.assertEqual(vault.unlock(self.path, PASSWORD).entries, {})

    def test_wrong_password(self):
        vault.create(self.path, PASSWORD)
        with self.assertRaises(vault.WrongPasswordError):
            vault.unlock(self.path, "wrong-password")

    def test_save_and_unlock_again(self):
        my_vault = vault.create(self.path, PASSWORD)
        my_vault.entries["example.com"] = {"username": "alice", "password": "dummy-pw-123"}
        my_vault.save()
        self.assertEqual(vault.unlock(self.path, PASSWORD).entries["example.com"]["username"], "alice")

    def test_nothing_in_cleartext(self):
        my_vault = vault.create(self.path, PASSWORD)
        my_vault.entries["example.com"] = {"username": "alice", "password": "dummy-pw-123"}
        my_vault.save()
        with open(self.path, "rb") as file:
            content = file.read()
        # no password hash or plaintext in the file
        for text in (PASSWORD, "dummy-pw-123", "alice"):
            self.assertNotIn(text.encode(), content)


if __name__ == "__main__":
    unittest.main()
