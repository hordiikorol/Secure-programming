import base64
import unittest

from pwmanager import crypto, storage
from tests.helpers import MASTER_PASSWORD, fast_key_settings

CONTENTS = {"owner": "alice", "entries": {
    "example.com": {"owner": "alice", "username": "alice", "password": "dummy-pw-123"}}}


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.key_settings = fast_key_settings()
        self.key, self.check = crypto.derive_keys(MASTER_PASSWORD, self.key_settings)

    def test_encrypt_then_decrypt(self):
        user_part = crypto.encrypt(self.key, self.key_settings, CONTENTS, "alice")
        user_part["auth"] = crypto.auth_part(self.check)
        storage.validate_user_part(user_part)
        self.assertEqual(crypto.decrypt(self.key, user_part, "alice"), CONTENTS)

    def test_key_is_a_wipeable_bytearray(self):
        self.assertIsInstance(self.key, bytearray)
        self.assertEqual(len(self.key), 32)

    def test_same_password_same_salt_same_result(self):
        self.assertEqual(crypto.derive_keys(MASTER_PASSWORD, self.key_settings), (self.key, self.check))

    def test_bytearray_password_gives_same_result(self):
        pw = bytearray(MASTER_PASSWORD.encode())
        self.assertEqual(crypto.derive_keys(pw, self.key_settings), (self.key, self.check))

    def test_different_salt_different_key_and_hash(self):
        key, check = crypto.derive_keys(MASTER_PASSWORD, fast_key_settings())
        self.assertNotEqual(key, self.key)
        self.assertNotEqual(check, self.check)

    def test_wrong_password_gives_different_hash(self):
        _, check = crypto.derive_keys("wrong-password", self.key_settings)
        self.assertFalse(crypto.same_hash(check, self.check))
        self.assertTrue(crypto.same_hash(self.check, self.check))

    def test_hash_is_not_the_key(self):
        # the stored hash must not give away the encryption key
        self.assertNotIn(bytes(self.key), base64.b64decode(self.check))
        self.assertNotEqual(base64.b64encode(bytes(self.key)).decode(), self.check)

    def test_wrong_password_fails(self):
        user_part = crypto.encrypt(self.key, self.key_settings, CONTENTS, "alice")
        wrong_key, _ = crypto.derive_keys("wrong-password", self.key_settings)
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(wrong_key, user_part, "alice")

    def test_modified_ciphertext_fails(self):
        user_part = crypto.encrypt(self.key, self.key_settings, CONTENTS, "alice")
        ciphertext_bytes = bytearray(base64.b64decode(user_part["ciphertext"]))
        ciphertext_bytes[0] ^= 1
        user_part["ciphertext"] = base64.b64encode(bytes(ciphertext_bytes)).decode()
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(self.key, user_part, "alice")

    def test_part_is_bound_to_its_user(self):
        # copying alice's part into bob's slot must not decrypt
        user_part = crypto.encrypt(self.key, self.key_settings, CONTENTS, "alice")
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(self.key, user_part, "bob")

    def test_new_nonce_each_time(self):
        first = crypto.encrypt(self.key, self.key_settings, CONTENTS, "alice")
        second = crypto.encrypt(self.key, self.key_settings, CONTENTS, "alice")
        self.assertNotEqual(first["cipher"]["nonce"], second["cipher"]["nonce"])

    def test_plaintext_not_in_output(self):
        user_part = crypto.encrypt(self.key, self.key_settings, CONTENTS, "alice")
        self.assertNotIn("dummy-pw-123", str(user_part))
        self.assertNotIn(b"dummy-pw-123", base64.b64decode(user_part["ciphertext"]))


if __name__ == "__main__":
    unittest.main()
