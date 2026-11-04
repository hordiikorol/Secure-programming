import base64
import unittest

from pwmanager import crypto, storage

# fake test passwords, not real ones
PASSWORD = "test-master-password"
CONTENTS = {"entries": {"example.com": {"username": "alice", "password": "dummy-pw-123"}}}


def fast_key_settings():
    # small n so the tests don't take long
    return crypto.new_key_settings(n=2 ** 14)


class CryptoTests(unittest.TestCase):
    def test_encrypt_then_decrypt(self):
        key_settings = fast_key_settings()
        key = crypto.derive_key(PASSWORD, key_settings)
        vault_file = crypto.encrypt(key, key_settings, CONTENTS)
        storage.validate(vault_file)
        self.assertEqual(crypto.decrypt(key, vault_file), CONTENTS)

    def test_wrong_password_fails(self):
        key_settings = fast_key_settings()
        vault_file = crypto.encrypt(crypto.derive_key(PASSWORD, key_settings), key_settings, CONTENTS)
        wrong_key = crypto.derive_key("wrong-password", key_settings)
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(wrong_key, vault_file)

    def test_modified_ciphertext_fails(self):
        key_settings = fast_key_settings()
        key = crypto.derive_key(PASSWORD, key_settings)
        vault_file = crypto.encrypt(key, key_settings, CONTENTS)
        ciphertext_bytes = bytearray(base64.b64decode(vault_file["ciphertext"]))
        ciphertext_bytes[0] ^= 1
        vault_file["ciphertext"] = base64.b64encode(bytes(ciphertext_bytes)).decode()
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(key, vault_file)

    def test_new_nonce_each_time(self):
        key_settings = fast_key_settings()
        key = crypto.derive_key(PASSWORD, key_settings)
        first = crypto.encrypt(key, key_settings, CONTENTS)
        second = crypto.encrypt(key, key_settings, CONTENTS)
        self.assertNotEqual(first["cipher"]["nonce"], second["cipher"]["nonce"])


if __name__ == "__main__":
    unittest.main()
