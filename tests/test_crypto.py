import base64
import unittest

from pwmanager import crypto, storage

# fake test passwords, not real ones
PASSWORD = "test-master-password"
DATA = {"entries": {"example.com": {"username": "alice", "password": "dummy-pw-123"}}}


def fast_kdf():
    # small n so the tests don't take long
    return crypto.new_kdf_params(n=2 ** 14)


class CryptoTests(unittest.TestCase):
    def test_encrypt_then_decrypt(self):
        kdf = fast_kdf()
        key = crypto.derive_key(PASSWORD, kdf)
        vault = crypto.encrypt(key, kdf, DATA)
        storage.validate(vault)
        self.assertEqual(crypto.decrypt(key, vault), DATA)

    def test_wrong_password_fails(self):
        kdf = fast_kdf()
        vault = crypto.encrypt(crypto.derive_key(PASSWORD, kdf), kdf, DATA)
        wrong_key = crypto.derive_key("wrong-password", kdf)
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(wrong_key, vault)

    def test_modified_ciphertext_fails(self):
        kdf = fast_kdf()
        key = crypto.derive_key(PASSWORD, kdf)
        vault = crypto.encrypt(key, kdf, DATA)
        raw = bytearray(base64.b64decode(vault["ciphertext"]))
        raw[0] ^= 1
        vault["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(key, vault)

    def test_new_nonce_each_time(self):
        kdf = fast_kdf()
        key = crypto.derive_key(PASSWORD, kdf)
        a = crypto.encrypt(key, kdf, DATA)
        b = crypto.encrypt(key, kdf, DATA)
        self.assertNotEqual(a["cipher"]["nonce"], b["cipher"]["nonce"])


if __name__ == "__main__":
    unittest.main()
