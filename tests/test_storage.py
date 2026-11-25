import copy
import json
import os
import stat
import tempfile
import unittest

from pwmanager import storage
from pwmanager.storage import VaultStorageError

GOOD_PART = {
    "kdf": {"name": "scrypt", "salt": "AAAAAAAAAAAAAAAAAAAAAA==", "n": 2 ** 14, "r": 8, "p": 1},
    "auth": {"name": "scrypt-sha256", "hash": "A" * 43 + "="},
    "cipher": {"name": "AES-256-GCM", "nonce": "AAAAAAAAAAAAAAAA"},
    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA==",
}


def sample_vault(marker="AAAAAAAAAAAAAAAAAAAAAA=="):
    part = copy.deepcopy(GOOD_PART)
    part["ciphertext"] = marker
    return {"format": storage.FORMAT_NAME, "version": storage.FORMAT_VERSION, "users": {"alice": part}}


OLD = "b2xkb2xkb2xkb2xkb2xkb2xk"  # base64 of "oldoldoldoldoldold"
NEW = "bmV3bmV3bmV3bmV3bmV3bmV3"


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.path = os.path.join(self.temp_dir.name, "test.vault")

    def write_raw(self, content):
        with open(self.path, "w") as file:
            file.write(content if isinstance(content, str) else json.dumps(content))
        os.chmod(self.path, 0o600)

    def assert_load_refused(self, content):
        self.write_raw(content)
        with self.assertRaises(VaultStorageError):
            storage.load(self.path)

    def test_create_then_load_returns_same_vault(self):
        storage.create(self.path, sample_vault())
        self.assertEqual(storage.load(self.path), sample_vault())

    def test_empty_vault_is_valid(self):
        storage.create(self.path, storage.empty_vault())
        self.assertEqual(storage.load(self.path)["users"], {})

    def test_create_sets_owner_only_permissions(self):
        storage.create(self.path, sample_vault())
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_create_refuses_to_overwrite(self):
        storage.create(self.path, sample_vault(OLD))
        with self.assertRaises(VaultStorageError):
            storage.create(self.path, sample_vault(NEW))
        self.assertEqual(storage.load(self.path)["users"]["alice"]["ciphertext"], OLD)

    def test_create_refuses_symlink(self):
        target = os.path.join(self.temp_dir.name, "target")
        os.symlink(target, self.path)
        with self.assertRaises(VaultStorageError):
            storage.create(self.path, sample_vault())
        self.assertFalse(os.path.exists(target))

    def test_save_replaces_contents_and_keeps_permissions(self):
        storage.create(self.path, sample_vault(OLD))
        storage.save(self.path, sample_vault(NEW))
        self.assertEqual(storage.load(self.path)["users"]["alice"]["ciphertext"], NEW)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_save_leaves_no_temp_files(self):
        storage.create(self.path, sample_vault())
        storage.save(self.path, sample_vault(NEW))
        self.assertEqual(os.listdir(self.temp_dir.name), ["test.vault"])

    def test_save_replaces_symlink_without_writing_through_it(self):
        target = os.path.join(self.temp_dir.name, "target")
        with open(target, "w") as file:
            file.write("do not touch")
        os.symlink(target, self.path)
        storage.save(self.path, sample_vault())
        with open(target) as file:
            self.assertEqual(file.read(), "do not touch")
        self.assertFalse(os.path.islink(self.path))

    def test_invalid_vault_is_not_written(self):
        with self.assertRaises(VaultStorageError):
            storage.create(self.path, {"format": "something else"})
        self.assertFalse(os.path.exists(self.path))

    def test_load_missing_file(self):
        with self.assertRaises(VaultStorageError):
            storage.load(self.path)

    def test_load_refuses_symlink(self):
        real = os.path.join(self.temp_dir.name, "real.vault")
        storage.create(real, sample_vault())
        os.symlink(real, self.path)
        with self.assertRaises(VaultStorageError):
            storage.load(self.path)

    def test_load_refuses_directory(self):
        with self.assertRaises(VaultStorageError):
            storage.load(self.temp_dir.name)

    def test_load_refuses_file_readable_by_others(self):
        storage.create(self.path, sample_vault())
        os.chmod(self.path, 0o644)
        with self.assertRaises(VaultStorageError):
            storage.load(self.path)

    def test_load_refuses_invalid_json(self):
        self.assert_load_refused("not json {")

    def test_load_refuses_deeply_nested_json(self):
        self.assert_load_refused("[" * 100000 + "]" * 100000)

    def test_load_refuses_wrong_structure(self):
        for content in ([], {"format": "pwmanager-vault", "version": 99}, "null",
                        {"format": "pwmanager-vault", "version": 2, "users": []},
                        {**sample_vault(), "extra": 1}):
            with self.subTest(content=content):
                self.assert_load_refused(content)

    def test_load_refuses_old_single_user_vault(self):
        self.assert_load_refused({"format": "pwmanager-vault", "version": 1, "kdf": {},
                                  "cipher": {}, "ciphertext": ""})

    def test_load_refuses_bad_user_names(self):
        for name in ("", "../etc", "a b", "x" * 33, "\x1b[31m"):
            with self.subTest(name=name):
                vault_file = sample_vault()
                vault_file["users"] = {name: copy.deepcopy(GOOD_PART)}
                self.assert_load_refused(vault_file)

    def test_load_refuses_bad_key_settings(self):
        # huge n would eat all the memory when unlocking, so its refused
        bad_values = [("n", 2 ** 30), ("n", 1000), ("n", True), ("n", "16384"),
                      ("r", 0), ("p", 100), ("name", "md5"), ("salt", "short"), ("salt", "!!!notbase64!!!")]
        for key, value in bad_values:
            with self.subTest(key=key, value=value):
                vault_file = sample_vault()
                vault_file["users"]["alice"]["kdf"][key] = value
                self.assert_load_refused(vault_file)

    def test_load_refuses_bad_cipher_settings(self):
        for key, value in [("name", "DES"), ("nonce", "AAAA"), ("nonce", 12)]:
            with self.subTest(key=key, value=value):
                vault_file = sample_vault()
                vault_file["users"]["alice"]["cipher"][key] = value
                self.assert_load_refused(vault_file)

    def test_load_refuses_bad_password_hash(self):
        for key, value in [("name", "md5"), ("hash", "AAAA"), ("hash", None)]:
            with self.subTest(key=key, value=value):
                vault_file = sample_vault()
                vault_file["users"]["alice"]["auth"][key] = value
                self.assert_load_refused(vault_file)
        vault_file = sample_vault()
        del vault_file["users"]["alice"]["auth"]
        self.assert_load_refused(vault_file)

    def test_load_refuses_bad_ciphertext(self):
        for value in ("", "AAAA", "not base64!", None):
            with self.subTest(value=value):
                vault_file = sample_vault()
                vault_file["users"]["alice"]["ciphertext"] = value
                self.assert_load_refused(vault_file)

    def test_load_refuses_oversized_file(self):
        with open(self.path, "wb") as file:
            file.truncate(storage.MAX_VAULT_BYTES + 1)
        os.chmod(self.path, 0o600)
        with self.assertRaises(VaultStorageError):
            storage.load(self.path)

    def test_lock_file_is_owner_only(self):
        storage.create(self.path, sample_vault())
        with storage.locked(self.path):
            pass
        lock_path = self.path + ".lock"
        self.assertEqual(stat.S_IMODE(os.stat(lock_path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
