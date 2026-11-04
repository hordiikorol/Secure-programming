import os
import stat
import tempfile
import unittest

from pwmanager import storage
from pwmanager.storage import VaultStorageError


def sample_vault(ciphertext="AAAA"):
    return {
        "format": storage.FORMAT_NAME,
        "version": storage.FORMAT_VERSION,
        "kdf": {},
        "cipher": {},
        "ciphertext": ciphertext,
    }


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.path = os.path.join(self.temp_dir.name, "test.vault")

    def test_create_then_load_returns_same_vault(self):
        storage.create(self.path, sample_vault())
        self.assertEqual(storage.load(self.path), sample_vault())

    def test_create_sets_owner_only_permissions(self):
        storage.create(self.path, sample_vault())
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_create_refuses_to_overwrite(self):
        storage.create(self.path, sample_vault("old"))
        with self.assertRaises(VaultStorageError):
            storage.create(self.path, sample_vault("new"))
        self.assertEqual(storage.load(self.path)["ciphertext"], "old")

    def test_create_refuses_symlink(self):
        target = os.path.join(self.temp_dir.name, "target")
        os.symlink(target, self.path)
        with self.assertRaises(VaultStorageError):
            storage.create(self.path, sample_vault())
        self.assertFalse(os.path.exists(target))

    def test_save_replaces_contents_and_keeps_permissions(self):
        storage.create(self.path, sample_vault("old"))
        storage.save(self.path, sample_vault("new"))
        self.assertEqual(storage.load(self.path)["ciphertext"], "new")
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_save_leaves_no_temp_files(self):
        storage.create(self.path, sample_vault())
        storage.save(self.path, sample_vault("new"))
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

    def test_load_refuses_invalid_json(self):
        with open(self.path, "w") as file:
            file.write("not json {")
        with self.assertRaises(VaultStorageError):
            storage.load(self.path)

    def test_load_refuses_wrong_structure(self):
        for content in ('[]', '{"format": "pwmanager-vault", "version": 99}'):
            with open(self.path, "w") as file:
                file.write(content)
            with self.assertRaises(VaultStorageError):
                storage.load(self.path)

    def test_load_refuses_oversized_file(self):
        with open(self.path, "wb") as file:
            file.truncate(storage.MAX_VAULT_BYTES + 1)
        with self.assertRaises(VaultStorageError):
            storage.load(self.path)


if __name__ == "__main__":
    unittest.main()
