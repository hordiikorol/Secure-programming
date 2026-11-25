import base64
import json
import unittest
from unittest import mock

from pwmanager import crypto, storage, validation, vault
from tests.helpers import ENTRY_PASSWORD, MASTER_PASSWORD, OTHER_MASTER_PASSWORD, TempDirTestCase


class VaultTestCase(TempDirTestCase):
    def setUp(self):
        super().setUp()
        vault.create(self.path)
        vault.register(self.path, "alice", MASTER_PASSWORD)

    def add_alice_entry(self):
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            session.add_entry("example.com", "alice@example.com", ENTRY_PASSWORD)
            session.save()


class LoginTests(VaultTestCase):
    def test_register_and_login(self):
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            self.assertEqual(session.list_entries(), [])

    def test_wrong_password(self):
        with self.assertRaises(vault.LoginFailed):
            vault.login(self.path, "alice", "wrong-password")

    def test_unknown_user_gets_same_error(self):
        with self.assertRaises(vault.LoginFailed) as unknown:
            vault.login(self.path, "nobody", MASTER_PASSWORD)
        with self.assertRaises(vault.LoginFailed) as wrong:
            vault.login(self.path, "alice", "wrong-password")
        self.assertEqual(str(unknown.exception), str(wrong.exception))

    def test_user_name_is_case_sensitive(self):
        with self.assertRaises(vault.LoginFailed):
            vault.login(self.path, "Alice", MASTER_PASSWORD)

    def test_duplicate_user_refused(self):
        with self.assertRaises(vault.VaultError):
            vault.register(self.path, "alice", OTHER_MASTER_PASSWORD)

    def test_register_validates_input(self):
        with self.assertRaises(validation.ValidationError):
            vault.register(self.path, "bad name", OTHER_MASTER_PASSWORD)
        with self.assertRaises(validation.ValidationError):
            vault.register(self.path, "bob", "short")

    def test_change_master_password(self):
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            session.change_master_password(OTHER_MASTER_PASSWORD)
            session.save()
        with self.assertRaises(vault.LoginFailed):
            vault.login(self.path, "alice", MASTER_PASSWORD)
        vault.login(self.path, "alice", OTHER_MASTER_PASSWORD).close()

    def test_master_password_hash_is_stored(self):
        with open(self.path) as file:
            part = json.load(file)["users"]["alice"]
        self.assertEqual(part["auth"]["name"], "scrypt-sha256")
        self.assertNotIn(MASTER_PASSWORD, json.dumps(part))

    def test_wrong_password_never_tries_to_decrypt(self):
        with mock.patch.object(crypto, "decrypt") as decrypt:
            with self.assertRaises(vault.LoginFailed):
                vault.login(self.path, "alice", "wrong-password")
        decrypt.assert_not_called()

    def test_tampered_data_with_right_password_is_detected(self):
        self.add_alice_entry()
        with open(self.path) as file:
            vault_file = json.load(file)
        raw = bytearray(base64.b64decode(vault_file["users"]["alice"]["ciphertext"]))
        raw[5] ^= 1
        vault_file["users"]["alice"]["ciphertext"] = base64.b64encode(bytes(raw)).decode()
        storage.save(self.path, vault_file)
        with self.assertRaises(storage.VaultStorageError):
            vault.login(self.path, "alice", MASTER_PASSWORD)

    def test_nothing_in_cleartext(self):
        self.add_alice_entry()
        with open(self.path, "rb") as file:
            content = file.read()
        for text in (MASTER_PASSWORD, ENTRY_PASSWORD, "alice@example.com", "example.com"):
            self.assertNotIn(text.encode(), content)


class EntryTests(VaultTestCase):
    def test_add_get_edit_delete(self):
        self.add_alice_entry()
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            self.assertEqual(session.get_entry("example.com"), ("alice@example.com", ENTRY_PASSWORD))
            session.edit_entry("example.com", password="new-dummy-pw")
            self.assertEqual(session.get_entry("example.com")[1], "new-dummy-pw")
            session.delete_entry("example.com")
            self.assertEqual(session.list_entries(), [])

    def test_add_existing_refused(self):
        self.add_alice_entry()
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            with self.assertRaises(vault.EntryExists):
                session.add_entry("example.com", "x", "y")

    def test_missing_entry(self):
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            for operation in (session.get_entry, session.delete_entry, session.edit_entry):
                with self.assertRaises(vault.EntryNotFound):
                    operation("missing")

    def test_every_operation_validates_input(self):
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            with self.assertRaises(validation.ValidationError):
                session.add_entry("bad\nname", "u", "p")
            with self.assertRaises(validation.ValidationError):
                session.add_entry("ok", "u\x1b", "p")
            with self.assertRaises(validation.ValidationError):
                session.add_entry("ok", "u", "")
            with self.assertRaises(validation.ValidationError):
                session.get_entry("")
            self.assertEqual(session.list_entries(), [])


class AccessControlTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        vault.register(self.path, "bob", OTHER_MASTER_PASSWORD)
        self.add_alice_entry()

    def test_users_only_see_their_own_entries(self):
        with vault.login(self.path, "bob", OTHER_MASTER_PASSWORD) as session:
            self.assertEqual(session.list_entries(), [])
            with self.assertRaises(vault.EntryNotFound):
                session.get_entry("example.com")
            # bob can have his own entry with the same name, its a separate record
            session.add_entry("example.com", "bob", "bobs-dummy-pw")
            session.save()
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            self.assertEqual(session.get_entry("example.com")[1], ENTRY_PASSWORD)

    def test_cant_log_in_as_another_user_with_own_password(self):
        with self.assertRaises(vault.LoginFailed):
            vault.login(self.path, "alice", OTHER_MASTER_PASSWORD)

    def test_entry_owned_by_someone_else_is_refused(self):
        # even if a foreign entry somehow got into the session, every operation refuses it
        session = vault.login(self.path, "bob", OTHER_MASTER_PASSWORD)
        session.entries["stolen"] = {"owner": "alice", "username": "a", "password": "p"}
        for operation in (lambda: session.get_entry("stolen"),
                          lambda: session.edit_entry("stolen", password="x"),
                          lambda: session.delete_entry("stolen"),
                          lambda: session.add_entry("stolen", "u", "p"),
                          session.list_entries):
            with self.assertRaises(vault.AccessDenied):
                operation()
        session.close()

    def test_closed_session_refuses_everything(self):
        session = vault.login(self.path, "alice", MASTER_PASSWORD)
        session.close()
        for operation in (lambda: session.get_entry("example.com"),
                          lambda: session.add_entry("new", "u", "p"),
                          lambda: session.edit_entry("example.com", password="x"),
                          lambda: session.delete_entry("example.com"),
                          lambda: session.change_master_password(OTHER_MASTER_PASSWORD),
                          session.list_entries, session.save):
            with self.assertRaises(vault.AccessDenied):
                operation()

    def test_swapping_encrypted_parts_doesnt_work(self):
        # someone with write access swaps alice's and bob's parts in the file
        with open(self.path) as file:
            vault_file = json.load(file)
        users = vault_file["users"]
        users["alice"], users["bob"] = users["bob"], users["alice"]
        storage.save(self.path, vault_file)
        # the password hash moved with the part so the password is "right",
        # but the data is bound to the other user name and doesnt decrypt
        with self.assertRaises(storage.VaultStorageError):
            vault.login(self.path, "bob", MASTER_PASSWORD)
        with self.assertRaises(storage.VaultStorageError):
            vault.login(self.path, "alice", OTHER_MASTER_PASSWORD)

    def test_saving_keeps_other_users(self):
        with vault.login(self.path, "bob", OTHER_MASTER_PASSWORD) as session:
            session.add_entry("bob-site", "bob", "bobs-dummy-pw")
            session.save()
        with vault.login(self.path, "alice", MASTER_PASSWORD) as session:
            self.assertEqual([name for name, _ in session.list_entries()], ["example.com"])


if __name__ == "__main__":
    unittest.main()
