"""Users, logins and the entries of a logged in user

Login: scrypt runs once on the master password. Half of the output is hashed and
compared with the hash stored in the file, the other half is the key that
decrypts the user's entries.

Access control works on two levels:
- every user's entries are encrypted with their own key, so without your master
  password you can't even read another user's part of the file
- every entry has an owner, and every operation on an entry goes through
  Session._authorize() which checks the session is open and you own the entry
"""

import logging

from pwmanager import crypto, logs, secure_memory, storage, validation


class VaultError(Exception):
    """Something the user did wrong, safe to show"""


class LoginFailed(VaultError):
    def __init__(self):
        # same message for unknown user and wrong password
        super().__init__("wrong user name or master password")


class AccessDenied(VaultError):
    pass


class EntryNotFound(VaultError):
    def __init__(self):
        super().__init__("no entry with that name")


class EntryExists(VaultError):
    def __init__(self):
        super().__init__("an entry with that name already exists, edit or delete it")


def create(path):
    storage.create(path, storage.empty_vault())


def make_part(key, settings, check, account, entries):
    part = crypto.encrypt(key, settings, {"owner": account, "entries": entries}, account)
    part["auth"] = crypto.auth_part(check)
    return part


def register(path, account, master_pw):
    """Add a new user to the vault. Call this while holding storage.locked(path)"""
    validation.check_account_name(account)
    validation.check_master_password(master_pw, account)
    data = storage.load(path)
    if account in data["users"]:
        raise VaultError("that user name is taken")
    if len(data["users"]) >= storage.MAX_USERS:
        raise VaultError("this vault has too many users")
    settings = crypto.new_key_settings()
    key, check = crypto.derive_keys(master_pw, settings)
    try:
        data["users"][account] = make_part(key, settings, check, account, {})
    finally:
        secure_memory.wipe(key)
    storage.save(path, data)


def login(path, account, master_pw):
    """Returns a Session, or raises LoginFailed"""
    validation.check_account_name(account)
    data = storage.load(path)
    part = data["users"].get(account)
    if part is None:
        # still run scrypt so unknown users take as long as wrong passwords
        key, check = crypto.derive_keys(master_pw, crypto.DUMMY_KEY_SETTINGS)
        secure_memory.wipe(key)
        crypto.same_hash(check, check)
        raise LoginFailed()

    key, check = crypto.derive_keys(master_pw, part["kdf"])
    if not crypto.same_hash(check, part["auth"]["hash"]):
        secure_memory.wipe(key)
        raise LoginFailed()

    try:
        contents = crypto.decrypt(key, part, account)
        validation.check_contents(contents, account)
    except (crypto.DecryptionError, validation.ValidationError):
        # right password but the data doesnt decrypt -> file was changed
        secure_memory.wipe(key)
        raise storage.VaultStorageError("your part of the vault is damaged or was modified") from None
    return Session(path, account, key, part["kdf"], check, contents["entries"])


class Session:
    """A logged in user. Use it with `with` so the key gets wiped at the end"""

    def __init__(self, path, account, key, settings, check, entries):
        self.path = path
        self.account = account
        self.key = key
        self.settings = settings
        self.check = check
        self.entries = entries
        self.is_open = True

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def close(self):
        secure_memory.wipe(self.key)
        self.entries.clear()
        self.is_open = False

    def _authorize(self, name=None):
        """The access check, every operation goes through here first.
        Returns the entry if name is given and it exists, else None
        """
        if not self.is_open:
            logs.event("access_denied", logging.WARNING, user=self.account, reason="session_closed",
                       outcome="denied")
            raise AccessDenied("you are not logged in")
        if name is None:
            return None
        e = self.entries.get(name)
        if e is not None and e.get("owner") != self.account:
            logs.event("access_denied", logging.WARNING, user=self.account, reason="not_owner",
                       outcome="denied")
            raise AccessDenied("you dont have access to that entry")
        return e

    def list_entries(self):
        self._authorize()
        return [(name, self._authorize(name)["username"]) for name in sorted(self.entries)]

    def has_entry(self, name):
        validation.check_entry_name(name)
        return self._authorize(name) is not None

    def get_entry(self, name):
        validation.check_entry_name(name)
        e = self._authorize(name)
        if e is None:
            raise EntryNotFound()
        return e["username"], e["password"]

    def add_entry(self, name, username, password):
        validation.check_entry_name(name)
        validation.check_entry_username(username)
        validation.check_entry_password(password)
        if self._authorize(name) is not None:
            raise EntryExists()
        if len(self.entries) >= validation.MAX_ENTRIES_PER_USER:
            raise VaultError("you have too many entries")
        self.entries[name] = {"owner": self.account, "username": username, "password": password}

    def edit_entry(self, name, username=None, password=None):
        validation.check_entry_name(name)
        if username is not None:
            validation.check_entry_username(username)
        if password is not None:
            validation.check_entry_password(password)
        e = self._authorize(name)
        if e is None:
            raise EntryNotFound()
        if username is not None:
            e["username"] = username
        if password is not None:
            e["password"] = password

    def delete_entry(self, name):
        validation.check_entry_name(name)
        if self._authorize(name) is None:
            raise EntryNotFound()
        del self.entries[name]

    def change_master_password(self, new_pw):
        self._authorize()
        validation.check_master_password(new_pw, self.account)
        settings = crypto.new_key_settings()  # new salt too
        key, check = crypto.derive_keys(new_pw, settings)
        secure_memory.wipe(self.key)
        self.key = key
        self.settings = settings
        self.check = check

    def save(self):
        """Write this user's part back. Call this while holding storage.locked(path).
        Reloads the file first and only replaces this user's part, so other
        users' changes aren't lost
        """
        self._authorize()
        data = storage.load(self.path)
        if self.account not in data["users"]:
            raise AccessDenied("your user doesnt exist in this vault anymore")
        data["users"][self.account] = make_part(self.key, self.settings, self.check,
                                                self.account, self.entries)
        storage.save(self.path, data)
