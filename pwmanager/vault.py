"""master password stuff

no password hash in the file. to check the master password we just derive the
key and try to decrypt, wrong password = decryption fails
"""

from pwmanager import crypto, storage


class WrongPasswordError(Exception):
    pass


class Vault:
    def __init__(self, path, key, key_settings, contents):
        self.path = path
        self.key = key
        self.key_settings = key_settings
        self.entries = contents["entries"]

    def save(self):
        vault_file = crypto.encrypt(self.key, self.key_settings, {"entries": self.entries})
        storage.save(self.path, vault_file)


def create(path, master_password):
    key_settings = crypto.new_key_settings()
    key = crypto.derive_key(master_password, key_settings)
    contents = {"entries": {}}
    storage.create(path, crypto.encrypt(key, key_settings, contents))
    return Vault(path, key, key_settings, contents)


def unlock(path, master_password):
    vault_file = storage.load(path)
    key_settings = vault_file["kdf"]
    key = crypto.derive_key(master_password, key_settings)
    try:
        contents = crypto.decrypt(key, vault_file)
    except crypto.DecryptionError as error:
        raise WrongPasswordError(str(error)) from None
    return Vault(path, key, key_settings, contents)
