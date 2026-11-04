"""Master password handling.

No password hash is stored. To check the master password we derive the key
and try to decrypt; if the password is wrong, GCM decryption fails.
"""

from pwmanager import crypto, storage


class WrongPasswordError(Exception):
    pass


class Vault:
    def __init__(self, path, key, kdf, data):
        self.path = path
        self.key = key
        self.kdf = kdf
        self.entries = data["entries"]

    def save(self):
        storage.save(self.path, crypto.encrypt(self.key, self.kdf, {"entries": self.entries}))


def create(path, master_password):
    kdf = crypto.new_kdf_params()
    key = crypto.derive_key(master_password, kdf)
    data = {"entries": {}}
    storage.create(path, crypto.encrypt(key, kdf, data))
    return Vault(path, key, kdf, data)


def unlock(path, master_password):
    vault_file = storage.load(path)
    key = crypto.derive_key(master_password, vault_file["kdf"])
    try:
        data = crypto.decrypt(key, vault_file)
    except crypto.DecryptionError as e:
        raise WrongPasswordError(str(e)) from None
    return Vault(path, key, vault_file["kdf"], data)
