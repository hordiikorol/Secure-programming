"""encryption stuff. scrypt makes the key from the master password, aes-256-gcm encrypts the entries"""

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pwmanager import storage

# scrypt settings from owasp, uses like 128MiB each time
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1


class DecryptionError(Exception):
    pass


def to_base64(raw_bytes):
    return base64.b64encode(raw_bytes).decode("ascii")


def from_base64(text):
    return base64.b64decode(text)


def new_key_settings(n=SCRYPT_N):
    # random salt per vault, doesnt need to be secret
    salt = to_base64(os.urandom(16))
    return {"name": "scrypt", "salt": salt, "n": n, "r": SCRYPT_R, "p": SCRYPT_P}


def derive_key(password, key_settings):
    scrypt = Scrypt(
        salt=from_base64(key_settings["salt"]),
        length=32,
        n=key_settings["n"],
        r=key_settings["r"],
        p=key_settings["p"],
    )
    return scrypt.derive(password.encode("utf-8"))


def encrypt(key, key_settings, contents):
    # new nonce every time, reusing one with the same key breaks gcm
    nonce = os.urandom(12)
    plaintext = json.dumps(contents).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "format": storage.FORMAT_NAME,
        "version": storage.FORMAT_VERSION,
        "kdf": key_settings,
        "cipher": {"name": "AES-256-GCM", "nonce": to_base64(nonce)},
        "ciphertext": to_base64(ciphertext),
    }


def decrypt(key, vault_file):
    nonce = from_base64(vault_file["cipher"]["nonce"])
    ciphertext = from_base64(vault_file["ciphertext"])
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        # gcm checks a tag so wrong password and tampered file both end up here
        raise DecryptionError("wrong master password or the vault file was modified") from None
    return json.loads(plaintext)
