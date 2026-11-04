"""Encryption: scrypt for the key, AES-256-GCM for the vault contents."""

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pwmanager import storage

# scrypt settings recommended by OWASP (uses about 128 MiB per derivation)
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1


class DecryptionError(Exception):
    pass


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(text)


def new_kdf_params(n=SCRYPT_N):
    # the salt is random for every new vault, it is not secret
    return {"name": "scrypt", "salt": b64(os.urandom(16)), "n": n, "r": SCRYPT_R, "p": SCRYPT_P}


def derive_key(password, kdf):
    scrypt = Scrypt(salt=unb64(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"])
    return scrypt.derive(password.encode("utf-8"))


def encrypt(key, kdf, data):
    # new random nonce every time, GCM breaks if a nonce is reused with the same key
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(data).encode("utf-8"), None)
    return {
        "format": storage.FORMAT_NAME,
        "version": storage.FORMAT_VERSION,
        "kdf": kdf,
        "cipher": {"name": "AES-256-GCM", "nonce": b64(nonce)},
        "ciphertext": b64(ciphertext),
    }


def decrypt(key, vault):
    nonce = unb64(vault["cipher"]["nonce"])
    try:
        plaintext = AESGCM(key).decrypt(nonce, unb64(vault["ciphertext"]), None)
    except InvalidTag:
        # GCM checks a tag, so a wrong key (wrong password) or an edited file both end up here
        raise DecryptionError("wrong master password or the vault file was modified") from None
    return json.loads(plaintext)
