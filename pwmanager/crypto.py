"""Encryption stuff. Scrypt makes the key from the master password, AES-256-GCM encrypts the entries

Every user has their own salt, key and encrypted part of the vault. The user
name is passed to GCM as associated data, so one user's encrypted part can't be
copied into another user's slot in the file
"""

import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pwmanager import secure_memory, storage

# Scrypt settings from OWASP, uses like 128MiB each time
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
KEY_BYTES = 32
AUTH_NAME = "scrypt-sha256"

# Used for logins with a user that doesn't exist, so they take as long as real ones
DUMMY_KEY_SETTINGS = {"name": "scrypt", "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                      "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}


class DecryptionError(Exception):
    pass


def to_base64(raw_bytes):
    return base64.b64encode(raw_bytes).decode("ascii")


def new_key_settings(n=SCRYPT_N):
    # random salt per user, doesnt need to be secret
    salt = to_base64(os.urandom(storage.SALT_BYTES))
    return {"name": "scrypt", "salt": salt, "n": n, "r": SCRYPT_R, "p": SCRYPT_P}


def derive_keys(password, key_settings):
    """Run scrypt once and split the 64 bytes:
    first half = encryption key (bytearray so it can be wiped),
    second half = hashed with sha256 and stored as the master password hash.
    password can be a str or a bytearray
    """
    s = Scrypt(
        salt=storage.decode_base64(key_settings["salt"], storage.SALT_BYTES),
        length=KEY_BYTES * 2,
        n=key_settings["n"],
        r=key_settings["r"],
        p=key_settings["p"],
    )
    if isinstance(password, str):
        pw = password.encode("utf-8")
        try:
            out = s.derive(pw)
        finally:
            secure_memory.wipe_bytes(pw)
    else:
        out = s.derive(password)
    key = bytearray(out[:KEY_BYTES])
    check = to_base64(hashlib.sha256(b"pwmanager-auth|" + out[KEY_BYTES:]).digest())
    secure_memory.wipe_bytes(out)
    return key, check


def same_hash(a, b):
    # constant time compare so timing doesnt leak how much of the hash matched
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))


def auth_part(check):
    return {"name": AUTH_NAME, "hash": check}


def _associated_data(account):
    return f"pwmanager-v2|{account}".encode("utf-8")


def encrypt(key, key_settings, contents, account):
    # New nonce every time, reusing one with the same key breaks GCM
    nonce = os.urandom(storage.NONCE_BYTES)
    plaintext = json.dumps(contents).encode("utf-8")
    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, _associated_data(account))
    finally:
        secure_memory.wipe_bytes(plaintext)
    return {
        "kdf": key_settings,
        "cipher": {"name": "AES-256-GCM", "nonce": to_base64(nonce)},
        "ciphertext": to_base64(ciphertext),
    }


def decrypt(key, user_part, account):
    nonce = storage.decode_base64(user_part["cipher"]["nonce"], storage.NONCE_BYTES)
    ciphertext = storage.decode_base64(user_part["ciphertext"])
    if nonce is None or ciphertext is None:
        raise DecryptionError("vault data is damaged")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _associated_data(account))
    except InvalidTag:
        # GCM checks a tag so wrong password and tampered file both end up here
        raise DecryptionError("wrong master password or the vault file was modified") from None
    try:
        return json.loads(plaintext)
    except (ValueError, RecursionError):
        raise DecryptionError("vault data is damaged") from None
    finally:
        secure_memory.wipe_bytes(plaintext)
