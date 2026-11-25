"""Reading/writing the vault file

Never sees a password or key, the secret parts are already encrypted by the
time they get here so this just deals with the file

The file looks like this, one encrypted part per user:
{"format": "pwmanager-vault", "version": 2,
 "users": {"alice": {"kdf": {...}, "auth": {...}, "cipher": {...}, "ciphertext": "..."}}}
"""

import base64
import binascii
import contextlib
import json
import os
import stat
import tempfile

from pwmanager import validation

try:
    import fcntl
except ImportError:  # Windows, no locking there (not supported anyway)
    fcntl = None

FORMAT_NAME = "pwmanager-vault"
FORMAT_VERSION = 2
MAX_VAULT_BYTES = 10 * 1024 * 1024  # Refuse anything over 10MiB
MAX_USERS = 100

# Scrypt limits we accept from the file. A huge n would make unlocking eat all
# the memory, so a tampered file could be used to crash the program
MIN_SCRYPT_N = 2 ** 14
MAX_SCRYPT_N = 2 ** 18
SALT_BYTES = 16
NONCE_BYTES = 12
GCM_TAG_BYTES = 16


class VaultStorageError(Exception):
    """Vault file can't be read/written or isn't a proper vault"""


def empty_vault():
    return {"format": FORMAT_NAME, "version": FORMAT_VERSION, "users": {}}


def decode_base64(text, expected_length=None):
    """Strict base64, returns None if its not valid"""
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if expected_length is not None and len(raw) != expected_length:
        return None
    return raw


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def validate_user_part(part):
    """Check one user's encrypted part, raise VaultStorageError if its wrong"""
    if not isinstance(part, dict) or set(part) != {"kdf", "auth", "cipher", "ciphertext"}:
        raise VaultStorageError("vault has a damaged user section")
    auth = part["auth"]
    if (not isinstance(auth, dict) or set(auth) != {"name", "hash"} or auth["name"] != "scrypt-sha256"
            or decode_base64(auth["hash"], 32) is None):
        raise VaultStorageError("vault has a damaged password hash")
    kdf = part["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != {"name", "salt", "n", "r", "p"}:
        raise VaultStorageError("vault has damaged key settings")
    n_ok = _is_int(kdf["n"]) and MIN_SCRYPT_N <= kdf["n"] <= MAX_SCRYPT_N and kdf["n"] & (kdf["n"] - 1) == 0
    if (kdf["name"] != "scrypt" or not n_ok
            or not (_is_int(kdf["r"]) and 1 <= kdf["r"] <= 16)
            or not (_is_int(kdf["p"]) and 1 <= kdf["p"] <= 4)
            or decode_base64(kdf["salt"], SALT_BYTES) is None):
        raise VaultStorageError("vault has damaged key settings")
    cipher = part["cipher"]
    if (not isinstance(cipher, dict) or set(cipher) != {"name", "nonce"}
            or cipher["name"] != "AES-256-GCM"
            or decode_base64(cipher["nonce"], NONCE_BYTES) is None):
        raise VaultStorageError("vault has damaged cipher settings")
    ciphertext = decode_base64(part["ciphertext"])
    if ciphertext is None or len(ciphertext) < GCM_TAG_BYTES:
        raise VaultStorageError("vault has damaged encrypted data")


def validate(vault_file):
    """Check the whole vault looks right, raise VaultStorageError if not"""
    if not isinstance(vault_file, dict):
        raise VaultStorageError("not a vault file")
    if vault_file.get("format") != FORMAT_NAME:
        raise VaultStorageError("not a vault file")
    if vault_file.get("version") == 1:
        raise VaultStorageError("this vault is the old single user format, make a new one with init")
    if vault_file.get("version") != FORMAT_VERSION or set(vault_file) != {"format", "version", "users"}:
        raise VaultStorageError("unsupported vault version")
    users = vault_file["users"]
    if not isinstance(users, dict) or len(users) > MAX_USERS:
        raise VaultStorageError("vault has a damaged user list")
    for account, part in users.items():
        try:
            validation.check_account_name(account)
        except validation.ValidationError:
            raise VaultStorageError("vault has a damaged user list") from None
        validate_user_part(part)


def to_bytes(vault_file):
    validate(vault_file)
    return json.dumps(vault_file, indent=2).encode("utf-8")


def _check_file_is_safe(file_info, path):
    if not stat.S_ISREG(file_info.st_mode):
        raise VaultStorageError(f"{path} is not a regular file")
    # Like SSH does with keys: only the owner, and only owner permissions
    if hasattr(os, "geteuid") and file_info.st_uid != os.geteuid():
        raise VaultStorageError(f"{path} belongs to another user")
    if file_info.st_mode & 0o077:
        raise VaultStorageError(f"{path} can be read by other users, run chmod 600 on it")


def create(path, vault_file):
    """Write a new vault file, fails if something is already at path

    O_EXCL does the check and the create in one step so nothing can sneak in
    between and an old vault can't get overwritten by accident. Also won't follow
    a symlink. 0600 = only the owner can read/write
    """
    file_bytes = to_bytes(vault_file)
    try:
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise VaultStorageError(f"{path} already exists") from None
    except OSError:
        raise VaultStorageError(f"cant create {path}") from None

    try:
        with os.fdopen(handle, "wb") as file:
            file.write(file_bytes)
            file.flush()
            os.fsync(file.fileno())
    except OSError:
        os.unlink(path)  # dont leave half a vault lying around
        raise VaultStorageError(f"cant write {path}") from None


def load(path):
    """Read the vault file, returns a dict

    Open first then check through the handle so the checks are on the file we
    actually read (no TOCTOU race). O_NOFOLLOW refuses a symlink where the vault
    should be
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        handle = os.open(path, flags)
    except FileNotFoundError:
        raise VaultStorageError(f"{path} does not exist") from None
    except OSError:
        raise VaultStorageError(f"cant open {path}") from None

    try:
        file_info = os.fstat(handle)
        _check_file_is_safe(file_info, path)
        if file_info.st_size > MAX_VAULT_BYTES:
            raise VaultStorageError(f"{path} is too large to be a vault")
    except VaultStorageError:
        os.close(handle)
        raise

    with os.fdopen(handle, "rb") as file:
        file_bytes = file.read(MAX_VAULT_BYTES + 1)

    if len(file_bytes) > MAX_VAULT_BYTES:  # Could have grown after fstat
        raise VaultStorageError(f"{path} is too large to be a vault")

    try:
        vault_file = json.loads(file_bytes)
    except (ValueError, RecursionError):
        raise VaultStorageError(f"{path} is not a valid vault file") from None

    validate(vault_file)
    return vault_file


def save(path, vault_file):
    """Replace the vault in one go

    Writes to a temp file in the same folder then renames it over the vault, so
    if it dies halfway the old vault is still fine. mkstemp already uses 0600
    """
    file_bytes = to_bytes(vault_file)
    folder = os.path.dirname(os.path.abspath(path))
    temp_path = None
    try:
        handle, temp_path = tempfile.mkstemp(dir=folder, prefix=".vault-", suffix=".tmp")
        with os.fdopen(handle, "wb") as file:
            file.write(file_bytes)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, path)
    except OSError:
        if temp_path is not None and os.path.exists(temp_path):
            os.unlink(temp_path)
        raise VaultStorageError(f"cant save {path}") from None


@contextlib.contextmanager
def locked(path):
    """Hold an exclusive lock on the vault while reading and saving it

    The lock is on a separate .lock file because save() renames a new file over
    the vault, so a lock on the vault file itself would get lost
    """
    if fcntl is None:
        yield
        return
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        handle = os.open(path + ".lock", flags, 0o600)
    except OSError:
        raise VaultStorageError("cant lock the vault") from None
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
    finally:
        os.close(handle)  # Closing it drops the lock
