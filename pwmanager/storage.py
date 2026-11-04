"""reading/writing the vault file

never sees a password or key, the secret part is already encrypted by the time
it gets here so this just deals with the file
"""

import json
import os
import stat
import tempfile

FORMAT_NAME = "pwmanager-vault"
FORMAT_VERSION = 1
MAX_VAULT_BYTES = 10 * 1024 * 1024  # refuse anything over 10MiB


class VaultStorageError(Exception):
    """vault file cant be read/written or isnt a proper vault"""


def validate(vault_file):
    """check the vault looks right, raise VaultStorageError if not"""
    if not isinstance(vault_file, dict):
        raise VaultStorageError("vault must be a JSON object")
    if vault_file.get("format") != FORMAT_NAME:
        raise VaultStorageError("not a vault file")
    if vault_file.get("version") != FORMAT_VERSION:
        raise VaultStorageError("unsupported vault version")
    if not isinstance(vault_file.get("kdf"), dict):
        raise VaultStorageError("vault has no valid 'kdf' section")
    if not isinstance(vault_file.get("cipher"), dict):
        raise VaultStorageError("vault has no valid 'cipher' section")
    if not isinstance(vault_file.get("ciphertext"), str):
        raise VaultStorageError("vault has no valid 'ciphertext' field")


def to_bytes(vault_file):
    validate(vault_file)
    return json.dumps(vault_file, indent=2).encode("utf-8")


def create(path, vault_file):
    """write a new vault file, fails if something is already at path

    O_EXCL does the check and the create in one step so nothing can sneak in
    between and an old vault cant get overwritten by accident. also wont follow
    a symlink. 0600 = only the owner can read/write
    """
    file_bytes = to_bytes(vault_file)
    try:
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise VaultStorageError(f"{path} already exists") from None
    except OSError as error:
        raise VaultStorageError(f"cannot create {path}: {error.strerror}") from None

    try:
        with os.fdopen(handle, "wb") as file:
            file.write(file_bytes)
            file.flush()
            os.fsync(file.fileno())
    except OSError as error:
        os.unlink(path)  # dont leave half a vault lying around
        raise VaultStorageError(f"cannot write {path}: {error.strerror}") from None


def load(path):
    """read the vault file, returns a dict

    open first then check through the handle so the checks are on the file we
    actually read (no toctou race). O_NOFOLLOW refuses a symlink where the vault
    should be
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        handle = os.open(path, flags)
    except FileNotFoundError:
        raise VaultStorageError(f"{path} does not exist") from None
    except OSError as error:
        raise VaultStorageError(f"cannot open {path}: {error.strerror}") from None

    file_info = os.fstat(handle)
    if not stat.S_ISREG(file_info.st_mode):
        os.close(handle)
        raise VaultStorageError(f"{path} is not a regular file")
    if file_info.st_size > MAX_VAULT_BYTES:
        os.close(handle)
        raise VaultStorageError(f"{path} is too large to be a vault")

    with os.fdopen(handle, "rb") as file:
        file_bytes = file.read(MAX_VAULT_BYTES + 1)

    if len(file_bytes) > MAX_VAULT_BYTES:  # could have grown after fstat
        raise VaultStorageError(f"{path} is too large to be a vault")

    try:
        vault_file = json.loads(file_bytes)
    except (ValueError, RecursionError):
        raise VaultStorageError(f"{path} is not a valid vault file") from None

    validate(vault_file)
    return vault_file


def save(path, vault_file):
    """replace the vault in one go

    writes to a temp file in the same folder then renames it over the vault, so
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
    except OSError as error:
        if temp_path is not None and os.path.exists(temp_path):
            os.unlink(temp_path)
        raise VaultStorageError(f"cannot save {path}: {error.strerror}") from None
