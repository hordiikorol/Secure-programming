"""Storage layer: reads and writes the vault file.

This module never sees passwords or keys. It only handles the vault file, whose
secret part is already encrypted by the time it gets here.
"""

import json
import os
import stat
import tempfile

FORMAT_NAME = "pwmanager-vault"
FORMAT_VERSION = 1
MAX_VAULT_BYTES = 10 * 1024 * 1024  # refuse to load anything over 10 MiB


class VaultStorageError(Exception):
    """The vault file could not be read or written, or is not a valid vault."""


def validate(vault):
    """Check the vault's structure. Raise VaultStorageError if it is wrong."""
    if not isinstance(vault, dict):
        raise VaultStorageError("vault must be a JSON object")
    if vault.get("format") != FORMAT_NAME:
        raise VaultStorageError("not a vault file")
    if vault.get("version") != FORMAT_VERSION:
        raise VaultStorageError("unsupported vault version")
    if not isinstance(vault.get("kdf"), dict):
        raise VaultStorageError("vault has no valid 'kdf' section")
    if not isinstance(vault.get("cipher"), dict):
        raise VaultStorageError("vault has no valid 'cipher' section")
    if not isinstance(vault.get("ciphertext"), str):
        raise VaultStorageError("vault has no valid 'ciphertext' field")


def _serialise(vault):
    validate(vault)
    return json.dumps(vault, indent=2).encode("utf-8")


def create(path, vault):
    """Write a new vault file. Fails if anything already exists at path.

    O_EXCL makes the check and the creation one atomic step, so nothing can be
    swapped in between them, and an existing vault can't be overwritten by
    accident. O_EXCL also refuses to follow a symlink at path. Mode 0600 means
    only the owner can read or write the file.
    """
    data = _serialise(vault)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise VaultStorageError(f"{path} already exists") from None
    except OSError as e:
        raise VaultStorageError(f"cannot create {path}: {e.strerror}") from None

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        os.unlink(path)  # don't leave a half-written vault behind
        raise VaultStorageError(f"cannot write {path}: {e.strerror}") from None


def load(path):
    """Read a vault file and return it as a dict.

    The file is opened first and then checked through its descriptor, so the
    checks apply to the file actually being read (this avoids a TOCTOU race).
    O_NOFOLLOW refuses a symlink where the vault should be.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise VaultStorageError(f"{path} does not exist") from None
    except OSError as e:
        raise VaultStorageError(f"cannot open {path}: {e.strerror}") from None

    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise VaultStorageError(f"{path} is not a regular file")
    if info.st_size > MAX_VAULT_BYTES:
        os.close(fd)
        raise VaultStorageError(f"{path} is too large to be a vault")

    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_VAULT_BYTES + 1)

    if len(data) > MAX_VAULT_BYTES:  # the file may have grown after fstat
        raise VaultStorageError(f"{path} is too large to be a vault")

    try:
        vault = json.loads(data)
    except (ValueError, RecursionError):
        raise VaultStorageError(f"{path} is not a valid vault file") from None

    validate(vault)
    return vault


def save(path, vault):
    """Replace an existing vault atomically.

    The new contents go into a temporary file in the same folder, which is then
    renamed over the vault. If the program crashes midway, the old vault is
    still intact. mkstemp creates the temporary file with mode 0600.
    """
    data = _serialise(vault)
    folder = os.path.dirname(os.path.abspath(path))
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=folder, prefix=".vault-", suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except OSError as e:
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise VaultStorageError(f"cannot save {path}: {e.strerror}") from None
