"""Input validation for everything the user types or the vault file contains

Error messages never repeat the bad value back, so nothing weird ends up in the
terminal or the log
"""

import os
import re

from pwmanager import secure_memory

# Account names show up in the vault file and the log, so keep them boring
ACCOUNT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")

MAX_ENTRY_NAME_LENGTH = 100
MAX_ENTRY_USERNAME_LENGTH = 200
MAX_PASSWORD_LENGTH = 1024
MIN_MASTER_PASSWORD_LENGTH = 12
MAX_PATH_LENGTH = 4096
MAX_ENTRIES_PER_USER = 1000

ENTRY_FIELDS = {"owner", "username", "password"}
CONTENTS_FIELDS = {"owner", "entries"}


class ValidationError(Exception):
    """Bad input. Field says which input it was, for the log"""

    def __init__(self, field, message):
        super().__init__(message)
        self.field = field


def _check_text(value, field, label, min_length, max_length, allow_edge_spaces=False):
    if not isinstance(value, str):
        raise ValidationError(field, f"{label} must be text")
    if not min_length <= len(value) <= max_length:
        raise ValidationError(field, f"{label} must be {min_length}-{max_length} characters")
    # isprintable() is false for control chars (ESC, newline, tab) and for invisible
    # format chars like zero width spaces and right-to-left overrides
    if not value.isprintable():
        raise ValidationError(field, f"{label} has characters that arent allowed")
    if not allow_edge_spaces and value != value.strip():
        raise ValidationError(field, f"{label} cant start or end with a space")
    return value


def check_account_name(name):
    if not isinstance(name, str) or not ACCOUNT_NAME_PATTERN.fullmatch(name):
        raise ValidationError(
            "account", "user name must be 1-32 letters, digits, '.', '_' or '-' and start with a letter or digit")
    return name


def check_entry_name(name):
    return _check_text(name, "entry_name", "entry name", 1, MAX_ENTRY_NAME_LENGTH)


def check_entry_username(username):
    return _check_text(username, "entry_username", "username", 1, MAX_ENTRY_USERNAME_LENGTH)


def check_entry_password(password):
    # Spaces are fine in passwords, even at the ends
    return _check_text(password, "entry_password", "password", 1, MAX_PASSWORD_LENGTH,
                       allow_edge_spaces=True)


def check_master_password(password, account):
    if isinstance(password, (bytes, bytearray)):
        return _check_master_bytes(password, account)
    _check_text(password, "master_password", "master password",
                MIN_MASTER_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH, allow_edge_spaces=True)
    if account.lower() in password.lower():
        raise ValidationError("master_password", "master password cant contain your user name")
    return password


def _check_master_bytes(pw, account):
    # same rules but on the raw bytes, so the password never has to become a str.
    # length is counted in bytes here (non-ascii letters count as 2-4)
    if not MIN_MASTER_PASSWORD_LENGTH <= len(pw) <= MAX_PASSWORD_LENGTH:
        raise ValidationError("master_password", f"master password must be "
                              f"{MIN_MASTER_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters")
    if any(b < 0x20 or b == 0x7f for b in pw):
        raise ValidationError("master_password", "master password has characters that arent allowed")
    low = pw.lower()
    try:
        if account.lower().encode() in low:
            raise ValidationError("master_password", "master password cant contain your user name")
    finally:
        secure_memory.wipe(low)
    return pw


def check_file_path(path, label):
    """Basic sanity check on a path from the command line, returns it absolute"""
    if not isinstance(path, str) or not 1 <= len(path) <= MAX_PATH_LENGTH:
        raise ValidationError("path", f"{label} path is empty or too long")
    if "\x00" in path or not path.isprintable():
        raise ValidationError("path", f"{label} path has characters that arent allowed")
    full_path = os.path.abspath(os.path.expanduser(path))
    if os.path.isdir(full_path):
        raise ValidationError("path", f"{label} path is a folder, not a file")
    if not os.path.isdir(os.path.dirname(full_path)):
        raise ValidationError("path", f"the folder for the {label} doesnt exist")
    return full_path


def is_yes(answer):
    return isinstance(answer, str) and answer.strip().lower() in ("y", "yes")


def check_contents(contents, account):
    """Check the decrypted contents of one user's part of the vault

    GCM already stops tampering, this is so a buggy or old file can't put
    garbage into the program
    """
    if not isinstance(contents, dict) or set(contents) != CONTENTS_FIELDS:
        raise ValidationError("contents", "vault contents have the wrong shape")
    if contents["owner"] != account:
        raise ValidationError("contents", "vault contents belong to someone else")
    entries = contents["entries"]
    if not isinstance(entries, dict) or len(entries) > MAX_ENTRIES_PER_USER:
        raise ValidationError("contents", "vault contents have the wrong shape")
    for name, entry in entries.items():
        check_entry_name(name)
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
            raise ValidationError("contents", "vault entry has the wrong shape")
        if entry["owner"] != account:
            raise ValidationError("contents", "vault entry belongs to someone else")
        check_entry_username(entry["username"])
        check_entry_password(entry["password"])
    return contents
