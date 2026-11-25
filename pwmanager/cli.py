"""CLI - init, register, add, get, edit, delete, list, passwd

Passwords are typed hidden (secure_input.read_secret) into a bytearray that gets
wiped after use, and they never get printed.
get puts the password on the clipboard and clears it after 15 sec

Errors shown to the user are short and generic, no tracebacks or OS details.
anything unexpected becomes "something went wrong" and only the error type goes
to the log
"""

import argparse
import getpass
import hmac
import logging
import os
import shutil
import subprocess
import sys
import time

from pwmanager import logs, secure_memory, storage, validation, vault
from pwmanager.secure_input import read_secret

DEFAULT_VAULT_PATH = os.path.join(os.path.expanduser("~"), ".pwmanager.vault")
DEFAULT_LOG_PATH = os.path.join(os.path.expanduser("~"), ".pwmanager.log")
SECONDS_BEFORE_CLEARING = 15
FAILED_LOGIN_DELAY = 1  # Slows down guessing a bit more on top of scrypt

# macOS, Linux, WSL
CLIPBOARD_TOOLS = [["pbcopy"], ["xclip", "-selection", "clipboard"], ["clip.exe"]]


class CliError(Exception):
    pass


def copy_to_clipboard(text):
    for tool_command in CLIPBOARD_TOOLS:
        if shutil.which(tool_command[0]):
            # Password goes in on stdin not as an arg (args show up in ps)
            # devnull bc xclip keeps running in the background
            text_bytes = text.encode("utf-8")
            try:
                subprocess.run(tool_command, input=text_bytes, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            finally:
                secure_memory.wipe_bytes(text_bytes)
            return
    raise CliError("no clipboard tool found (install xclip)")


def ask_new_password(prompt):
    pw = read_secret(prompt)
    again = read_secret("Again: ")
    try:
        same = hmac.compare_digest(pw, again)
    finally:
        secure_memory.wipe(again)
    if not same:
        secure_memory.wipe(pw)
        raise CliError("the passwords did not match")
    return pw


def ask_new_master_password(account):
    pw = ask_new_password("New master password: ")
    try:
        validation.check_master_password(pw, account)
    except validation.ValidationError:
        secure_memory.wipe(pw)
        raise
    return pw


def to_text(pw):
    # entries are saved as json so an entry password has to become a str here
    try:
        return pw.decode("utf-8")
    except UnicodeDecodeError:
        raise validation.ValidationError("entry_password", "password has characters that arent allowed") from None
    finally:
        secure_memory.wipe(pw)


def require_vault(path):
    if not os.path.exists(path):
        raise CliError("no vault there, create one with 'init'")


def login(args, account):
    require_vault(args.vault)
    pw = read_secret("Master password: ")
    try:
        session = vault.login(args.vault, account, pw)
    except vault.LoginFailed:
        logs.event("login_failed", logging.WARNING, user=account, command=args.command)
        time.sleep(FAILED_LOGIN_DELAY)
        raise
    finally:
        secure_memory.wipe(pw)
    logs.event("login_ok", user=account, command=args.command)
    return session


def cmd_init(args, account):
    if os.path.lexists(args.vault):
        raise CliError("theres already a file there")
    pw = ask_new_master_password(account)
    try:
        vault.create(args.vault)
        with storage.locked(args.vault):
            vault.register(args.vault, account, pw)
    finally:
        secure_memory.wipe(pw)
    logs.event("vault_created", user=account)
    print(f"Created vault at {args.vault} with user {account}")


def cmd_register(args, account):
    require_vault(args.vault)
    pw = ask_new_master_password(account)
    try:
        with storage.locked(args.vault):
            vault.register(args.vault, account, pw)
    finally:
        secure_memory.wipe(pw)
    logs.event("user_registered", user=account)
    print(f"Added user {account}")


def cmd_add(args, account):
    name = validation.check_entry_name(args.name)
    with storage.locked(args.vault), login(args, account) as session:
        if session.has_entry(name):
            raise vault.EntryExists()
        username = validation.check_entry_username(input("Username: "))
        password = validation.check_entry_password(to_text(ask_new_password("Password: ")))
        session.add_entry(name, username, password)
        session.save()
    logs.event("entry_added", user=account)
    print(f"Added {name}")


def cmd_list(args, account):
    with storage.locked(args.vault), login(args, account) as session:
        entries = session.list_entries()
    logs.event("entries_listed", user=account)
    if not entries:
        print("No entries yet")
    for name, username in entries:
        print(f"{name}  ({username})")


def cmd_get(args, account):
    name = validation.check_entry_name(args.name)
    with storage.locked(args.vault), login(args, account) as session:
        username, password = session.get_entry(name)
    # Lock is released before the 15 sec wait so other commands aren't blocked
    logs.event("entry_viewed", user=account)
    print(f"Username: {username}")
    copy_to_clipboard(password)
    del password
    print(f"Password copied, clearing clipboard in {SECONDS_BEFORE_CLEARING} sec")
    try:
        time.sleep(SECONDS_BEFORE_CLEARING)
    finally:
        copy_to_clipboard("")  # Runs on ctrl+c too
    print("Clipboard cleared")


def cmd_edit(args, account):
    name = validation.check_entry_name(args.name)
    with storage.locked(args.vault), login(args, account) as session:
        session.get_entry(name)  # Fails early if its not there or not yours
        new_username = input("New username (empty = keep): ")
        new_pw = read_secret("New password (empty = keep): ")
        if new_pw:
            again = read_secret("Again: ")
            same = hmac.compare_digest(new_pw, again)
            secure_memory.wipe(again)
            if not same:
                secure_memory.wipe(new_pw)
                raise CliError("the passwords did not match")
        new_password = to_text(new_pw)
        if not new_username and not new_password:
            print("Nothing changed")
            return
        session.edit_entry(name, username=new_username or None, password=new_password or None)
        session.save()
    logs.event("entry_edited", user=account)
    print(f"Updated {name}")


def cmd_delete(args, account):
    name = validation.check_entry_name(args.name)
    with storage.locked(args.vault), login(args, account) as session:
        session.get_entry(name)
        if not validation.is_yes(input(f"Delete {name}? [y/N] ")):
            print("Ok, not deleted")
            return
        session.delete_entry(name)
        session.save()
    logs.event("entry_deleted", user=account)
    print(f"Deleted {name}")


def cmd_passwd(args, account):
    with storage.locked(args.vault), login(args, account) as session:
        pw = ask_new_master_password(account)
        try:
            session.change_master_password(pw)
        finally:
            secure_memory.wipe(pw)
        session.save()
    logs.event("master_password_changed", user=account)
    print("Master password changed")


def default_account():
    try:
        return getpass.getuser()
    except Exception:
        return None


def build_parser():
    parser = argparse.ArgumentParser(prog="pwmanager", description="Small password manager")
    parser.add_argument("--vault", default=DEFAULT_VAULT_PATH, help="Vault file")
    parser.add_argument("--user", default=None, help="Your user name in the vault (default: your OS user)")
    parser.add_argument("--log", default=DEFAULT_LOG_PATH, help="Log file")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create a new vault with you as the first user").set_defaults(handler=cmd_init)
    commands.add_parser("register", help="Add a new user to the vault").set_defaults(handler=cmd_register)
    commands.add_parser("list", help="List your entries").set_defaults(handler=cmd_list)
    commands.add_parser("passwd", help="Change your master password").set_defaults(handler=cmd_passwd)
    for command_name, handler, help_text in [
        ("add", cmd_add, "Add an entry"),
        ("get", cmd_get, "Show the username and copy the password"),
        ("edit", cmd_edit, "Change an entry's username or password"),
        ("delete", cmd_delete, "Delete an entry"),
    ]:
        command = commands.add_parser(command_name, help=help_text)
        command.add_argument("name")
        command.set_defaults(handler=handler)
    return parser


def main(argv=None):
    secure_memory.harden_process()
    args = build_parser().parse_args(argv)
    try:
        log_path = validation.check_file_path(args.log, "log")
        logs.setup(log_path)
    except (validation.ValidationError, logs.LogSetupError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    account = None
    try:
        args.vault = validation.check_file_path(args.vault, "vault")
        account = validation.check_account_name(args.user if args.user else default_account())
        args.handler(args, account)
        return 0
    except validation.ValidationError as error:
        logs.event("invalid_input", logging.WARNING, command=args.command, reason=error.field)
        print(f"error: {error}", file=sys.stderr)
    except vault.AccessDenied as error:
        print(f"error: {error}", file=sys.stderr)
    except (vault.VaultError, storage.VaultStorageError, CliError) as error:
        logs.event("command_failed", logging.WARNING, command=args.command, error_type=type(error).__name__)
        print(f"error: {error}", file=sys.stderr)
    except subprocess.CalledProcessError:
        logs.event("command_failed", logging.WARNING, command=args.command, error_type="ClipboardError")
        print("error: the clipboard tool failed", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nCancelled", file=sys.stderr)
        return 130
    except Exception as error:
        # No traceback for the user, it could show paths, code or data
        logs.event("unexpected_error", logging.ERROR, command=args.command, error_type=type(error).__name__)
        print("error: Something went wrong", file=sys.stderr)
    finally:
        logs.shutdown()
    return 1
