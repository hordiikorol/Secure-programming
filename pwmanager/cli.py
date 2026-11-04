"""Command line interface: init, add, list, get, delete.

Passwords are always typed with getpass (not shown) and never printed.
get copies the password to the clipboard and clears it after 15 seconds.
"""

import argparse
import getpass
import os
import shutil
import subprocess
import sys
import time

from pwmanager import storage, vault

DEFAULT_VAULT = os.path.join(os.path.expanduser("~"), ".pwmanager.vault")
MIN_MASTER_LENGTH = 12
CLEAR_AFTER = 15

# macOS, Linux, WSL
CLIPBOARD_TOOLS = [["pbcopy"], ["xclip", "-selection", "clipboard"], ["clip.exe"]]


class CliError(Exception):
    pass


def copy_to_clipboard(text):
    for tool in CLIPBOARD_TOOLS:
        if shutil.which(tool[0]):
            # pass the password on stdin, not as an argument (arguments show up in ps)
            # stdout/stderr go to DEVNULL because xclip stays running in the background
            subprocess.run(tool, input=text.encode("utf-8"), check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
    raise CliError("no clipboard tool found (install xclip)")


def ask_new_password(prompt):
    first = getpass.getpass(prompt)
    if getpass.getpass("Repeat: ") != first:
        raise CliError("the passwords did not match")
    return first


def unlock(path):
    if not os.path.exists(path):
        raise CliError(f"no vault at {path}, create one with 'init'")
    return vault.unlock(path, getpass.getpass("Master password: "))


def cmd_init(args):
    if os.path.exists(args.vault):
        raise CliError(f"{args.vault} already exists")
    password = ask_new_password("New master password: ")
    if len(password) < MIN_MASTER_LENGTH:
        raise CliError(f"master password must be at least {MIN_MASTER_LENGTH} characters")
    vault.create(args.vault, password)
    print(f"Created an empty vault at {args.vault}")


def cmd_add(args):
    # isprintable() rejects control characters like ESC, so names can't mess up the terminal in list
    if not args.name.isprintable():
        raise CliError("entry name must be printable")
    v = unlock(args.vault)
    if args.name in v.entries:
        raise CliError(f"'{args.name}' already exists, delete it first")
    username = input("Username: ")
    if not username.isprintable():
        raise CliError("username must be printable")
    password = ask_new_password("Password: ")
    v.entries[args.name] = {"username": username, "password": password}
    v.save()
    print(f"Added '{args.name}'.")


def cmd_list(args):
    v = unlock(args.vault)
    if not v.entries:
        print("The vault is empty.")
    for name in sorted(v.entries):
        print(f"{name}  ({v.entries[name]['username']})")


def cmd_get(args):
    v = unlock(args.vault)
    if args.name not in v.entries:
        raise CliError(f"no entry named '{args.name}'")
    entry = v.entries[args.name]
    print(f"Username: {entry['username']}")
    copy_to_clipboard(entry["password"])
    print(f"Password copied to the clipboard, clearing it in {CLEAR_AFTER} seconds...")
    try:
        time.sleep(CLEAR_AFTER)
    finally:
        copy_to_clipboard("")  # also runs on Ctrl+C
    print("Clipboard cleared.")


def cmd_delete(args):
    v = unlock(args.vault)
    if args.name not in v.entries:
        raise CliError(f"no entry named '{args.name}'")
    if input(f"Delete '{args.name}'? [y/N] ").strip().lower() != "y":
        print("Nothing deleted.")
        return
    del v.entries[args.name]
    v.save()
    print(f"Deleted '{args.name}'.")


def build_parser():
    parser = argparse.ArgumentParser(prog="pwmanager", description="A small password manager.")
    parser.add_argument("--vault", default=DEFAULT_VAULT, help="vault file")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)
    sub.add_parser("list", help="list entries").set_defaults(func=cmd_list)
    for name, func in [("add", cmd_add), ("get", cmd_get), ("delete", cmd_delete)]:
        p = sub.add_parser(name)
        p.add_argument("name")
        p.set_defaults(func=func)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (CliError, vault.WrongPasswordError, storage.VaultStorageError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError:
        print("error: the clipboard tool failed", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    return 0
