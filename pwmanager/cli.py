"""cli - init, add, list, get, delete

passwords are typed with getpass so they dont show and never get printed.
get puts the password on the clipboard and clears it after 15 sec
"""

import argparse
import getpass
import os
import shutil
import subprocess
import sys
import time

from pwmanager import storage, vault

DEFAULT_VAULT_PATH = os.path.join(os.path.expanduser("~"), ".pwmanager.vault")
MIN_MASTER_PASSWORD_LENGTH = 12
SECONDS_BEFORE_CLEARING = 15

# macOS, Linux, WSL
CLIPBOARD_TOOLS = [["pbcopy"], ["xclip", "-selection", "clipboard"], ["clip.exe"]]


class CliError(Exception):
    pass


def copy_to_clipboard(text):
    for tool_command in CLIPBOARD_TOOLS:
        if shutil.which(tool_command[0]):
            # password goes in on stdin not as an arg (args show up in ps)
            # devnull bc xclip keeps running in the background
            subprocess.run(tool_command, input=text.encode("utf-8"), check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
    raise CliError("no clipboard tool found (install xclip)")


def ask_new_password(prompt):
    password = getpass.getpass(prompt)
    if getpass.getpass("again: ") != password:
        raise CliError("the passwords did not match")
    return password


def unlock(path):
    if not os.path.exists(path):
        raise CliError(f"no vault at {path}, create one with 'init'")
    return vault.unlock(path, getpass.getpass("master password: "))


def cmd_init(args):
    if os.path.exists(args.vault):
        raise CliError(f"{args.vault} already exists")
    password = ask_new_password("new master password: ")
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise CliError(f"master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters")
    vault.create(args.vault, password)
    print(f"created empty vault at {args.vault}")


def cmd_add(args):
    # isprintable() blocks stuff like ESC so a name cant mess up the terminal in list
    if not args.name.isprintable():
        raise CliError("entry name must be printable")
    my_vault = unlock(args.vault)
    if args.name in my_vault.entries:
        raise CliError(f"'{args.name}' already exists, delete it first")
    username = input("username: ")
    if not username.isprintable():
        raise CliError("username must be printable")
    password = ask_new_password("password: ")
    my_vault.entries[args.name] = {"username": username, "password": password}
    my_vault.save()
    print(f"added {args.name}")


def cmd_list(args):
    my_vault = unlock(args.vault)
    if not my_vault.entries:
        print("vault is empty")
    for name in sorted(my_vault.entries):
        print(f"{name}  ({my_vault.entries[name]['username']})")


def cmd_get(args):
    my_vault = unlock(args.vault)
    if args.name not in my_vault.entries:
        raise CliError(f"no entry named '{args.name}'")
    entry = my_vault.entries[args.name]
    print(f"username: {entry['username']}")
    copy_to_clipboard(entry["password"])
    print(f"password copied, clearing clipboard in {SECONDS_BEFORE_CLEARING} sec")
    try:
        time.sleep(SECONDS_BEFORE_CLEARING)
    finally:
        copy_to_clipboard("")  # runs on ctrl+c too
    print("clipboard cleared")


def cmd_delete(args):
    my_vault = unlock(args.vault)
    if args.name not in my_vault.entries:
        raise CliError(f"no entry named '{args.name}'")
    if input(f"delete {args.name}? [y/N] ").strip().lower() != "y":
        print("ok, not deleted")
        return
    del my_vault.entries[args.name]
    my_vault.save()
    print(f"deleted {args.name}")


def build_parser():
    parser = argparse.ArgumentParser(prog="pwmanager", description="small password manager")
    parser.add_argument("--vault", default=DEFAULT_VAULT_PATH, help="vault file")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create a new vault").set_defaults(handler=cmd_init)
    commands.add_parser("list", help="list entries").set_defaults(handler=cmd_list)
    for command_name, handler in [("add", cmd_add), ("get", cmd_get), ("delete", cmd_delete)]:
        command = commands.add_parser(command_name)
        command.add_argument("name")
        command.set_defaults(handler=handler)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.handler(args)
    except (CliError, vault.WrongPasswordError, storage.VaultStorageError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError:
        print("error: the clipboard tool failed", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ncancelled", file=sys.stderr)
        return 130
    return 0
