# Password Manager

Small command line password manager I made for ICS0022 Secure Programming. One encrypted vault file can have several users, everyone has their own master password and only sees their own entries.

How it works in short: the master password goes through scrypt (N=2^17, r=8, p=1, random salt per user). Half of what comes out is stored as a password hash to check the login, the other half is the key that encrypts that user's entries with AES-256-GCM. Passwords are typed hidden, wiped from memory after use and never printed. `get` copies the password to the clipboard and clears it after 15 sec. The log is JSON lines and has no secrets in it.

Other docs:

- USER_MANUAL.md - install, all commands, error messages
- TEST_RESULTS.md - the 116 tests and results
- PROGRESS.md - whats done and known problems
- docs/report.pdf (and .docx) - the report
- docs/DEMO_SCRIPT.md - what I run in the demo

## What you need

Python 3.10+ with venv, on Linux or WSL. On WSL put the project in your Linux home folder, not under /mnt/c, permissions dont work there. On Linux `get` needs xclip, on WSL it uses clip.exe so nothing extra.

Debian/Ubuntu:

```
sudo apt install python3 python3-venv xclip
```

## Setup

```
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Run the tests:

```
python -m unittest discover -v
```

## Usage

```
python -m pwmanager init                # new vault, you're the first user
python -m pwmanager register            # add another user
python -m pwmanager add example.com     # add entry, asks username + password
python -m pwmanager list                # your entries
python -m pwmanager get example.com     # shows username, copies password
python -m pwmanager edit example.com    # change username and/or password
python -m pwmanager delete example.com  # delete entry
python -m pwmanager passwd              # change master password
```

By default your user name in the vault is your OS user name, `--user NAME` picks another one, like `python -m pwmanager --user bob register`.

Vault is ~/.pwmanager.vault and the log is ~/.pwmanager.log, use `--vault PATH` / `--log PATH` (before the command) for other files.

Master password needs 12+ characters and cant contain your user name. If you forget it the entries are gone, theres no recovery.

Vaults from checkpoint 2 (old single user format) dont open anymore, just make a new one with `init`.
