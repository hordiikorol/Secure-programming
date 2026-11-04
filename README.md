# Password Manager

A small command-line password manager for ICS0022 Secure Programming. Credentials
are kept in a single encrypted vault file, unlocked with a master password.

- The key is derived from the master password with scrypt (N=2^17, r=8, p=1).
- The vault is encrypted with AES-256-GCM. A wrong master password makes
  decryption fail, so no password hash is stored.
- Passwords are typed at hidden prompts and are never printed. `get` copies the
  password to the clipboard and clears it after 15 seconds.

See [PROGRESS.md](PROGRESS.md) for the current status.

## Requirements

- Python 3.10 or newer, with `venv`
- Linux, or WSL on Windows (keep the project in your Linux home folder, not under
  `/mnt/c`, because file permissions don't work properly there)
- For `get` on Linux: `xclip`. On WSL the Windows clipboard (`clip.exe`) is used
  and nothing extra is needed.

On Debian or Ubuntu:

```
sudo apt install python3 python3-venv xclip
```

## Set up

From the project folder:

```
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Run the tests

```
python -m unittest discover -v
```

## Use it

```
python -m pwmanager init                # create a vault (asks for a new master password)
python -m pwmanager add example.com     # add an entry (asks for username and password)
python -m pwmanager list                # list entry names and usernames
python -m pwmanager get example.com     # show the username, copy the password to the clipboard
python -m pwmanager delete example.com  # delete an entry
```

The vault is stored in `~/.pwmanager.vault`. Use `--vault PATH` before the command
to use another file, for example `python -m pwmanager --vault test.vault list`.

The master password must be at least 12 characters. If you forget it, the vault
cannot be recovered.
