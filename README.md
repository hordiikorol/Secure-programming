# Password Manager

A small command-line password manager for ICS0022 Secure Programming. Credentials
are kept in a single encrypted vault file, unlocked with a master password.

Status: in progress. The storage layer is done. Encryption, master password
authentication and the command-line interface are not built yet.

## Requirements

- Python 3.10 or newer
- Linux, or WSL on Windows (keep the project in your Linux home folder, not under
  `/mnt/c`, because file permissions don't work properly there)

## Run the tests

From the project folder:

```
python3 -m unittest discover -v
```
