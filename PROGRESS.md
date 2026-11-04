# Progress note - Checkpoint 2

## Done

- Storage (`storage.py`): the vault is one JSON file, created with 0600
  permissions, saved atomically (temp file + rename), symlinks refused.
- Encryption (`crypto.py`): key from the master password with scrypt
  (N=2^17, r=8, p=1, random salt), contents encrypted with AES-256-GCM with a
  new random nonce on every save. Salt, scrypt settings and nonce are stored in
  the `kdf` and `cipher` sections.
- Master password (`vault.py`): no hash is stored. A wrong password gives a
  wrong key, so GCM decryption fails and the vault doesn't open.
- CLI (`cli.py`): init, add, list, get, delete. Passwords are typed with
  getpass and never printed, `get` copies to the clipboard and clears it after
  15 seconds.
- 27 unit tests (fake passwords only).

## Known problems

- Python can't wipe the key/passwords from memory.
- A vault file edited by hand in a broken way can crash the program with a
  traceback instead of a nice error.
- `get` needs xclip on Linux (or clip.exe on WSL).
- If two instances edit the vault at the same time, the last save wins.

## Next

- change master password
- edit an entry
