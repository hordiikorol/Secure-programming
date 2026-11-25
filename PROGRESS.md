# Progress - final

The project is finished. I skipped turning in a separate checkpoint 3 draft because everything was already done by then, the final report is in docs/.

## Done

Multiple users. One vault file, every user has their own encrypted part with their own salt and key. Commands: init, register, add, list, get, edit, delete, passwd.

Master password. scrypt runs once per login and gives 64 bytes. The second half gets hashed with SHA-256 and stored as the password hash, login compares it in constant time. The first half is the AES-256-GCM key. A wrong password gets stopped by the hash check before anything is decrypted.

Access control (vault.py). Every entry operation goes through `Session._authorize()`, it checks the session is still open and that the entry is yours, and logs access_denied if not. On top of that every user's entries are encrypted with their own key, and the user name goes into GCM as associated data so you cant swap two users parts in the file. The vault file has to be yours and 0600 or it wont open.

Memory (secure_memory.py, secure_input.py). Passwords are read from the terminal byte by byte into a fixed size bytearray (not getpass, that gives a str which cant be wiped) and zeroed right after. Keys are bytearrays and get zeroed when the session closes, also on errors and after passwd. Encoded passwords, decrypted JSON and the clipboard bytes get zeroed too. Core dumps are off and on Linux the process is not dumpable.

Input validation (validation.py). User names, entry names, usernames, passwords, master passwords, paths and the y/N answer are all checked: length, no control or invisible characters, no spaces at the ends where it matters. The vault file gets checked properly too, strict base64, salt/nonce/hash lengths, scrypt N only 2^14..2^18 so a tampered file cant eat all the memory. Decrypted data is checked as well. Error messages never repeat the bad value.

Logging (logs.py). JSON lines in ~/.pwmanager.log (0600). Each line has time, level, event, a random session id for the run, the user and outcome (success/failure/denied). Events: vault_created, user_registered, login_ok, login_failed, entry_added/viewed/edited/deleted, entries_listed, master_password_changed, access_denied, invalid_input, command_failed, unexpected_error. Only a fixed list of fields is allowed so passwords or keys cant end up there by accident. Entry names arent logged either.

Errors. Short messages, no tracebacks. Unknown user and wrong password look the same and take about the same time. Anything unexpected is "Something went wrong" and only the error type goes in the log. A broken vault file gives a normal error, no crash.

Locking. Commands hold a flock on a .lock file so two running at once cant overwrite each other.

Tests: 116, fake passwords only, all pass. See TEST_RESULTS.md.

## Known problems

- entry passwords are inside the encrypted JSON, so after decrypting they are Python strings and those cant be wiped. The cryptography library also keeps its own copy of the key inside AESGCM.
- user names are visible in the vault file
- anyone who can write the vault file can delete it or add a user, they still cant read other users entries
- `get` needs xclip on Linux (or clip.exe on WSL)
