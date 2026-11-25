# Test results

Run on Debian 13.5 (WSL), Python 3.13.5, cryptography 50.0.2.

Command: `python -m unittest discover -v`

Result: **116 of 116 passed** (took 5.647 s). Only fake passwords are used in the tests.

| Area | Tests | Passed |
|---|---|---|
| Encryption, key derivation and the master password hash (`test_crypto.py`) | 12 | 12 |
| Vault file handling and file validation (`test_storage.py`) | 24 | 24 |
| Input validation edge cases (`test_validation.py`) | 21 | 21 |
| Login, entries and per-user access control (`test_vault.py`) | 21 | 21 |
| Memory handling (wiping, secret input, process hardening) (`test_memory.py`) | 11 | 11 |
| Structured logging (`test_logs.py`) | 9 | 9 |
| Whole commands through the CLI (`test_cli.py`) | 18 | 18 |

## Encryption, key derivation and the master password hash

| Test | Result |
|---|---|
| bytearray password gives same result | pass |
| different salt different key and hash | pass |
| encrypt then decrypt | pass |
| hash is not the key | pass |
| key is a wipeable bytearray | pass |
| modified ciphertext fails | pass |
| new nonce each time | pass |
| part is bound to its user | pass |
| plaintext not in output | pass |
| same password same salt same result | pass |
| wrong password fails | pass |
| wrong password gives different hash | pass |

## Vault file handling and file validation

| Test | Result |
|---|---|
| create refuses symlink | pass |
| create refuses to overwrite | pass |
| create sets owner only permissions | pass |
| create then load returns same vault | pass |
| empty vault is valid | pass |
| invalid vault is not written | pass |
| load missing file | pass |
| load refuses bad cipher settings | pass |
| load refuses bad ciphertext | pass |
| load refuses bad key settings | pass |
| load refuses bad password hash | pass |
| load refuses bad user names | pass |
| load refuses deeply nested json | pass |
| load refuses directory | pass |
| load refuses file readable by others | pass |
| load refuses invalid json | pass |
| load refuses old single user vault | pass |
| load refuses oversized file | pass |
| load refuses symlink | pass |
| load refuses wrong structure | pass |
| lock file is owner only | pass |
| save leaves no temp files | pass |
| save replaces contents and keeps permissions | pass |
| save replaces symlink without writing through it | pass |

## Input validation edge cases

| Test | Result |
|---|---|
| bad names | pass |
| good names | pass |
| not yes | pass |
| yes | pass |
| bad | pass |
| good | pass |
| bad entry names | pass |
| bad passwords | pass |
| bad usernames | pass |
| entry name limit is inclusive | pass |
| error message doesnt echo the value | pass |
| good entry names | pass |
| password can have spaces | pass |
| bytearray master password | pass |
| contains user name | pass |
| control chars | pass |
| exactly minimum length | pass |
| good | pass |
| too short | pass |
| bad paths | pass |
| good path becomes absolute | pass |

## Login, entries and per-user access control

| Test | Result |
|---|---|
| cant log in as another user with own password | pass |
| closed session refuses everything | pass |
| entry owned by someone else is refused | pass |
| saving keeps other users | pass |
| swapping encrypted parts doesnt work | pass |
| users only see their own entries | pass |
| add existing refused | pass |
| add get edit delete | pass |
| every operation validates input | pass |
| missing entry | pass |
| change master password | pass |
| duplicate user refused | pass |
| master password hash is stored | pass |
| nothing in cleartext | pass |
| register and login | pass |
| register validates input | pass |
| tampered data with right password is detected | pass |
| unknown user gets same error | pass |
| user name is case sensitive | pass |
| wrong password | pass |
| wrong password never tries to decrypt | pass |

## Memory handling (wiping, secret input, process hardening)

| Test | Result |
|---|---|
| core dumps disabled | pass |
| reads into bytearray | pass |
| stops at end of input | pass |
| very long input is cut | pass |
| key is wiped when an error happens | pass |
| key is wiped when session closes | pass |
| old key wiped after master password change | pass |
| wipe bytearray | pass |
| wipe bytes in place | pass |
| wipe bytes skips shared objects | pass |
| wipe ignores other types | pass |

## Structured logging

| Test | Result |
|---|---|
| bad outcome refused | pass |
| events are json lines | pass |
| log file is owner only | pass |
| long values are cut | pass |
| newlines cant fake log lines | pass |
| only text and numbers | pass |
| refuses symlink | pass |
| secret fields are refused | pass |
| session and outcome | pass |

## Whole commands through the CLI

| Test | Result |
|---|---|
| add and list | pass |
| bad vault path | pass |
| damaged vault gives clean error | pass |
| delete | pass |
| delete needs yes | pass |
| edit | pass |
| get uses clipboard | pass |
| invalid inputs are rejected | pass |
| log has events but no secrets | pass |
| master password wiped on wrong password | pass |
| mismatched passwords | pass |
| passwd | pass |
| second user cant see first users entries | pass |
| short master password | pass |
| typed passwords are wiped | pass |
| unexpected error is generic | pass |
| unknown user looks like wrong password | pass |
| wrong master password | pass |

## Manual test in a real terminal

The unit tests fake the password prompt, so I also tried the real hidden input in a pseudo terminal, like a person typing:

| Step | Expected | Result |
|---|---|---|
| `init` with matching master passwords | vault created, passwords not shown on screen | pass |
| `add example.com` | entry added, password not shown on screen | pass |
| `list` with right password | `example.com  (site-user)` | pass |
| `list` with wrong password | `error: wrong user name or master password` | pass |
| check vault and log files | both 0600, no password or entry name in either file | pass |
| check the log | every line has time, event, session id, user, outcome | pass |
