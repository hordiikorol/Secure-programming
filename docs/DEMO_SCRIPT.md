# Demo script (about 5 min)

Everything runs in a separate `~/demo` folder so my real vault doesnt get touched. Make the terminal font big first.

All the passwords here are made up for the demo, type them when asked (they dont show on screen).

## 0. Before the presentation

```
cd ~/Secure-programming
. .venv/bin/activate
python -m unittest discover        # should say OK, backup if the live demo breaks
mkdir -p ~/demo && rm -f ~/demo/*
alias pm='python -m pwmanager --vault ~/demo/vault --log ~/demo/log'
```

## 1. Normal use (slide "What it does")

```
pm --user alice init                  # master password: correct horse battery
pm --user alice add gmail.com         # username alice@gmail.com, password demo-pass-123
pm --user alice list
pm --user alice get gmail.com         # paste it somewhere within 15 s, then show its gone
```

Point out: nothing was echoed while typing, and `list` doesnt show passwords.

## 2. Failed logins look the same (slide "Master password")

```
pm --user alice list                  # type a wrong password
pm --user nobody list                 # any password
```

Both say `error: wrong user name or master password`. The second one still runs scrypt so it takes the same time too. Every failure also waits 1 extra second.

## 3. Users are separate (slide "Per-user access control")

```
pm --user bob register                # master password: purple monkey dishwasher
pm --user bob list                    # bob has nothing
pm --user bob get gmail.com           # error: no entry with that name
```

## 4. Bad input gets rejected (slide "Everything coming in is checked")

```
pm --user alice add $'evil\e[31mname'       # escape code in the name
pm --user 'alice;rm -rf ~' list             # shell stuff in the user name
pm --user carol register                    # try "carol-password-1": has the user name in it
pm --user carol register                    # try "short": too short
```

Each one gives a short error and never prints the bad value back.

## 5. No secrets in the files (slide "Useful log, nothing secret in it")

```
ls -l ~/demo                                   # vault and log are -rw------- (0600)
head -c 600 ~/demo/vault; echo                 # only user names are readable
grep -c 'demo-pass-123\|correct horse\|gmail' ~/demo/vault ~/demo/log   # both 0
tail -n 4 ~/demo/log                           # events with session id and outcome
```

## 6. File permissions and tampering (slide "Each user gets their own encrypted part")

Permissions:

```
chmod 644 ~/demo/vault
pm --user alice list                  # refused, other users could read it
chmod 600 ~/demo/vault
```

Change one character in alice's encrypted data:

```
python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); c=d['users']['alice']['ciphertext']; d['users']['alice']['ciphertext']=c[:10]+('B' if c[10]!='B' else 'C')+c[11:]; json.dump(d,open(p,'w'))" ~/demo/vault
pm --user alice list                  # right password -> "your part of the vault is damaged or was modified"
pm --user bob list                    # bob's part is fine and still works
```

## 7. If something breaks

Just run the tests and show them passing:

```
python -m unittest discover -v
```

## Questions they might ask

- **Why scrypt and not bcrypt?** Both are slow salted password hashes. scrypt also needs a lot of memory (about 128 MiB per guess) so GPUs are bad at it, and the same run gives me the encryption key.
- **Isnt storing a hash a weakness?** Attacking it costs exactly as much as scrypt itself, and it's from the other half of the output than the key so it says nothing about the key.
- **Why a new nonce every save?** Same nonce twice with the same key breaks AES-GCM.
- **What's TOCTOU?** Time of check to time of use. If you check a file and then open it, someone can swap it in between. I open first and then check the file that's already open.
- **What cant be wiped from memory?** Decrypted entry passwords are Python strings, those cant be overwritten. Typed passwords and keys are bytearrays and do get wiped.
- **Why a separate lock file?** Saving renames a new file over the vault, so a lock on the old file would just disappear.
