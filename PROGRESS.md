# progress - checkpoint 2

## done

storage.py - vault is one json file, made with 0600 perms. saving writes a temp file and renames it over the old one so a crash cant break the vault. symlinks get refused

crypto.py - key from the master password with scrypt (N=2^17 r=8 p=1, random salt), contents encrypted with AES-256-GCM, new random nonce every save. salt, scrypt settings and nonce are stored in the kdf and cipher parts of the file

vault.py - no hash stored. wrong password = wrong key = gcm decryption fails, vault doesnt open

cli.py - init, add, list, get, delete. passwords typed with getpass and never printed, get copies to clipboard and clears after 15 sec

27 unit tests, fake passwords only

## known problems

- python cant wipe the key/passwords from memory
- if the vault file gets edited by hand and broken it can crash with a traceback instead of a normal error
- get needs xclip on linux (or clip.exe on wsl)
- two instances editing at once = last save wins

## next

- change master password
- edit an entry
