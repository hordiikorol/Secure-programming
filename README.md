# password manager

small command line password manager, made it for ICS0022 secure programming. all the logins go in one encrypted vault file and you open it with a master password

key comes from the master password with scrypt (N=2^17 r=8 p=1) and the vault is encrypted with AES-256-GCM. no password hash is stored, wrong master password just means decryption fails. passwords are typed hidden and never printed, get puts it on the clipboard and clears it after 15 sec

what's done / not done is in PROGRESS.md

## what you need

python 3.10+ with venv, on linux or wsl. on wsl keep the project in your linux home folder not /mnt/c, permissions dont really work there. on linux get needs xclip, on wsl it uses clip.exe so nothing extra

debian/ubuntu:

```
sudo apt install python3 python3-venv xclip
```

## setup

```
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

tests:

```
python -m unittest discover -v
```

## usage

```
python -m pwmanager init                # new vault, asks for a master password
python -m pwmanager add example.com     # add entry, asks username + password
python -m pwmanager list                # list names and usernames
python -m pwmanager get example.com     # shows username, copies password
python -m pwmanager delete example.com  # delete entry
```

vault is at ~/.pwmanager.vault, use --vault PATH before the command for another file, eg `python -m pwmanager --vault test.vault list`

master password has to be 12+ chars. forget it and the vault is gone, no recovery
