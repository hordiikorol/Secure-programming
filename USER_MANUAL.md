# User manual

pwmanager is a password manager you use from the terminal. One vault file can have several users, each with their own master password, and you only ever see your own entries. An entry is a name (like `gmail.com`), a username and a password.

## 1. Install

You need Linux or WSL and Python 3.10 or newer. On WSL keep the project in your Linux home folder and not under `/mnt/c`, file permissions dont really work there.

Debian or Ubuntu:

```
sudo apt install python3 python3-venv xclip
```

xclip is only for plain Linux, it's what copies passwords to the clipboard. WSL uses the Windows clipboard.

Then in the project folder:

```
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

To check it works, run the tests:

```
python -m unittest discover -v
```

In every new terminal you have to activate the venv again (`. .venv/bin/activate`).

## 2. First start

Make a vault, you'll be the first user:

```
$ python -m pwmanager init
New master password:
Again:
Created vault at /home/alice/.pwmanager.vault with user alice
```

Nothing shows up while you type a password, thats on purpose.

The master password has to be 12 to 1024 characters, cant contain your user name and cant have control characters like Tab or Esc.

If you forget it there's no way to get your entries back.

## 3. Commands

```
python -m pwmanager [--user NAME] [--vault PATH] [--log PATH] COMMAND [ENTRY NAME]
```

| Command | What it does |
|---|---|
| `init` | new vault with you as the first user |
| `register` | add a new user to a vault that already exists |
| `add NAME` | add an entry, asks for username and password |
| `list` | names and usernames of your entries |
| `get NAME` | shows the username, copies the password for 15 sec |
| `edit NAME` | change the username and/or password |
| `delete NAME` | delete an entry (asks y/N first) |
| `passwd` | change your master password |

Everything except `init` and `register` asks for your master password first.

### Add an entry

```
$ python -m pwmanager add gmail.com
Master password:
Username: alice@gmail.com
Password:
Again:
Added gmail.com
```

### List

```
$ python -m pwmanager list
Master password:
gmail.com  (alice@gmail.com)
```

Passwords never show up in the list.

### Get a password

```
$ python -m pwmanager get gmail.com
Master password:
Username: alice@gmail.com
Password copied, clearing clipboard in 15 sec
Clipboard cleared
```

Paste it within 15 seconds. After that the clipboard is cleared, also if you hit Ctrl+C.

### Edit

Leave a field empty to keep what was there:

```
$ python -m pwmanager edit gmail.com
Master password:
New username (empty = keep):
New password (empty = keep):
Again:
Updated gmail.com
```

### Delete

```
$ python -m pwmanager delete gmail.com
Master password:
Delete gmail.com? [y/N] y
Deleted gmail.com
```

Anything except `y` or `yes` cancels it.

### Change master password

```
$ python -m pwmanager passwd
Master password:
New master password:
Again:
Master password changed
```

## 4. More than one user

Your user name is your Linux user name unless you put `--user NAME` before the command:

```
$ python -m pwmanager --user bob register
New master password:
Again:
Added user bob
$ python -m pwmanager --user bob add work-email
```

User names are 1-32 characters, letters, digits, `.`, `_` and `-`, and start with a letter or digit. Case matters, `Bob` and `bob` are two different users.

Users cant see, change or delete each others entries. Two users can both have an entry called the same thing, they're just separate entries.

## 5. Files

| File | What it is |
|---|---|
| `~/.pwmanager.vault` | the encrypted vault, change with `--vault PATH` |
| `~/.pwmanager.vault.lock` | lock file so two commands dont write at once, just leave it |
| `~/.pwmanager.log` | the log, one JSON line per event, change with `--log PATH` |

The vault has to belong to you and have permissions 600 or the program wont open it. If you copied it from somewhere:

```
chmod 600 ~/.pwmanager.vault
```

Back up the vault file now and then. Lose the file or the master password and the entries are gone.

The log never has passwords, keys or entry names in it. A line looks like:

```
{"time": "2026-11-23T17:00:11+00:00", "level": "warning", "event": "login_failed", "session": "797654c0", "user": "alice", "command": "list", "outcome": "failure"}
```

## 6. Error messages

| Message | What to do |
|---|---|
| `wrong user name or master password` | check `--user` and type the password again. It waits a second after every wrong try |
| `no vault there, create one with 'init'` | wrong `--vault` path, or you havent made a vault yet |
| `... can be read by other users, run chmod 600 on it` | run `chmod 600` on the vault |
| `... belongs to another user` | the vault file is owned by another Linux user |
| `the passwords did not match` | the two passwords you typed were different, try again |
| `... has characters that arent allowed` | take out tabs, newlines, escape codes or invisible characters |
| `no clipboard tool found (install xclip)` | `sudo apt install xclip` |
| `this vault is the old single user format` | checkpoint 2 vaults dont open, make a new one with `init` |
| `your part of the vault is damaged or was modified` | the file was changed outside the program, restore a backup |
| `Something went wrong` | unexpected error, the error type is in the log |

## 7. Some tips

- use a long master password, a few random words works
- dont use it on a computer you dont trust, a keylogger would get your master password
- other programs can read the clipboard during those 15 sec, so keep that in mind with `get`
