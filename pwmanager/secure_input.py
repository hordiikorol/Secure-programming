"""Reading passwords from the terminal into a bytearray

getpass returns a str and a str can't be wiped. This reads the typed bytes one by
one into a bytearray that was allocated up front (so it never gets resized and
copied), and the caller zeroes it when done.
"""

import os
import sys

from pwmanager import secure_memory

try:
    import termios
except ImportError:
    termios = None

MAX_INPUT = 1100  # a bit more than the longest allowed password


def _read_line(fd):
    buf = bytearray(MAX_INPUT)
    n = 0
    while True:
        c = os.read(fd, 1)
        if not c or c in (b"\n", b"\r"):
            break
        if n < MAX_INPUT:
            buf[n] = c[0]
            n += 1
    out = buf[:n]
    secure_memory.wipe(buf)
    return out


def read_secret(prompt):
    try:
        tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        tty = None

    if tty is None or termios is None:
        if tty is not None:
            os.close(tty)
        # no terminal, eg input piped in. falls back to a normal line read,
        # so here the password does pass through a str
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = sys.stdin.readline().rstrip("\r\n")
        return bytearray(line.encode("utf-8"))

    old = termios.tcgetattr(tty)
    new = termios.tcgetattr(tty)
    new[3] &= ~termios.ECHO  # turn off echo so the password isnt shown
    try:
        os.write(tty, prompt.encode("utf-8"))
        termios.tcsetattr(tty, termios.TCSAFLUSH, new)
        return _read_line(tty)
    finally:
        termios.tcsetattr(tty, termios.TCSAFLUSH, old)
        os.write(tty, b"\n")
        os.close(tty)
