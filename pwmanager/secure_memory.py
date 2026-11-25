"""Best effort memory handling for keys and secrets

Python doesn't let you control memory properly. Strings and bytes are immutable and
the garbage collector can copy things around, so this can't promise every copy is
gone. What it does:
- Keys live in a bytearray and get zeroed when the session closes
- Short lived bytes copies (encoded passwords, decrypted JSON) get zeroed in place
- Core dumps are switched off so a crash doesn't write secrets to disk
"""

import ctypes
import platform
import sys

PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3


def wipe(buffer):
    """Zero a bytearray in place"""
    if isinstance(buffer, bytearray) and buffer:
        buffer[:] = bytes(len(buffer))


def wipe_bytes(data):
    """Zero an immutable bytes object in place (CPython only)

    Only for fresh objects we made ourselves. Empty and 1 byte bytes objects are
    shared singletons in CPython so those are skipped
    """
    if type(data) is not bytes or len(data) < 2:
        return
    if platform.python_implementation() != "CPython":
        return
    # The bytes data sits at the end of the object, followed by a trailing nul
    offset = sys.getsizeof(data) - len(data) - 1
    ctypes.memset(id(data) + offset, 0, len(data))


def harden_process():
    """Switch off core dumps (and ptrace by other processes of the same user on Linux)"""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        except (OSError, AttributeError):
            pass


def is_dumpable():
    """For the tests. None if we can't tell"""
    if not sys.platform.startswith("linux"):
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    return bool(libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0))
