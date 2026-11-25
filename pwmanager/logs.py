"""Structured logging, one JSON object per line

Only a fixed list of fields can be logged, so a password or key can't end up in
the log by accident. Entry names aren't logged either since they show which sites
you have accounts on
"""

import json
import logging
import os
import secrets
import stat
from datetime import datetime, timezone

LOGGER = logging.getLogger("pwmanager")
LOGGER.addHandler(logging.NullHandler())
LOGGER.propagate = False
LOGGER.setLevel(logging.INFO)

ALLOWED_FIELDS = {"user", "command", "outcome", "reason", "error_type"}
OUTCOMES = {"success", "failure", "denied"}

# random id per run of the program, so you can see which lines belong together
session_id = None
MAX_FIELD_LENGTH = 64


class LogSetupError(Exception):
    pass


class JsonFormatter(logging.Formatter):
    def format(self, record):
        line = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
            "session": session_id,
        }
        line.update(getattr(record, "fields", {}))
        # JSON escapes newlines and control chars so nobody can fake log lines
        return json.dumps(line, ensure_ascii=True)


def setup(path):
    """Send events to path, made with 0600 permissions"""
    global session_id
    shutdown()
    session_id = secrets.token_hex(4)
    logging.raiseExceptions = False  # A broken log shouldn't crash the program
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        handle = os.open(path, flags, 0o600)
    except OSError:
        raise LogSetupError("cant open the log file") from None
    file_info = os.fstat(handle)
    if not stat.S_ISREG(file_info.st_mode) or (
            hasattr(os, "geteuid") and file_info.st_uid != os.geteuid()):
        os.close(handle)
        raise LogSetupError("the log file isnt a normal file owned by you")
    if hasattr(os, "fchmod"):
        os.fchmod(handle, 0o600)
    handler = logging.StreamHandler(os.fdopen(handle, "a", encoding="utf-8"))
    handler.setFormatter(JsonFormatter())
    LOGGER.addHandler(handler)


def shutdown():
    for handler in list(LOGGER.handlers):
        if isinstance(handler, logging.StreamHandler):
            LOGGER.removeHandler(handler)
            handler.close()
            handler.stream.close()


def event(name, level=logging.INFO, **fields):
    # if outcome isnt given: info = success, warning/error = failure
    fields.setdefault("outcome", "success" if level == logging.INFO else "failure")
    if fields["outcome"] not in OUTCOMES:
        raise ValueError("bad outcome")
    for key, value in fields.items():
        if key not in ALLOWED_FIELDS:
            raise ValueError(f"'{key}' is not allowed in the log")
        if not isinstance(value, (str, int)):
            raise ValueError(f"log field '{key}' must be text or a number")
        if isinstance(value, str):
            fields[key] = value[:MAX_FIELD_LENGTH]
    LOGGER.log(level, name, extra={"fields": fields})
