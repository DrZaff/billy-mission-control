"""The append-only events log (design §6 and §11.8): one row per request, plus stop results.

Each row holds a UTC time, this process's id and a sequence number (so rows stay in order
even if the clock moves), and a small JSON record. Text is length-capped and stripped of
control characters before it is stored. Never stored: request headers other than the login,
query strings, tokens, or config values. Triggers refuse UPDATE and DELETE; that is a
convention, not tamper-proofing, so the owner keeps dated exports.

A logging failure never blocks a stop, and is reported rather than hidden.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import secrets
import sqlite3
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path

SCHEMA_VERSION = 1
BUSY_TIMEOUT_MS = 500
LIMITS = {"path": 200, "login": 64, "detail": 200, "method": 10, "kind": 32, "result": 32}
CONTROL = re.compile(r"[\x00-\x1f\x7f]")

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS events ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " at TEXT NOT NULL, process TEXT NOT NULL, seq INTEGER NOT NULL, record TEXT NOT NULL)",
    "CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events"
    " BEGIN SELECT RAISE(ABORT, 'events are append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events"
    " BEGIN SELECT RAISE(ABORT, 'events are append-only'); END",
)


def clean(value: object, limit: int) -> str:
    text = CONTROL.sub("?", str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class Events:
    def __init__(self, path: Path, clock: Callable[[], str] = now):
        self.path = Path(path)
        self.clock = clock
        self.process = secrets.token_hex(4)
        self.sequence = itertools.count(1)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
        db.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        return db

    def initialise(self) -> None:
        """Create the schema (idempotent) with a private file mode. Raises if it can't."""
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(fd)
        with self._connect() as db:
            for statement in SCHEMA:
                db.execute(statement)
            row = db.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()
            if row is None:
                db.execute("INSERT INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
            elif row[0] != str(SCHEMA_VERSION):
                raise sqlite3.DatabaseError(f"events schema {row[0]} is not {SCHEMA_VERSION}")

    def append(self, kind: str, **fields: object) -> bool:
        """Record one event. False if it could not be stored; never raises."""
        record = {"kind": clean(kind, LIMITS["kind"])}
        for key, value in fields.items():
            if key in LIMITS and value is not None:
                record[key] = clean(value, LIMITS[key])
            elif key == "status" and isinstance(value, int):
                record[key] = value
        try:
            db = self._connect()
            try:
                db.execute(
                    "INSERT INTO events (at, process, seq, record) VALUES (?, ?, ?, ?)",
                    (self.clock(), self.process, next(self.sequence), json.dumps(record)),
                )
            finally:
                db.close()
        except (sqlite3.Error, OSError):
            return False
        return True

    def export(self, since: str, out: Path) -> int:
        """Write every event from `since` (YYYY-MM-DD, UTC) to a new file, as JSON Lines.
        Refuses to overwrite a file. Returns the number of events written."""
        day = date.fromisoformat(since).isoformat()
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        count = 0
        db = self._connect()
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                rows = db.execute(
                    "SELECT at, process, seq, record FROM events WHERE at >= ? ORDER BY id",
                    (day,),
                )
                for at, process, seq, record in rows:
                    line = {"at": at, "process": process, "seq": seq, **json.loads(record)}
                    f.write(json.dumps(line, sort_keys=True) + "\n")
                    count += 1
        finally:
            db.close()
        return count
