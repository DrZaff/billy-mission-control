"""Passkey sign-in (phase A4b), the second layer on top of the owner's Tailscale identity.

Every page needs both. The rules, all enforced here:

- **Enrollment** happens only with a one-time code from a shell on the server
  (`python3 -m mission_control passkey enroll`): valid for 10 minutes, used once, stored only as
  a hash, and spent as soon as a registration starts. At most two credentials (the iPhone and a
  hardware backup key). User verification is required.
- **Sign-in** challenges are 32 random bytes, used once, valid for 2 minutes and tied to the
  Tailscale login that asked for them. The signature counter must go up, unless the
  authenticator always reports 0 (synced passkeys do).
- **Sessions** are 32 random bytes in a `__Host-` cookie, stored only as a hash and bound to the
  Tailscale login and the credential that created them: 30 minutes idle, 12 hours at most.
- **Recovery** (`passkey revoke`, `passkey reset`) runs only from a shell on the server.

Nothing secret is ever logged: not codes, challenges, keys or cookies.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


def _passkeys():
    """The WebAuthn module, loaded only when a passkey step runs, so the read-only preview and
    everything outside sign-in need no third-party package installed."""
    from . import passkeys

    return passkeys


SCHEMA_VERSION = 1
BUSY_TIMEOUT_MS = 2000  # long enough for a sign-in in progress to finish
CODE_TTL = 600
CHALLENGE_TTL = 120
IDLE_TIMEOUT = 1800
ABSOLUTE_TIMEOUT = 43200
MAX_CREDENTIALS = 2
COOKIE = "__Host-mc_session"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O or 1/I look-alikes
CODE_LENGTH = 10

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, blob BLOB NOT NULL,"
    " counter INTEGER NOT NULL, label TEXT NOT NULL, created REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, login TEXT NOT NULL,"
    " credential TEXT NOT NULL, created REAL NOT NULL, seen REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS codes (hash TEXT PRIMARY KEY, label TEXT NOT NULL,"
    " created REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS challenges (ticket TEXT PRIMARY KEY, kind TEXT NOT NULL,"
    " login TEXT NOT NULL, state TEXT NOT NULL, label TEXT NOT NULL, created REAL NOT NULL,"
    " used INTEGER NOT NULL DEFAULT 0)",
)


class AuthError(ValueError):
    """A refusal. `reason` is a short code for the events log, never shown in detail."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Credential:
    id: str
    label: str
    created: float
    counter: int


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def normalise_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch in CODE_ALPHABET)


class Auth:
    def __init__(
        self, db: Path, origin: str, owner_login: str, clock: Callable[[], float] = time.time
    ):
        self.db, self.origin, self.owner_login, self.clock = Path(db), origin, owner_login, clock

    # ------------------------------------------------------------------ storage

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db, timeout=0.5, isolation_level=None)
        conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        return conn

    @contextlib.contextmanager
    def _locked(self, conn: sqlite3.Connection):
        """One write transaction, taken before anything is read (BEGIN IMMEDIATE): a sign-in,
        an enrollment, a revoke or a reset runs whole, never interleaved with another."""
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")

    def initialise(self) -> None:
        """Create the schema. Refuses anything but a private regular file of this account."""
        fd = os.open(self.db, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
        finally:
            os.close(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise PermissionError("the sign-in database must be a private file of this account")
        conn = self._connect()
        try:
            for statement in SCHEMA:
                conn.execute(statement)
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()
            if row is None:
                conn.execute("INSERT INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
            elif row[0] != str(SCHEMA_VERSION):
                raise sqlite3.DatabaseError(f"sign-in schema {row[0]} is not {SCHEMA_VERSION}")
        finally:
            conn.close()

    def _active(self, conn: sqlite3.Connection) -> list[tuple[str, bytes, int]]:
        return conn.execute("SELECT id, blob, counter FROM credentials ORDER BY created").fetchall()

    def _take_ticket(self, conn, ticket: object, kind: str, login: str) -> tuple[str, str]:
        if not isinstance(ticket, str) or not 0 < len(ticket) <= 64:
            raise AuthError("ticket")
        # Spend it in one atomic step: of any callers presenting the same ticket at once,
        # exactly one changes used from 0 to 1; every other finds it already used.
        won = conn.execute(
            "UPDATE challenges SET used = 1 WHERE ticket = ? AND used = 0", (ticket,)
        ).rowcount
        row = conn.execute(
            "SELECT kind, login, state, label, created FROM challenges WHERE ticket = ?",
            (ticket,),
        ).fetchone()
        if row is None:
            raise AuthError("ticket")
        if not won:
            raise AuthError("ticket-reused")
        r_kind, r_login, state, label, created = row
        if r_kind != kind:
            raise AuthError("ticket")
        if not hmac.compare_digest(r_login.encode(), login.encode()):
            raise AuthError("ticket-login")
        if self.clock() - created > CHALLENGE_TTL:
            raise AuthError("ticket-expired")
        return state, label

    @staticmethod
    def _still_there(conn, table: str, column: str, key: str, reason: str) -> None:
        """Inside a lock: the spent code or ticket must still exist. A reset deletes every
        code and ticket at once, so whatever was begun before a reset can't finish after it."""
        query = f"SELECT 1 FROM {table} WHERE {column} = ? AND used = 1"  # noqa: S608 - fixed names
        if conn.execute(query, (key,)).fetchone() is None:
            raise AuthError(reason)

    def _ticket(self, conn, kind: str, login: str, state: str, label: str = "") -> str:
        now = self.clock()
        conn.execute("DELETE FROM challenges WHERE created < ?", (now - 3600,))
        ticket = secrets.token_urlsafe(24)
        conn.execute(
            "INSERT INTO challenges (ticket, kind, login, state, label, created)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (ticket, kind, login, state, label, now),
        )
        return ticket

    # ------------------------------------------------------------------ the server shell

    def new_enroll_code(self, label: str) -> str:
        label = "".join(ch for ch in label if ch.isalnum() or ch in " -_.")[:40].strip()
        if not label:
            raise AuthError("label")
        conn = self._connect()
        try:
            if len(self._active(conn)) >= MAX_CREDENTIALS:
                raise AuthError("too-many-credentials")
            raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
            conn.execute(
                "INSERT INTO codes (hash, label, created) VALUES (?, ?, ?)",
                (_hash(raw), label, self.clock()),
            )
        finally:
            conn.close()
        return raw[:5] + "-" + raw[5:]

    def credentials(self) -> list[Credential]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, label, created, counter FROM credentials ORDER BY created"
            ).fetchall()
        finally:
            conn.close()
        return [Credential(*row) for row in rows]

    def revoke(self, credential_id: str) -> bool:
        """Remove one credential and every session it created."""
        conn = self._connect()
        try:
            with self._locked(conn):
                gone = conn.execute(
                    "DELETE FROM credentials WHERE id = ?", (credential_id,)
                ).rowcount
                conn.execute("DELETE FROM sessions WHERE credential = ?", (credential_id,))
        finally:
            conn.close()
        return bool(gone)

    def reset(self) -> int:
        """Remove every credential, session, code and challenge. Returns credentials removed."""
        conn = self._connect()
        try:
            with self._locked(conn):
                gone = conn.execute("DELETE FROM credentials").rowcount
                for table in ("sessions", "codes", "challenges"):
                    conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
        finally:
            conn.close()
        return gone

    # ------------------------------------------------------------------ enrollment (web)

    def enroll_begin(self, code: object, login: str) -> dict:
        if not isinstance(code, str) or len(code) > 40:
            raise AuthError("code")
        digest = _hash(normalise_code(code))
        conn = self._connect()
        try:
            # Spent now, in one atomic step: only one caller can change used from 0 to 1.
            won = conn.execute(
                "UPDATE codes SET used = 1 WHERE hash = ? AND used = 0", (digest,)
            ).rowcount
            row = conn.execute(
                "SELECT label, created FROM codes WHERE hash = ?", (digest,)
            ).fetchone()
            if row is None:
                raise AuthError("code")
            if not won:
                raise AuthError("code-reused")
            label, created = row
            if self.clock() - created > CODE_TTL:
                raise AuthError("code-expired")
            with self._locked(conn):
                # A reset since the code was spent deleted it: begun before a reset, refused.
                self._still_there(conn, "codes", "hash", digest, "code-reset")
                active = self._active(conn)
                if len(active) >= MAX_CREDENTIALS:
                    raise AuthError("too-many-credentials")
                options, state = _passkeys().registration_options(
                    self.origin, login, [blob for _, blob, _ in active]
                )
                ticket = self._ticket(conn, "enroll", login, state, label)
        finally:
            conn.close()
        return {"ticket": ticket, "options": options}

    def enroll_complete(self, ticket: object, response: object, login: str) -> str:
        if not isinstance(response, dict):
            raise AuthError("response")
        conn = self._connect()
        try:
            # The ticket is spent first, on its own, so it stays spent even if this fails.
            state, label = self._take_ticket(conn, ticket, "enroll", login)
            with self._locked(conn):  # the limit check and the insert happen as one
                # A reset since the ticket was spent deleted it: begun before a reset, refused.
                self._still_there(conn, "challenges", "ticket", ticket, "ticket-reset")
                if len(self._active(conn)) >= MAX_CREDENTIALS:
                    raise AuthError("too-many-credentials")
                try:
                    raw_id, blob, counter = _passkeys().register(self.origin, state, response)
                except ValueError as error:  # passkeys.PasskeyError
                    raise AuthError("rejected:" + str(error)[:40]) from None
                cid = _b64(raw_id)
                try:
                    conn.execute(
                        "INSERT INTO credentials (id, blob, counter, label, created)"
                        " VALUES (?, ?, ?, ?, ?)",
                        (cid, blob, counter, label, self.clock()),
                    )
                except sqlite3.IntegrityError:
                    raise AuthError("duplicate") from None
        finally:
            conn.close()
        return cid

    # ------------------------------------------------------------------ sign-in (web)

    def signin_begin(self, login: str) -> dict:
        conn = self._connect()
        try:
            active = self._active(conn)
            if not active:
                raise AuthError("no-credentials")
            options, state = _passkeys().authentication_options(
                self.origin, [blob for _, blob, _ in active]
            )
            ticket = self._ticket(conn, "signin", login, state)
        finally:
            conn.close()
        return {"ticket": ticket, "options": options}

    def signin_complete(self, ticket: object, response: object, login: str) -> str:
        """Check a sign-in. Returns a new session token (the cookie's value)."""
        if not isinstance(response, dict):
            raise AuthError("response")
        conn = self._connect()
        try:
            # The ticket is spent first, on its own, so it stays spent even if this fails.
            state, _ = self._take_ticket(conn, ticket, "signin", login)
            # Reading the passkeys, checking and raising the counter, and opening the session
            # happen as one: a revoke or reset runs wholly before (no passkey to sign in with)
            # or wholly after (it deletes this session with the passkey), never in between.
            with self._locked(conn):
                self._still_there(conn, "challenges", "ticket", ticket, "ticket-reset")
                active = self._active(conn)
                try:
                    raw_id, counter = _passkeys().authenticate(
                        self.origin, state, [blob for _, blob, _ in active], response
                    )
                except ValueError as error:  # passkeys.PasskeyError
                    raise AuthError("rejected:" + str(error)[:40]) from None
                cid = _b64(raw_id)
                stored = next((c for i, _, c in active if i == cid), None)
                if stored is None:
                    raise AuthError("unknown-credential")
                if (counter or stored) and counter <= stored:
                    raise AuthError("counter")  # a cloned authenticator, or a replay
                conn.execute("UPDATE credentials SET counter = ? WHERE id = ?", (counter, cid))
                token = secrets.token_urlsafe(32)
                now = self.clock()
                conn.execute(
                    "INSERT INTO sessions (hash, login, credential, created, seen)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (_hash(token), login, cid, now, now),
                )
        finally:
            conn.close()
        return token

    # ------------------------------------------------------------------ sessions

    def check_session(self, token: str | None, login: str) -> str | None:
        """None if the session is valid (and marks it used), else why not."""
        if not token or len(token) > 100:
            return "no-session"
        digest = _hash(token)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT login, created, seen FROM sessions WHERE hash = ?", (digest,)
            ).fetchone()
            if row is None:
                return "no-session"
            s_login, created, seen = row
            now = self.clock()
            if not hmac.compare_digest(s_login.encode(), login.encode()):
                return "session-login"
            if now - created > ABSOLUTE_TIMEOUT or now - seen > IDLE_TIMEOUT:
                conn.execute("DELETE FROM sessions WHERE hash = ?", (digest,))
                return "session-expired"
            conn.execute("UPDATE sessions SET seen = ? WHERE hash = ?", (now, digest))
        finally:
            conn.close()
        return None

    def end_session(self, token: str | None) -> None:
        if token:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM sessions WHERE hash = ?", (_hash(token),))
            finally:
                conn.close()


def session_cookie(token: str) -> str:
    return (
        f"{COOKIE}={token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={ABSOLUTE_TIMEOUT}"
    )


def cleared_cookie() -> str:
    return f"{COOKIE}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"


def cookie_value(header: str | None) -> str | None:
    """The session cookie's value from a Cookie header, or None. Exactly one is accepted."""
    if not header:
        return None
    values = []
    for part in header.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE:
            values.append(value)
    return values[0] if len(values) == 1 and values[0] else None


__all__ = [
    "ABSOLUTE_TIMEOUT",
    "COOKIE",
    "IDLE_TIMEOUT",
    "MAX_CREDENTIALS",
    "Auth",
    "AuthError",
    "Credential",
    "cleared_cookie",
    "cookie_value",
    "session_cookie",
]
