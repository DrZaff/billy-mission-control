"""The fetcher's refresh socket (phase A5a, issue #16).

Like the stop helper: a Unix socket that systemd hands it, one fixed request (`REFRESH\\n`),
accepted only from the web app's account, checked by the kernel (SO_PEERCRED). One request is
served at a time. A refresh runs at most once a minute (decision A5-1: on demand, never on a
timer). On success the snapshot is replaced; on any failure the last good snapshot stays, and
the status file records the time and a short reason code, never a token or a response.
"""

from __future__ import annotations

import fcntl
import os
import socket
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from mission_control.stopper import TIMEOUT, LineLog, _read_request, log_line, peer_uid

from .config import FetcherConfig
from .github import FetchError, GitHub, load_key
from .snapshot import SNAPSHOT, STATUS, read_json, refresh, write_json

REQUEST = b"REFRESH\n"
OK = b"ok\n"
TOO_SOON = b"too-soon\n"
BUSY = b"busy\n"
LOCK = ".refresh.lock"
REFUSED = b"refused\n"
MIN_INTERVAL = 60.0
MAX_KEY = 16 * 1024


def read_key(path: Path) -> bytes:
    """The App's key, read without following a symlink; never logged or returned anywhere
    else."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise FetchError("key-unreadable") from None
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_KEY + 1)
    if len(data) > MAX_KEY:
        raise FetchError("key-unreadable")
    return data


def github_for(cfg: FetcherConfig) -> GitHub:
    return GitHub(cfg.app_id, load_key(read_key(cfg.key)))


class Refresher:
    """Runs refreshes, at most one every MIN_INTERVAL seconds, and keeps the status file."""

    def __init__(
        self,
        cfg: FetcherConfig,
        github: Callable[[FetcherConfig], GitHub] = github_for,
        clock: Callable[[], float] = time.time,
    ):
        self.cfg = cfg
        self.github = github
        self.clock = clock

    def run(self) -> bytes:
        """One refresh, if none is running and none started in the last minute. A lock file
        held for the whole refresh keeps the service and `fetch-now` from running at once, and
        the attempt is recorded before any network work, so neither a second process nor a
        restart mid-refresh gets round the floor (Codex's review of f772122)."""
        # The folder is opened first, without following a symlink, and the lock made inside
        # it: O_NOFOLLOW on a full path guards only its last part.
        folder_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            folder = os.open(self.cfg.snapshot_dir, folder_flags)
            try:
                lock = os.open(LOCK, flags, 0o600, dir_fd=folder)
            finally:
                os.close(folder)
        except OSError:
            return b"failed:write\n"
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return BUSY
            return self._locked()
        finally:
            os.close(lock)  # releases the lock

    def _locked(self) -> bytes:
        now = self.clock()
        previous = read_json(self.cfg.snapshot_dir, STATUS) or {}
        last = previous.get("attempt_epoch")
        if isinstance(last, (int, float)) and not isinstance(last, bool):
            # A time in the future (a changed clock) counts as now.
            if now - min(last, now) < MIN_INTERVAL:
                return TOO_SOON
        stamp = datetime.fromtimestamp(now, UTC)
        status = {
            "attempt_epoch": now,
            "attempt_at": stamp.isoformat(),
            "snapshot_at": previous.get("snapshot_at"),
            "result": "running",
            "reason": None,
        }
        try:
            write_json(self.cfg.snapshot_dir, STATUS, status)
        except OSError:
            return b"failed:write\n"  # without a recorded attempt, no network work
        try:
            snapshot = refresh(self.cfg, self.github(self.cfg), stamp)
            write_json(self.cfg.snapshot_dir, SNAPSHOT, snapshot)
        except FetchError as error:
            reply, status["result"], status["reason"] = (
                f"failed:{error.code}\n".encode(),
                "failed",
                error.code,
            )
        except OSError:
            reply, status["result"], status["reason"] = b"failed:write\n", "failed", "write"
        else:
            reply, status["result"], status["reason"] = OK, "ok", None
            if snapshot.get("token_revoked") is not True:
                # The data is good, but say so plainly: the token stays valid until it
                # expires, within the hour (Codex's review of 1cc6cf8).
                reply, status["reason"] = b"ok:token-not-revoked\n", "token-not-revoked"
            status["snapshot_at"] = snapshot["fetched_at"]
            status["items"] = len(snapshot["items"])
        try:
            write_json(self.cfg.snapshot_dir, STATUS, status)
        except OSError:
            pass  # the reply still says what happened
        return reply


def handle(conn: socket.socket, refresher: Refresher, client_uid: int) -> str:
    """Serve one connection. Returns what happened, for the fetcher's own log line."""
    conn.settimeout(TIMEOUT)
    try:
        if peer_uid(conn) != client_uid:
            conn.sendall(REFUSED)
            return "refused: wrong account"
        if _read_request(conn) != REQUEST:
            conn.sendall(REFUSED)
            return "refused: not a refresh request"
        reply = refresher.run()
        conn.sendall(reply)
        return "refresh: " + reply.decode().strip()
    except OSError:
        return "error: connection"


def serve(
    listener: socket.socket,
    refresher: Refresher,
    client_uid: int,
    log: Callable[[str], None] | LineLog = log_line,
    once: bool = False,
) -> None:
    """Answer requests one at a time; the connection is closed before the log line is handed
    over, and the log never waits (the stop helper's LineLog)."""
    while True:
        conn, _ = listener.accept()
        with conn:
            result = handle(conn, refresher, client_uid)
        log("fetcher: " + result)
        if once:
            return
