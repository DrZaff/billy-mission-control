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
import re
import socket
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from mission_control.stopper import TIMEOUT, LineLog, _read_request, log_line, peer_uid

from .config import FetcherConfig
from .github import STOPPING, FetchError, GitHub, load_key
from .snapshot import (
    SNAPSHOT,
    STATUS,
    open_folder,
    open_regular,
    read_json,
    refresh,
    write_json,
)

REQUEST = b"REFRESH\n"
OK = b"ok\n"
TOO_SOON = b"too-soon\n"
BUSY = b"busy\n"
LOCK = ".refresh.lock"
# Set while this process holds the lock: a SIGTERM then waits for the refresh to end.
ACTIVE = threading.Event()
REFUSED = b"refused\n"
MIN_INTERVAL = 60.0
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")


def boot_clock() -> tuple[str | None, float]:
    """(this boot's id, seconds since boot). Time since boot never jumps when the wall clock
    is changed, so within one boot it measures the floor exactly (Codex's review of b24ac2d: a
    clock moved back let a refresh skip the floor)."""
    try:
        boot = BOOT_ID.read_text(encoding="ascii").strip()[:64] or None
    except OSError:
        boot = None
    return boot, time.clock_gettime(time.CLOCK_BOOTTIME)


MAX_KEY = 16 * 1024


def _unrecorded(reply: bytes) -> bytes:
    """The reply when the outcome couldn't be written to the status file: what happened, and
    that it isn't on record, never a plain "ok" (Codex's review of d99c9a7). The status file
    still says "running" from the attempt, so a reader never takes it for a recorded success."""
    text = reply.decode("ascii").strip()
    return f"{text}{'+' if ':' in text else ':'}status-not-written\n".encode("ascii")


def read_key(path: Path) -> bytes:
    """The App's key, read without following a symlink; never logged or returned anywhere
    else."""
    try:
        fd = open_regular(path)
    except OSError:
        raise FetchError("key-unreadable") from None
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_KEY + 1)
    if len(data) > MAX_KEY:
        raise FetchError("key-unreadable")
    return data


def github_for(cfg: FetcherConfig) -> GitHub:
    return GitHub(cfg.app_id, load_key(read_key(cfg.key)))


def _check_status(status: dict) -> None:
    """A status file must say when the last attempt was, in finite numbers (Codex's review of
    69ed8e3: missing or non-finite times let a refresh skip the floor). Anything else is
    malformed: ValueError, handled like unreadable JSON."""

    def finite(value) -> bool:
        # Never true or false. A JSON integer can be too large for a float: compared, never
        # converted (Codex's review of 9fb21c8); NaN and infinity fail the comparison.
        return type(value) in (int, float) and 0 <= value <= 2**53

    boot = status.get("boot_id")
    if not finite(status.get("attempt_epoch")) or not finite(status.get("attempt_since_boot")):
        raise ValueError("status times")
    if boot is not None and not isinstance(boot, str):
        raise ValueError("status boot id")


def _snapshot_at(value) -> str | None:
    """The last good snapshot's time, carried over only as a short ISO time (Fable's
    pre-review of 8152df0: any value was copied into every new status file)."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return value if parsed.tzinfo is not None else None


REASON = re.compile(r"[a-z0-9][a-z0-9+:-]{0,63}")


def _last_refresh(previous: dict) -> dict | None:
    """The last refresh's outcome from the previous status, carried over only in its own shape:
    short text, never anything else (the file is trusted only as far as it is checked)."""
    value = previous.get("last_refresh")
    if not isinstance(value, dict) or set(value) != {"result", "reason", "at"}:
        return None
    result, reason, at = value["result"], value["reason"], value["at"]
    # Held to what a refresh writes (audit of b69faa7): a real time, a reason code from the
    # fetcher's own alphabet, and a reason exactly when it failed (or a token outlived it).
    if _snapshot_at(at) is None:
        return None
    if reason is not None and not (isinstance(reason, str) and REASON.fullmatch(reason)):
        return None
    if result == "failed" and reason is None:
        return None
    if result == "ok" and reason not in (None, "token-not-revoked"):
        return None
    if result not in ("ok", "failed"):
        return None
    return {"result": result, "reason": reason, "at": at}


class Refresher:
    """Runs refreshes, at most one every MIN_INTERVAL seconds, and keeps the status file."""

    def __init__(
        self,
        cfg: FetcherConfig,
        github: Callable[[FetcherConfig], GitHub] = github_for,
        clock: Callable[[], float] = time.time,
        boot: Callable[[], tuple[str | None, float]] = boot_clock,
    ):
        self.cfg = cfg
        self.github = github
        self.clock = clock
        self.boot = boot
        self.results: list = []  # selfcheck --github's results, after run(work)

    def run(self, work: Callable[[], list] | None = None) -> bytes:
        """One refresh, if none is running and none started in the last minute. A lock file
        held for the whole refresh keeps the service and `fetch-now` from running at once, and
        the attempt is recorded before any network work, so neither a second process nor a
        restart mid-refresh gets round the floor (Codex's review of f772122)."""
        # The folder is opened first, following no symlink anywhere on its path (open_folder),
        # and the lock made inside it.
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            folder = open_folder(self.cfg.snapshot_dir)
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
            ACTIVE.set()
            try:
                return self._locked(work)
            finally:
                ACTIVE.clear()
        finally:
            os.close(lock)  # releases the lock

    @staticmethod
    def _too_soon(previous: dict, boot_id: str | None, since_boot: float) -> bool:
        """`previous` is a checked status, or empty. Judged by time since boot, which a change
        of the wall clock can't move (Codex's reviews of a1e05e5 and b24ac2d)."""
        last_boot = previous.get("attempt_since_boot")
        if last_boot is None:
            return False  # no earlier attempt
        same_boot = boot_id is not None and previous.get("boot_id") == boot_id
        # With a boot id missing on either side, time since boot still tells: it only goes
        # forward within a boot, so one no smaller than the last is taken as the same boot
        # (Codex's review of 198a66e).
        unknown_boot = boot_id is None or previous.get("boot_id") is None
        if same_boot or (unknown_boot and since_boot >= last_boot):
            return since_boot - last_boot < MIN_INTERVAL
        # Another boot. It began after the last attempt, so time since this boot is a lower
        # bound on the time since that attempt; the wall clock may be wrong before it syncs
        # (pre-review of 9537b08). At most one minute's wait after a restart.
        return since_boot < MIN_INTERVAL

    def _locked(self, work: Callable[[], list] | None = None) -> bytes:
        now = self.clock()
        boot_id, since_boot = self.boot()
        try:
            previous = read_json(self.cfg.snapshot_dir, STATUS, strict=True)
            if previous is not None:
                _check_status(previous)
                # In this boot, an attempt recorded later than now can't be: malformed, not a
                # reason to wait until the uptime catches up (Fable's pre-review of 8152df0).
                same_boot = boot_id is not None and previous.get("boot_id") == boot_id
                if same_boot and previous["attempt_since_boot"] > since_boot:
                    raise ValueError("attempt in the future")
            previous = previous or {}
        except OSError:
            # Unreadable is not "no earlier attempt": without it the floor can't be kept.
            return b"failed:status\n"
        except ValueError:
            # Malformed (Codex's review of 9aeff19): not "no earlier attempt" either. This
            # attempt is recorded in a fresh status file, with no network work, so the next
            # one, a minute later, goes ahead: the floor holds and nobody repairs anything.
            try:
                write_json(
                    self.cfg.snapshot_dir,
                    STATUS,
                    {
                        "boot_id": boot_id,
                        "attempt_since_boot": since_boot,
                        "attempt_epoch": now,
                        "attempt_at": datetime.fromtimestamp(now, UTC).isoformat(),
                        "snapshot_at": None,
                        "last_refresh": None,  # not known: said, never left out (b69faa7)
                        "result": "failed",
                        "reason": "status",
                    },
                )
            except OSError:
                pass
            return b"failed:status\n"
        if self._too_soon(previous, boot_id, since_boot):
            return TOO_SOON
        stamp = datetime.fromtimestamp(now, UTC)
        status = {
            "boot_id": boot_id,
            "attempt_since_boot": since_boot,
            "attempt_epoch": now,
            "attempt_at": stamp.isoformat(),
            "snapshot_at": _snapshot_at(previous.get("snapshot_at")),
            # The last refresh's outcome, kept apart so a selfcheck never erases it (audit of
            # 24973b8).
            "last_refresh": _last_refresh(previous),
            "result": "running",
            "reason": None,
        }
        try:
            write_json(self.cfg.snapshot_dir, STATUS, status, durable=True)
        except OSError:
            return b"failed:write\n"  # without a durably recorded attempt, no network work
        if work is not None:
            # `selfcheck --github`: GitHub requests under the same lock, floor and durably
            # recorded attempt as a refresh, though it writes no snapshot (audit of e58b933).
            try:
                self.results = work()
                failed = [c for c in self.results if not c.ok]
                if failed:
                    # A failure on record, never a neutral "selfcheck" (audit of 24973b8).
                    reason = "selfcheck-failed"
                    # However found: the revoke check, or a refused token's own failed revoke
                    # (audit of b69faa7).
                    if any(
                        c.name == "token revoked" or "token-not-revoked" in str(c.detail)
                        for c in failed
                    ):
                        reason += "+token-not-revoked"
                    reply = f"failed:{reason}\n".encode()
                    status["result"], status["reason"] = "failed", reason
                else:
                    reply, status["result"] = OK, "selfcheck"
            except FetchError as error:
                reply, status["result"], status["reason"] = (
                    f"failed:{error.code}\n".encode(),
                    "failed",
                    error.code,
                )
            except Exception:  # noqa: BLE001 - as for a refresh
                reply, status["result"], status["reason"] = (
                    b"failed:internal\n",
                    "failed",
                    "internal",
                )
            try:
                write_json(self.cfg.snapshot_dir, STATUS, status)
            except OSError:
                return _unrecorded(reply)
            return reply
        snapshot = None
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
            reason = "write"
            if snapshot is not None and snapshot.get("token_revoked") is not True:
                reason += "+token-not-revoked"  # pre-review of 9537b08: it was lost here
            reply, status["result"], status["reason"] = (
                f"failed:{reason}\n".encode(),
                "failed",
                reason,
            )
        except Exception:  # noqa: BLE001 - a surprise fails this refresh, never the service
            # (Codex's review of 23bfb61: one escaped and stopped the fetcher).
            reply, status["result"], status["reason"] = b"failed:internal\n", "failed", "internal"
        else:
            reply, status["result"], status["reason"] = OK, "ok", None
            if snapshot.get("token_revoked") is not True:
                # The data is good, but say so plainly: the token stays valid until it
                # expires, within the hour (Codex's review of 1cc6cf8).
                reply, status["reason"] = b"ok:token-not-revoked\n", "token-not-revoked"
            status["snapshot_at"] = snapshot["fetched_at"]
            status["items"] = len(snapshot["items"])
        status["last_refresh"] = {
            "result": status["result"],
            "reason": status["reason"],
            "at": status["attempt_at"],
        }
        try:
            write_json(self.cfg.snapshot_dir, STATUS, status)
        except OSError:
            return _unrecorded(reply)
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
        try:
            conn, _ = listener.accept()
        except OSError:
            # A failed accept (an aborted connection, too many open files) fails that one
            # request, never the service (pre-review of 9537b08); the pause stops a spin.
            log("fetcher: error: accept")
            time.sleep(1)
            continue
        with conn:
            result = handle(conn, refresher, client_uid)
        log("fetcher: " + result)
        if once or STOPPING.is_set():
            return
