"""The stop helper: the only thing that sets Billy's stop marker for Mission Control.

It runs as its own account, the one that owns the control folder (A4-pre in the main
repository), on a Unix socket that systemd hands it. It accepts exactly one request, the bytes
`STOP\\n`, and only from the web app's account, checked through the operating system
(SO_PEERCRED), not only the socket's permissions. It takes no paths, arguments or commands.

It creates the marker atomically, without following symlinks, writes it to disk (the file and
its folder), and only then replies `stopped`. It has no code that removes or changes a marker:
the web app can ask for a stop but never clear one. Only the owner clears it, on the server.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
from collections.abc import Callable
from pathlib import Path

MARKER = "STOP"
REQUEST = b"STOP\n"
STOPPED = b"stopped\n"
REFUSED = b"refused\n"
FAILED = b"error\n"
TIMEOUT = 5.0
MAX_REQUEST = 16


def peer_uid(conn: socket.socket) -> int | None:
    """The account on the other end of a Unix socket, from the kernel, or None."""
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    except (OSError, AttributeError):
        return None
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def set_marker(control_dir: Path, owner: int) -> bool:
    """Create the marker, durably. True only if a regular marker file owned by `owner` now
    exists in a folder owned by `owner` that nobody else can write to."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        folder = os.open(control_dir, flags)
    except OSError:
        return False
    try:
        info = os.fstat(folder)
        if info.st_uid != owner or info.st_mode & 0o022:
            return False
        create = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(MARKER, create, 0o644, dir_fd=folder)
        except FileExistsError:
            # Already stopped: confirm it is a real marker, and write it (the file itself, then
            # the folder) to disk again, in case an earlier attempt failed before its fsync.
            # Check the type before opening, and never block on the open: a FIFO in the
            # marker's place would otherwise hang the helper until a writer appeared.
            before = os.stat(MARKER, dir_fd=folder, follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode):
                return False
            nonblocking = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            fd = os.open(MARKER, nonblocking, dir_fd=folder)
            try:
                existing = os.fstat(fd)
                if not stat.S_ISREG(existing.st_mode) or existing.st_uid != owner:
                    return False
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(folder)
            return True
        try:
            os.fchmod(fd, 0o644)
            os.write(fd, b"Set by Mission Control's stop button.\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(folder)
        return True
    except OSError:
        return False
    finally:
        os.close(folder)


def _read_request(conn: socket.socket) -> bytes:
    data = b""
    try:
        while len(data) < MAX_REQUEST and not data.endswith(b"\n"):
            chunk = conn.recv(MAX_REQUEST - len(data))
            if not chunk:
                break
            data += chunk
    except TimeoutError:
        pass  # an incomplete request is simply not a stop request
    return data


def handle(conn: socket.socket, control_dir: Path, owner: int, client_uid: int) -> str:
    """Serve one connection. Returns what happened, for the helper's own log line."""
    conn.settimeout(TIMEOUT)
    try:
        if peer_uid(conn) != client_uid:
            conn.sendall(REFUSED)
            return "refused: wrong account"
        if _read_request(conn) != REQUEST:
            conn.sendall(REFUSED)
            return "refused: not a stop request"
        if set_marker(control_dir, owner):
            conn.sendall(STOPPED)
            return "stopped"
        conn.sendall(FAILED)
        return "error: the marker could not be set"
    except OSError:
        return "error: connection"


def serve(
    listener: socket.socket,
    control_dir: Path,
    owner: int,
    client_uid: int,
    log: Callable[[str], None] = print,
    once: bool = False,
) -> None:
    """Answer requests one at a time. Each connection has a short timeout, so a stuck client
    holds the helper for at most TIMEOUT seconds."""
    while True:
        conn, _ = listener.accept()
        with conn:
            log("stop helper: " + handle(conn, control_dir, owner, client_uid))
        if once:
            return


def confirmers(helper_uid: int) -> frozenset[int]:
    """Who may own the listening socket a stop confirmation comes from: the stop helper, or root.
    With systemd socket activation, systemd (root) creates the listener and hands it to the
    helper, so the kernel reports root as the listener's account. That is safe because the
    start-up checks allow only root and the helper to own the folders above the stop socket:
    no other account can put a socket at that path."""
    return frozenset({0, helper_uid})


def request_stop(path: Path, allowed: frozenset[int], timeout: float = TIMEOUT) -> bool:
    """The web app's side: ask the helper to stop. True only on `stopped` over a socket whose
    listener belongs to an `allowed` account (checked by the kernel), so nothing else that
    manages to listen at the socket's path can fake a confirmation."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(str(path))
            if peer_uid(conn) not in allowed:
                return False
            conn.sendall(REQUEST)
            reply = b""
            while len(reply) < 32:
                chunk = conn.recv(32 - len(reply))
                if not chunk:
                    break
                reply += chunk
    except OSError:
        return False
    return reply == STOPPED
