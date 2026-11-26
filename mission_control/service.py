"""Serving the A4a app on a Unix socket that systemd hands over (socket activation).

- **Who may connect:** only the accounts in `proxy_uids` (tailscaled runs as root). The kernel
  reports the connecting account (SO_PEERCRED), so another local account, such as an agent,
  can't speak to the app directly even if the socket's permissions were wrong.
- **Identity:** read here, from exactly one `Tailscale-User-Login` header, and passed to the app
  under `app.LOGIN_KEY`. A request with two login headers, or any header naming the login with
  underscores (`Tailscale_User_Login`, which wsgiref would otherwise merge with the real one),
  gets no identity. Every header whose name contains an underscore is dropped.
- **Limits:** a request must arrive in full within 15 seconds in total, however slowly its bytes
  trickle in (a per-read timeout alone would let a drip of bytes hold the one-at-a-time server),
  with at most 40 headers and 8 KB of them. Requests are served one at a time.
- **Logs:** nothing about requests goes to journald; the events log records them.
"""

from __future__ import annotations

import os
import socket
import socketserver
import time
from collections.abc import Callable, Iterable
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

from .app import LOGIN_KEY
from .stopper import peer_uid

LOGIN_HEADER = "tailscale-user-login"
MAX_HEADERS = 40
MAX_HEADER_BYTES = 8192
TIMEOUT = 10
REQUEST_DEADLINE = 15.0
# Statuses recorded for requests that never reached the app (no response was sent for these).
TIMED_OUT = 408
CONNECTION_LOST = 499  # the client closed or reset the connection (nginx's convention)
SERVER_ERROR = 500


class DeadlineReader:
    """Reads from a socket, but never past a fixed deadline: each read waits only for the time
    left, and an expired deadline raises TimeoutError. Covers what the handler and wsgiref use:
    readline() for the request line and headers, read() for a body."""

    def __init__(self, conn: socket.socket, deadline: float, clock=time.monotonic):
        self.conn, self.deadline, self.clock = conn, deadline, clock
        self.buffer = b""

    def _fill(self) -> bool:
        left = self.deadline - self.clock()
        if left <= 0:
            raise TimeoutError("request deadline")
        self.conn.settimeout(left)
        chunk = self.conn.recv(4096)
        self.buffer += chunk
        return bool(chunk)

    def readline(self, limit: int = -1) -> bytes:
        while b"\n" not in self.buffer and (limit < 0 or len(self.buffer) < limit):
            if not self._fill():
                break
        end = self.buffer.find(b"\n") + 1 or len(self.buffer)
        if limit >= 0:
            end = min(end, limit)
        line, self.buffer = self.buffer[:end], self.buffer[end:]
        return line

    def read(self, size: int = -1) -> bytes:
        while size < 0 or len(self.buffer) < size:
            if not self._fill():
                break
        size = len(self.buffer) if size < 0 else size
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def close(self) -> None:
        self.buffer = b""


def trusted_login(headers) -> str | None:
    """The one login Tailscale Serve set, or None if it is missing, repeated or shadowed."""
    names = [name.lower() for name in headers.keys()]
    if any(n != LOGIN_HEADER and n.replace("_", "-") == LOGIN_HEADER for n in names):
        return None
    values = headers.get_all(LOGIN_HEADER) or []
    if len(values) != 1:
        return None
    value = values[0].strip()
    return value or None


class _Discard:
    """Where wsgiref's error output goes: nowhere. Nothing about requests reaches journald."""

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        pass


class Handler(WSGIRequestHandler):
    timeout = TIMEOUT

    def get_stderr(self):
        return _Discard()

    def setup(self) -> None:
        super().setup()
        self.rfile = DeadlineReader(self.connection, time.monotonic() + REQUEST_DEADLINE)

    def handle(self) -> None:
        try:
            super().handle()
        except TimeoutError:
            self.server.on_rejected(TIMED_OUT)  # too slow: dropped, and recorded
        except OSError:
            # The other end went away mid-request (a reset or a broken pipe): nothing to
            # answer. Recorded, and never a traceback.
            self.server.on_rejected(CONNECTION_LOST)

    def address_string(self) -> str:
        return "unix"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 (the base class's name)
        pass  # the events log records requests; journald gets nothing about them

    def send_error(self, code: int, message: str | None = None, explain: str | None = None):
        # Requests refused while their headers are read (malformed, too long, too many headers)
        # never reach the app, so they are recorded here: the status only, never the raw text.
        self.server.on_rejected(code)
        super().send_error(code, message, explain)

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        size = sum(len(k) + len(v) for k, v in self.headers.items())
        if len(self.headers) > MAX_HEADERS or size > MAX_HEADER_BYTES:
            self.send_error(431)
            return False
        return True

    def get_environ(self) -> dict:
        env = super().get_environ()
        for name in self.headers.keys():
            if "_" in name:
                env.pop("HTTP_" + name.replace("-", "_").upper(), None)
        env.pop("HTTP_TAILSCALE_USER_LOGIN", None)
        env[LOGIN_KEY] = trusted_login(self.headers)
        env["REMOTE_ADDR"] = "unix"
        return env


class UnixWSGIServer(WSGIServer):
    """wsgiref's server on an already-listening Unix socket."""

    address_family = socket.AF_UNIX

    def __init__(
        self,
        listener: socket.socket,
        app: Callable[..., Iterable[bytes]],
        proxy_uids: Iterable[int],
        on_refused: Callable[[int | None], None] = lambda uid: None,
        on_rejected: Callable[[int], None] = lambda code: None,
    ):
        socketserver.TCPServer.__init__(self, "unix", Handler, bind_and_activate=False)
        self.socket.close()
        self.socket = listener
        self.proxy_uids = frozenset(proxy_uids)
        self.on_refused = on_refused
        self.on_rejected = on_rejected
        self.server_name, self.server_port = "localhost", 443
        self.setup_environ()
        self.set_app(app)

    def get_request(self):
        conn, _ = self.socket.accept()
        return conn, ("unix", 0)

    def handle_error(self, request, client_address) -> None:
        # socketserver's default prints a traceback to stderr. Record the failure instead:
        # nothing about requests, and no traceback, reaches journald.
        self.on_rejected(SERVER_ERROR)

    def verify_request(self, request, client_address) -> bool:
        uid = peer_uid(request)
        if uid in self.proxy_uids:
            return True
        self.on_refused(uid)
        return False


def systemd_socket(environ=os.environ, pid: int | None = None) -> socket.socket:
    """The one Unix stream socket systemd passed (LISTEN_FDS=1, fd 3). Anything else refuses."""
    pid = os.getpid() if pid is None else pid
    if environ.get("LISTEN_PID") != str(pid) or environ.get("LISTEN_FDS") != "1":
        raise RuntimeError("no socket from systemd: run this through its .socket unit")
    sock = socket.socket(fileno=3)
    if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_STREAM:
        sock.detach()
        raise RuntimeError("systemd passed something other than a Unix stream socket")
    # Listening, too: one that isn't fails every accept, after the service said it was ready
    # (Codex's review of a86575d).
    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
        sock.detach()
        raise RuntimeError("systemd passed a socket that isn't listening")
    return sock
