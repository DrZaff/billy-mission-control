"""Serving the A4a app on a Unix socket that systemd hands over (socket activation).

- **Who may connect:** only the accounts in `proxy_uids` (tailscaled runs as root). The kernel
  reports the connecting account (SO_PEERCRED), so another local account, such as an agent,
  can't speak to the app directly even if the socket's permissions were wrong.
- **Identity:** read here, from exactly one `Tailscale-User-Login` header, and passed to the app
  under `app.LOGIN_KEY`. A request with two login headers, or any header naming the login with
  underscores (`Tailscale_User_Login`, which wsgiref would otherwise merge with the real one),
  gets no identity. Every header whose name contains an underscore is dropped.
- **Limits:** a 10-second socket timeout, at most 40 headers and 8 KB of them. Requests are
  served one at a time.
- **Logs:** nothing about requests goes to journald; the events log records them.
"""

from __future__ import annotations

import os
import socket
import socketserver
from collections.abc import Callable, Iterable
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

from .app import LOGIN_KEY
from .stopper import peer_uid

LOGIN_HEADER = "tailscale-user-login"
MAX_HEADERS = 40
MAX_HEADER_BYTES = 8192
TIMEOUT = 10


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


class Handler(WSGIRequestHandler):
    timeout = TIMEOUT

    def address_string(self) -> str:
        return "unix"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 (the base class's name)
        pass  # the events log records requests; journald gets nothing about them

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
    ):
        socketserver.TCPServer.__init__(self, "unix", Handler, bind_and_activate=False)
        self.socket.close()
        self.socket = listener
        self.proxy_uids = frozenset(proxy_uids)
        self.on_refused = on_refused
        self.server_name, self.server_port = "localhost", 443
        self.setup_environ()
        self.set_app(app)

    def get_request(self):
        conn, _ = self.socket.accept()
        return conn, ("unix", 0)

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
    return sock
