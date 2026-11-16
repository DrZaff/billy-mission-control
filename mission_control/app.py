"""The Mission Control web application (WSGI, standard library only).

Two modes:

- **Development** (`make_app()`): read-only, GET and HEAD only, over the loopback development
  server. No identity, no write action, no events.
- **Service** (`make_app(service=...)`, phase A4a): run by `python3 -m mission_control serve`
  behind Tailscale Serve. Every request must carry the owner's exact Tailscale login, which the
  service's own request handler reads (`service.LOGIN_KEY`); a request without it gets 403. The
  one write action is POST /stop, which asks the stop helper to set Billy's stop marker. Every
  request is recorded in the events log; a logging failure never blocks the stop.

The data is still Demo 0's synthetic data: real GitHub data is phase A5.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs

from . import PHASE, __version__, views
from .config import AppConfig
from .demo import Demo, DemoError, load_file
from .events import Events

# Sent on every response. Nothing may load but the app's own stylesheet, and a form may post
# only to the app itself (the stop button): no scripts, images, fonts, frames or outside
# resources, until a later phase adds one deliberately (with a test).
SECURITY_HEADERS: list[tuple[str, str]] = [
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
]

READ_METHODS = ("GET", "HEAD")
TASK_PATH = re.compile(r"/tasks/([a-z0-9][a-z0-9-]{0,63})")
STYLESHEET = (Path(__file__).with_name("static") / "app.css").read_bytes()
LOGIN_KEY = "mission_control.login"  # set only by the service's request handler
STOP_PATH = "/stop"
FORM_TYPE = "application/x-www-form-urlencoded"
MAX_STOP_BODY = 512
RATE_LIMIT = 120  # requests a minute: far above one person's use

StartResponse = Callable[..., object]
Response = tuple[str, str, bytes]
HTML = "text/html; charset=utf-8"


def _html(status: str, text: str) -> Response:
    return status, HTML, text.encode("utf-8")


def _text(status: str, message: str) -> Response:
    return status, "text/plain; charset=utf-8", (message + "\n").encode("utf-8")


def health() -> Response:
    payload = {"status": "ok", "version": __version__, "phase": PHASE}
    return "200 OK", "application/json", json.dumps(payload).encode("utf-8")


def stylesheet() -> Response:
    return "200 OK", "text/css; charset=utf-8", STYLESHEET


PAGES: dict[str, Callable[[Demo], str]] = {
    "/": views.home,
    "/tasks": views.task_list,
    "/usage": views.usage,
    "/settings": views.settings,
}
STATIC: dict[str, Callable[[], Response]] = {
    "/healthz": health,
    "/static/app.css": stylesheet,
}


@dataclass
class RateLimit:
    limit: int = RATE_LIMIT
    window: float = 60.0
    clock: Callable[[], float] = time.monotonic
    seen: deque = field(default_factory=deque)

    def allow(self) -> bool:
        t = self.clock()
        while self.seen and t - self.seen[0] >= self.window:
            self.seen.popleft()
        if len(self.seen) >= self.limit:
            return False
        self.seen.append(t)
        return True


@dataclass
class Service:
    config: AppConfig
    events: Events
    stop: Callable[[], bool]
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    rate: RateLimit = field(default_factory=RateLimit)


def route(path: str, load: Callable[[], Demo], service: Service | None = None) -> Response:
    if path in STATIC and not (service and path == "/healthz"):
        return STATIC[path]()
    task = TASK_PATH.fullmatch(path)
    if path not in PAGES and not task:
        return _html("404 Not Found", views.not_found())
    try:
        demo = load()
    except (DemoError, OSError):
        # Never a guess: without readable data, show that it is unavailable.
        return _html("503 Service Unavailable", views.unavailable())
    if task:
        entry = demo.entry(task.group(1))
        if entry is None:
            return _html("404 Not Found", views.not_found())
        return _html("200 OK", views.task_detail(demo, entry))
    if path == "/settings" and service:
        return _html("200 OK", views.settings(demo, stop_token=service.token))
    return _html("200 OK", PAGES[path](demo))


def stop_refusal(environ: dict, service: Service) -> str | None:
    """Why a POST /stop must be refused, or None. Every check must pass."""
    if environ.get("HTTP_ORIGIN") != service.config.origin:
        return "origin"
    if environ.get("HTTP_SEC_FETCH_SITE") != "same-origin":
        return "fetch-site"
    if environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower() != FORM_TYPE:
        return "content-type"
    try:
        length = int(environ.get("CONTENT_LENGTH") or "")
    except ValueError:
        return "length"
    if not 0 < length <= MAX_STOP_BODY:
        return "length"
    body = environ["wsgi.input"].read(length)
    try:
        fields = parse_qs(body.decode("ascii"), strict_parsing=True, max_num_fields=2)
    except (UnicodeDecodeError, ValueError):
        return "body"
    tokens = fields.get("token", [])
    if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), service.token.encode()):
        return "token"
    return None


def stop(environ: dict, service: Service) -> tuple[Response, dict]:
    refusal = stop_refusal(environ, service)
    if refusal:
        page = views.stop_refused()
        return _html("403 Forbidden", page), {"kind": "stop", "result": "refused:" + refusal}
    stopped = service.stop()  # first, before any logging: the stop never waits on the log
    status = "200 OK" if stopped else "503 Service Unavailable"
    return _html(status, views.stop_result(stopped)), {
        "kind": "stop",
        "result": "stopped" if stopped else "failed",
    }


def _serve(environ: dict, load: Callable[[], Demo], service: Service | None):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO") or "/"
    extra: list[tuple[str, str]] = []
    event = {"kind": "request"}

    if service is not None:
        login = environ.get(LOGIN_KEY)
        if not isinstance(login, str) or not hmac.compare_digest(
            login.encode(), service.config.owner_login.encode()
        ):
            return _text("403 Forbidden", "Not available."), extra, event, login
        if not service.rate.allow():
            return _text("429 Too Many Requests", "Too many requests."), extra, event, login
        if path == STOP_PATH:
            if method != "POST":
                extra.append(("Allow", "POST"))
                return _text("405 Method Not Allowed", "POST only."), extra, event, login
            response, event = stop(environ, service)
            return response, extra, event, login
    else:
        login = None

    if method not in READ_METHODS:
        extra.append(("Allow", ", ".join(READ_METHODS)))
        return _text("405 Method Not Allowed", "Read-only."), extra, event, login
    return route(path, load, service), extra, event, login


def make_app(
    load: Callable[[], Demo] = load_file, service: Service | None = None
) -> Callable[..., Iterable[bytes]]:
    """A WSGI app over the data that `load` returns. With `service`, the A4a service."""

    def application(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        (status, content_type, body), extra, event, login = _serve(environ, load, service)
        if service is not None:
            logged = service.events.append(
                event.pop("kind"),
                method=method,
                path=environ.get("PATH_INFO") or "/",
                status=int(status.split()[0]),
                login=login if isinstance(login, str) else "(none)",
                **event,
            )
            if not logged and content_type == HTML:
                body = views.with_logging_warning(body.decode("utf-8")).encode("utf-8")
        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            *SECURITY_HEADERS,
            *extra,
        ]
        start_response(status, headers)
        return [b"" if method == "HEAD" else body]

    return application


application = make_app()
