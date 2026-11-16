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
from .auth import Auth, AuthError, cleared_cookie, cookie_value, session_cookie
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

# Only the two sign-in pages may run a script: the app's own passkey.js, which calls the
# browser's WebAuthn API and posts to the app. Every other page keeps the policy above.
SIGNIN_CSP = (
    "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
PASSKEY_JS = (Path(__file__).with_name("static") / "passkey.js").read_bytes()
SIGNIN_PAGES = ("/signin", "/enroll")
# Reachable with the owner's Tailscale login but no session yet. Everything else needs both.
OPEN_PATHS = (
    *SIGNIN_PAGES,
    "/static/app.css",
    "/static/passkey.js",
    "/signin/begin",
    "/signin/complete",
    "/enroll/begin",
    "/enroll/complete",
)
JSON_TYPE = "application/json"
MAX_JSON_BODY = 16384
SIGNIN_RATE_LIMIT = 10  # sign-in and enrollment attempts a minute

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


def passkey_script() -> Response:
    return "200 OK", "text/javascript; charset=utf-8", PASSKEY_JS


def _json(status: str, payload: dict) -> Response:
    return status, "application/json", json.dumps(payload).encode("utf-8")


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
SERVICE_STATIC: dict[str, Callable[[], Response]] = {
    "/static/app.css": stylesheet,
    "/static/passkey.js": passkey_script,
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
    auth: Auth
    token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    rate: RateLimit = field(default_factory=RateLimit)
    signin_rate: RateLimit = field(default_factory=lambda: RateLimit(limit=SIGNIN_RATE_LIMIT))


def route(path: str, load: Callable[[], Demo], service: Service | None = None) -> Response:
    if service is not None and path in SERVICE_STATIC:
        return SERVICE_STATIC[path]()
    if service is None and path in STATIC:
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
        return _html("200 OK", views.settings(demo, stop_token=service.token, signed_in=True))
    return _html("200 OK", PAGES[path](demo))


def _same_origin_body(
    environ: dict, service: Service, content_type: str, limit: int
) -> tuple[str | None, bytes]:
    """(why the POST must be refused or None, its body). Origin, fetch metadata, type, size."""
    if environ.get("HTTP_ORIGIN") != service.config.origin:
        return "origin", b""
    if environ.get("HTTP_SEC_FETCH_SITE") != "same-origin":
        return "fetch-site", b""
    if environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower() != content_type:
        return "content-type", b""
    try:
        length = int(environ.get("CONTENT_LENGTH") or "")
    except ValueError:
        return "length", b""
    if not 0 < length <= limit:
        return "length", b""
    try:
        body = environ["wsgi.input"].read(length)
    except OSError:  # includes the request deadline (TimeoutError): refused, never a 500
        return "body-timeout", b""
    if len(body) != length:
        return "body-incomplete", b""
    return None, body


def stop_refusal(environ: dict, service: Service) -> str | None:
    """Why a form POST (the stop, sign-out) must be refused, or None. Every check must pass."""
    refusal, body = _same_origin_body(environ, service, FORM_TYPE, MAX_STOP_BODY)
    if refusal:
        return refusal
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


def json_request(environ: dict, service: Service) -> tuple[str | None, dict]:
    """(why the JSON POST must be refused or None, its object)."""
    refusal, body = _same_origin_body(environ, service, JSON_TYPE, MAX_JSON_BODY)
    if refusal:
        return refusal, {}
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "json", {}
    if not isinstance(data, dict):
        return "json", {}
    return None, data


CEREMONIES = {
    "/enroll/begin": "enroll-begin",
    "/enroll/complete": "enroll",
    "/signin/begin": "signin-begin",
    "/signin/complete": "signin",
}


def ceremony(environ: dict, service: Service, path: str, login: str):
    """A passkey step. Returns (response, event, extra headers). Failures are generic to the
    browser; the events log gets the reason (never a code, challenge, key or cookie)."""
    kind = CEREMONIES[path]
    if not service.signin_rate.allow():
        return _json("429 Too Many Requests", {"ok": False}), {"kind": kind, "result": "rate"}, []
    refusal, data = json_request(environ, service)
    if refusal:
        return (
            _json("403 Forbidden", {"ok": False}),
            {"kind": kind, "result": "refused:" + refusal},
            [],
        )
    auth = service.auth
    try:
        if path == "/enroll/begin":
            return (
                _json("200 OK", auth.enroll_begin(data.get("code"), login)),
                {"kind": kind, "result": "ok"},
                [],
            )
        if path == "/signin/begin":
            return _json("200 OK", auth.signin_begin(login)), {"kind": kind, "result": "ok"}, []
        if path == "/enroll/complete":
            cid = auth.enroll_complete(data.get("ticket"), data.get("credential"), login)
            return (
                _json("200 OK", {"ok": True}),
                {"kind": kind, "result": "ok", "detail": "credential " + cid[:12]},
                [],
            )
        token = auth.signin_complete(data.get("ticket"), data.get("credential"), login)
        return (
            _json("200 OK", {"ok": True}),
            {"kind": kind, "result": "ok"},
            [("Set-Cookie", session_cookie(token))],
        )
    except AuthError as error:
        return (
            _json("400 Bad Request", {"ok": False}),
            {"kind": kind, "result": "failed:" + error.reason},
            [],
        )
    except Exception:  # noqa: BLE001 - the sign-in store is unavailable: refuse, never a 500
        return (
            _json("503 Service Unavailable", {"ok": False}),
            {"kind": kind, "result": "error"},
            [],
        )


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
        if path in CEREMONIES:
            if method != "POST":
                extra.append(("Allow", "POST"))
                return _text("405 Method Not Allowed", "POST only."), extra, event, login
            response, event, cookies = ceremony(environ, service, path, login)
            return response, extra + cookies, event, login
        if path in SIGNIN_PAGES:
            if method not in READ_METHODS:
                extra.append(("Allow", ", ".join(READ_METHODS)))
                return _text("405 Method Not Allowed", "Read-only."), extra, event, login
            extra.append(("Content-Security-Policy", SIGNIN_CSP))
            page = views.signin_page() if path == "/signin" else views.enroll_page()
            return _html("200 OK", page), extra, event, login
        if path not in OPEN_PATHS:
            token = cookie_value(environ.get("HTTP_COOKIE"))
            try:
                problem = service.auth.check_session(token, login)
            except Exception:  # noqa: BLE001 - the sign-in store is unavailable: refuse
                problem = "auth-unavailable"
            if problem:
                event = {"kind": "request", "result": problem}
                if method in READ_METHODS:
                    extra.append(("Location", "/signin"))
                    if problem == "session-expired":
                        extra.append(("Set-Cookie", cleared_cookie()))
                    return _text("303 See Other", "Sign in first."), extra, event, login
                return _text("403 Forbidden", "Sign in first."), extra, event, login
        if path == "/signout":
            if method != "POST":
                extra.append(("Allow", "POST"))
                return _text("405 Method Not Allowed", "POST only."), extra, event, login
            refusal = stop_refusal(environ, service)
            if refusal:
                event = {"kind": "signout", "result": "refused:" + refusal}
                return _text("403 Forbidden", "Refused."), extra, event, login
            result = "ok"
            try:
                service.auth.end_session(cookie_value(environ.get("HTTP_COOKIE")))
            except Exception:  # noqa: BLE001 - the cookie is cleared regardless; say so in the log
                result = "cookie-cleared-session-not-removed"
            extra += [("Set-Cookie", cleared_cookie()), ("Location", "/signin")]
            event = {"kind": "signout", "result": result}
            return _text("303 See Other", "Signed out."), extra, event, login
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
        overrides = {name for name, _ in extra if name == "Content-Security-Policy"}
        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            *[(n, v) for n, v in SECURITY_HEADERS if n not in overrides],
            *extra,
        ]
        start_response(status, headers)
        return [b"" if method == "HEAD" else body]

    return application


application = make_app()
