"""The Mission Control web application (WSGI, standard library only).

Read-only by design: it answers GET and HEAD and refuses every other method. Phase A3 serves the
screens over synthetic demo data (Demo 0), with no credentials and no outbound calls. Later
phases add sign-in and the stop switch (A4), then read-only GitHub data (A5).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from pathlib import Path

from . import PHASE, __version__, views
from .demo import Demo, DemoError, load_file

# Sent on every response. Nothing may load but the app's own stylesheet: no scripts, images,
# fonts, frames, forms or outside resources, until a later phase adds one deliberately (with a
# test).
SECURITY_HEADERS: list[tuple[str, str]] = [
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; "
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


def route(path: str, load: Callable[[], Demo]) -> Response:
    if path in STATIC:
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
    return _html("200 OK", PAGES[path](demo))


def make_app(load: Callable[[], Demo] = load_file) -> Callable[..., Iterable[bytes]]:
    """A WSGI app over the data that `load` returns (the demo file by default)."""

    def application(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO") or "/"
        extra: list[tuple[str, str]] = []

        if method not in READ_METHODS:
            status, content_type, body = _text("405 Method Not Allowed", "Read-only.")
            extra.append(("Allow", ", ".join(READ_METHODS)))
        else:
            status, content_type, body = route(path, load)

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
