"""The Mission Control web application (WSGI, standard library only).

Read-only by design: it answers GET and HEAD and refuses every other method. In phase A1 it
serves a placeholder page and a health check, with no data, no credentials and no outbound
calls. Later phases add screens over synthetic fixtures (A3), then read-only GitHub data (A5).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from html import escape

from . import PHASE, __version__

# Sent on every response. No scripts, styles, frames, forms or outside resources are allowed
# until a later phase needs one and adds it deliberately (with a test).
SECURITY_HEADERS: list[tuple[str, str]] = [
    (
        "Content-Security-Policy",
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
]

READ_METHODS = ("GET", "HEAD")

StartResponse = Callable[..., object]
Response = tuple[str, str, bytes]


def index_page() -> Response:
    title = "Billy Mission Control"
    body = (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{escape(title)}</title>\n"
        "</head>\n"
        "<body>\n"
        f"<h1>{escape(title)}</h1>\n"
        f"<p>Phase {escape(PHASE)} skeleton. Read-only. No data is connected yet.</p>\n"
        "</body>\n"
        "</html>\n"
    )
    return "200 OK", "text/html; charset=utf-8", body.encode("utf-8")


def health() -> Response:
    payload = {"status": "ok", "version": __version__, "phase": PHASE}
    return "200 OK", "application/json", json.dumps(payload).encode("utf-8")


ROUTES: dict[str, Callable[[], Response]] = {
    "/": index_page,
    "/healthz": health,
}


def _text(status: str, message: str) -> Response:
    return status, "text/plain; charset=utf-8", (message + "\n").encode("utf-8")


def application(environ: dict, start_response: StartResponse) -> Iterable[bytes]:
    """The WSGI entry point."""
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO") or "/"
    extra: list[tuple[str, str]] = []

    if method not in READ_METHODS:
        status, content_type, body = _text("405 Method Not Allowed", "Read-only.")
        extra.append(("Allow", ", ".join(READ_METHODS)))
    elif path in ROUTES:
        status, content_type, body = ROUTES[path]()
    else:
        status, content_type, body = _text("404 Not Found", "Not found.")

    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        *SECURITY_HEADERS,
        *extra,
    ]
    start_response(status, headers)
    return [b"" if method == "HEAD" else body]
