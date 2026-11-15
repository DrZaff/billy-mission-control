"""Smoke tests for the read-only WSGI app. No server is started; no network is used."""

from __future__ import annotations

import json
import unittest
from wsgiref.util import setup_testing_defaults

from mission_control import PHASE, __version__
from mission_control.app import READ_METHODS, SECURITY_HEADERS, application


def call(path: str = "/", method: str = "GET") -> tuple[str, dict[str, str], bytes]:
    environ: dict = {"PATH_INFO": path, "REQUEST_METHOD": method}
    setup_testing_defaults(environ)
    captured: dict = {}

    def start_response(status, headers, exc_info=None):
        captured["status"], captured["headers"] = status, dict(headers)

    body = b"".join(application(environ, start_response))
    return captured["status"], captured["headers"], body


class Pages(unittest.TestCase):
    def test_index_is_a_small_phone_ready_page(self):
        status, headers, body = call("/")
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        text = body.decode()
        self.assertIn('name="viewport"', text)
        self.assertIn("read-only", text)
        self.assertIn(f"Phase {PHASE}", text)
        self.assertIn('href="/static/app.css"', text)
        self.assertEqual(int(headers["Content-Length"]), len(body))

    def test_health_reports_version_and_phase(self):
        status, headers, body = call("/healthz")
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(body), {"status": "ok", "version": __version__, "phase": PHASE})

    def test_head_has_headers_and_no_body(self):
        status, headers, body = call("/", "HEAD")
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, b"")
        self.assertGreater(int(headers["Content-Length"]), 0)

    def test_unknown_paths_are_not_found(self):
        for path in ("/nope", "/../etc/passwd", "/healthz/", "//", "/index.html"):
            status, _, _ = call(path)
            self.assertEqual(status, "404 Not Found", path)


class ReadOnly(unittest.TestCase):
    def test_every_write_method_is_refused(self):
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"):
            for path in ("/", "/healthz", "/nope", "/tasks", "/static/app.css"):
                status, headers, _ = call(path, method)
                self.assertEqual(status, "405 Method Not Allowed", (method, path))
                self.assertEqual(headers["Allow"], ", ".join(READ_METHODS))

    def test_methods_are_case_insensitive(self):
        self.assertEqual(call("/", "post")[0], "405 Method Not Allowed")
        self.assertEqual(call("/", "get")[0], "200 OK")


class SecurityHeaders(unittest.TestCase):
    def test_every_response_carries_them(self):
        for path, method in (("/", "GET"), ("/healthz", "GET"), ("/nope", "GET"), ("/", "POST")):
            _, headers, _ = call(path, method)
            for name, value in SECURITY_HEADERS:
                self.assertEqual(headers.get(name), value, (path, method, name))

    def test_policy_allows_only_the_apps_own_stylesheet(self):
        csp = dict(SECURITY_HEADERS)["Content-Security-Policy"]
        directives = {d.split()[0]: d.split()[1:] for d in csp.split("; ")}
        self.assertEqual(directives["default-src"], ["'none'"])
        self.assertEqual(directives["style-src"], ["'self'"])
        self.assertEqual(directives["form-action"], ["'none'"])
        self.assertEqual(
            set(directives),
            {"default-src", "style-src", "base-uri", "form-action", "frame-ancestors"},
        )
        self.assertNotIn("script-src", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(dict(SECURITY_HEADERS)["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()
