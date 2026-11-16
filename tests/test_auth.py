"""Phase A4b: passkey sign-in on top of the Tailscale identity. A synthetic software
authenticator (tests/softkey.py) stands in for the iPhone and the security key."""

from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from wsgiref.util import setup_testing_defaults

from mission_control import auth as auth_module
from mission_control.__main__ import passkey_main
from mission_control.app import LOGIN_KEY, SECURITY_HEADERS, SIGNIN_CSP, Service, make_app
from mission_control.auth import (
    ABSOLUTE_TIMEOUT,
    CHALLENGE_TTL,
    CODE_TTL,
    COOKIE,
    IDLE_TIMEOUT,
    Auth,
    AuthError,
    cookie_value,
    session_cookie,
)
from mission_control.config import parse_app
from mission_control.events import Events
from tests.softkey import SoftKey

ROOT = Path(__file__).resolve().parent.parent
ORIGIN = "https://mission-control.example.invalid"
OWNER = "owner@example.com"
OTHER = "someone@example.com"


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


def tmp(case) -> Path:
    path = Path(tempfile.mkdtemp())
    case.addCleanup(shutil.rmtree, path, ignore_errors=True)
    return path


class Fixture(unittest.TestCase):
    def setUp(self):
        self.base = tmp(self)
        self.clock = Clock()
        self.auth = Auth(self.base / "auth.db", ORIGIN, OWNER, clock=self.clock)
        self.auth.initialise()

    def enroll(self, key: SoftKey, label="iPhone", **create) -> str:
        code = self.auth.new_enroll_code(label)
        begin = self.auth.enroll_begin(code, OWNER)
        return self.auth.enroll_complete(
            begin["ticket"], key.create(begin["options"], **create), OWNER
        )

    def signin(self, key: SoftKey, login=OWNER, **get) -> str:
        begin = self.auth.signin_begin(login)
        return self.auth.signin_complete(begin["ticket"], key.get(begin["options"], **get), login)

    def refused(self, reason_start: str, fn, *args):
        with self.assertRaises(AuthError) as caught:
            fn(*args)
        self.assertTrue(caught.exception.reason.startswith(reason_start), caught.exception.reason)


# ---------------------------------------------------------------- enrollment


class Enrollment(Fixture):
    def test_a_code_enrolls_one_passkey(self):
        cid = self.enroll(SoftKey(ORIGIN))
        creds = self.auth.credentials()
        self.assertEqual([(c.id, c.label) for c in creds], [(cid, "iPhone")])

    def test_codes_are_formatted_and_case_insensitive(self):
        code = self.auth.new_enroll_code("iPhone")
        self.assertRegex(code, r"^[A-Z2-9]{5}-[A-Z2-9]{5}$")
        begin = self.auth.enroll_begin(code.lower().replace("-", " "), OWNER)
        self.assertIn("ticket", begin)

    def test_a_code_is_never_stored_and_works_once(self):
        code = self.auth.new_enroll_code("iPhone")
        raw = code.replace("-", "")
        self.assertNotIn(raw.encode(), (self.base / "auth.db").read_bytes())
        self.auth.enroll_begin(code, OWNER)
        self.refused("code-reused", self.auth.enroll_begin, code, OWNER)

    def test_wrong_and_expired_codes(self):
        self.refused("code", self.auth.enroll_begin, "AAAAA-AAAAA", OWNER)
        self.refused("code", self.auth.enroll_begin, ["not", "text"], OWNER)
        code = self.auth.new_enroll_code("iPhone")
        self.clock.now += CODE_TTL + 1
        self.refused("code-expired", self.auth.enroll_begin, code, OWNER)

    def test_at_most_two_passkeys(self):
        self.enroll(SoftKey(ORIGIN), "iPhone")
        self.enroll(SoftKey(ORIGIN), "key")
        self.refused("too-many-credentials", self.auth.new_enroll_code, "third")

    def test_a_code_made_before_the_second_passkey_cant_add_a_third(self):
        spare = self.auth.new_enroll_code("spare")
        self.enroll(SoftKey(ORIGIN), "iPhone")
        self.enroll(SoftKey(ORIGIN), "key")
        self.refused("too-many-credentials", self.auth.enroll_begin, spare, OWNER)

    def test_registration_needs_user_verification_the_right_origin_and_rp(self):
        for create in (
            {"uv": False},
            {"origin": "https://evil.example"},
            {"rp_id": "evil.example"},
            {"kind": "webauthn.get"},
        ):
            code = self.auth.new_enroll_code("iPhone")
            begin = self.auth.enroll_begin(code, OWNER)
            response = SoftKey(ORIGIN).create(begin["options"], **create)
            self.refused("rejected", self.auth.enroll_complete, begin["ticket"], response, OWNER)
        self.assertEqual(self.auth.credentials(), [])

    def test_garbage_responses_are_refused_not_crashes(self):
        for response in ({}, {"id": "x"}, {"response": {"clientDataJSON": "!!"}}, "text", None):
            code = self.auth.new_enroll_code("iPhone")
            begin = self.auth.enroll_begin(code, OWNER)
            with self.assertRaises(AuthError):
                self.auth.enroll_complete(begin["ticket"], response, OWNER)

    def test_an_enrollment_ticket_is_single_use_timed_and_tied_to_the_login(self):
        key = SoftKey(ORIGIN)
        code = self.auth.new_enroll_code("iPhone")
        begin = self.auth.enroll_begin(code, OWNER)
        response = key.create(begin["options"])
        self.refused("ticket-login", self.auth.enroll_complete, begin["ticket"], response, OTHER)
        self.refused("ticket-reused", self.auth.enroll_complete, begin["ticket"], response, OWNER)
        code = self.auth.new_enroll_code("iPhone")
        begin = self.auth.enroll_begin(code, OWNER)
        self.clock.now += CHALLENGE_TTL + 1
        self.refused(
            "ticket-expired",
            self.auth.enroll_complete,
            begin["ticket"],
            key.create(begin["options"]),
            OWNER,
        )


# ---------------------------------------------------------------- sign-in


class SignIn(Fixture):
    def setUp(self):
        super().setUp()
        self.key = SoftKey(ORIGIN)
        self.cid = self.enroll(self.key)

    def test_a_good_sign_in_opens_a_session(self):
        token = self.signin(self.key)
        self.assertIsNone(self.auth.check_session(token, OWNER))
        self.assertNotIn(token.encode(), (self.base / "auth.db").read_bytes())

    def test_no_passkeys_no_sign_in(self):
        self.auth.reset()
        self.refused("no-credentials", self.auth.signin_begin, OWNER)

    def test_each_check_refuses(self):
        for get in (
            {"uv": False},
            {"origin": "https://evil.example"},
            {"rp_id": "evil.example"},
            {"tamper": True},
        ):
            begin = self.auth.signin_begin(OWNER)
            response = self.key.get(begin["options"], **get)
            self.refused("rejected", self.auth.signin_complete, begin["ticket"], response, OWNER)

    def test_a_ticket_is_single_use_timed_and_tied_to_the_login(self):
        begin = self.auth.signin_begin(OWNER)
        response = self.key.get(begin["options"])
        self.refused("ticket-login", self.auth.signin_complete, begin["ticket"], response, OTHER)
        self.refused("ticket-reused", self.auth.signin_complete, begin["ticket"], response, OWNER)
        begin = self.auth.signin_begin(OWNER)
        self.clock.now += CHALLENGE_TTL + 1
        self.refused(
            "ticket-expired",
            self.auth.signin_complete,
            begin["ticket"],
            self.key.get(begin["options"]),
            OWNER,
        )
        self.refused("ticket", self.auth.signin_complete, "made-up", response, OWNER)

    def test_the_counter_must_go_up(self):
        self.signin(self.key, counter=5)
        for counter in (5, 3, 0):
            begin = self.auth.signin_begin(OWNER)
            response = self.key.get(begin["options"], counter=counter)
            self.refused("counter", self.auth.signin_complete, begin["ticket"], response, OWNER)
        self.signin(self.key, counter=6)

    def test_an_authenticator_that_always_reports_zero_is_accepted(self):
        synced = SoftKey(ORIGIN, step=0)
        self.enroll(synced, "synced")
        self.signin(synced)
        self.signin(synced)

    def test_a_revoked_passkey_cant_sign_in_and_its_sessions_end(self):
        token = self.signin(self.key)
        self.assertTrue(self.auth.revoke(self.cid))
        self.assertEqual(self.auth.check_session(token, OWNER), "no-session")
        self.refused("no-credentials", self.auth.signin_begin, OWNER)

    def test_an_unknown_passkey_cant_sign_in(self):
        stranger = SoftKey(ORIGIN)
        begin = self.auth.signin_begin(OWNER)
        response = stranger.get(begin["options"])
        self.refused("rejected", self.auth.signin_complete, begin["ticket"], response, OWNER)


# ---------------------------------------------------------------- sessions


class Sessions(Fixture):
    def setUp(self):
        super().setUp()
        self.key = SoftKey(ORIGIN)
        self.enroll(self.key)

    def test_idle_and_absolute_timeouts(self):
        token = self.signin(self.key)
        self.clock.now += IDLE_TIMEOUT - 10
        self.assertIsNone(self.auth.check_session(token, OWNER))  # and this refreshes it
        self.clock.now += IDLE_TIMEOUT + 1
        self.assertEqual(self.auth.check_session(token, OWNER), "session-expired")
        token = self.signin(self.key)
        for _ in range(ABSOLUTE_TIMEOUT // (IDLE_TIMEOUT - 60) + 1):
            self.clock.now += IDLE_TIMEOUT - 60
            if self.auth.check_session(token, OWNER):
                break
        self.assertEqual(self.auth.check_session(token, OWNER), "no-session")

    def test_a_session_is_tied_to_its_login(self):
        token = self.signin(self.key)
        self.assertEqual(self.auth.check_session(token, OTHER), "session-login")
        self.assertEqual(self.auth.check_session("made-up", OWNER), "no-session")
        self.assertEqual(self.auth.check_session(None, OWNER), "no-session")

    def test_sign_out_and_reset_end_sessions(self):
        token = self.signin(self.key)
        self.auth.end_session(token)
        self.assertEqual(self.auth.check_session(token, OWNER), "no-session")
        token = self.signin(self.key)
        self.assertEqual(self.auth.reset(), 1)
        self.assertEqual(self.auth.check_session(token, OWNER), "no-session")
        self.assertEqual(self.auth.credentials(), [])

    def test_the_cookie(self):
        cookie = session_cookie("tok")
        for part in ("__Host-mc_session=tok", "Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(part, cookie)
        self.assertNotIn("Domain", cookie)
        self.assertEqual(cookie_value(f"a=1; {COOKIE}=tok; b=2"), "tok")
        self.assertIsNone(cookie_value(f"{COOKIE}=one; {COOKIE}=two"))  # never guess
        self.assertIsNone(cookie_value(f"{COOKIE}="))
        self.assertIsNone(cookie_value(None))

    def test_a_private_database_only(self):
        db = self.base / "other.db"
        db.write_text("")
        os.chmod(db, 0o644)
        with self.assertRaises(PermissionError):
            Auth(db, ORIGIN, OWNER).initialise()


# ---------------------------------------------------------------- the web flow


class WebFlow(unittest.TestCase):
    def setUp(self):
        self.base = tmp(self)
        (self.base / "state").mkdir()
        text = json.dumps(
            {
                "origin": ORIGIN,
                "owner_login": OWNER,
                "service_account": "mission-control",
                "stop_account": "billy-stop",
                "proxy_uids": [0],
                "stop_socket": str(self.base / "stop.sock"),
                "events_db": str(self.base / "state" / "events.db"),
                "auth_db": str(self.base / "state" / "auth.db"),
                "forbidden_paths": [str(self.base / "key.pem")],
            }
        )
        self.cfg = parse_app(text)
        self.events = Events(self.cfg.events_db)
        self.events.initialise()
        self.auth = Auth(self.cfg.auth_db, ORIGIN, OWNER)
        self.auth.initialise()
        self.stops = []
        self.service = Service(
            config=self.cfg,
            events=self.events,
            stop=lambda: self.stops.append(1) or True,
            auth=self.auth,
            token="form-token",
        )
        self.app = make_app(service=self.service)
        self.cookie = None

    def call(self, path, method="GET", body=None, login=OWNER, **headers):
        raw = (
            b""
            if body is None
            else (body if isinstance(body, bytes) else json.dumps(body).encode())
        )
        environ = {"PATH_INFO": path, "REQUEST_METHOD": method}
        setup_testing_defaults(environ)
        environ.update(
            {
                LOGIN_KEY: login,
                "wsgi.input": io.BytesIO(raw),
                "CONTENT_LENGTH": str(len(raw)),
                "HTTP_ORIGIN": ORIGIN,
                "HTTP_SEC_FETCH_SITE": "same-origin",
                "CONTENT_TYPE": "application/json",
            }
        )
        if self.cookie:
            environ["HTTP_COOKIE"] = f"{COOKIE}={self.cookie}"
        for key, value in headers.items():
            if value is None:
                environ.pop(key, None)
            else:
                environ[key] = value
        captured = {}

        def start_response(status, response_headers, exc_info=None):
            captured["status"], captured["headers"] = status, response_headers

        out = b"".join(self.app(environ, start_response))
        return captured["status"], captured["headers"], out

    def header(self, headers, name):
        return [v for n, v in headers if n == name]

    def enroll_and_sign_in(self, key: SoftKey):
        code = self.auth.new_enroll_code("iPhone")
        status, _, out = self.call("/enroll/begin", "POST", {"code": code})
        self.assertEqual(status, "200 OK")
        begin = json.loads(out)
        status, _, _ = self.call(
            "/enroll/complete",
            "POST",
            {"ticket": begin["ticket"], "credential": key.create(begin["options"])},
        )
        self.assertEqual(status, "200 OK")
        status, _, out = self.call("/signin/begin", "POST", {})
        begin = json.loads(out)
        status, headers, _ = self.call(
            "/signin/complete",
            "POST",
            {"ticket": begin["ticket"], "credential": key.get(begin["options"])},
        )
        self.assertEqual(status, "200 OK")
        (cookie,) = self.header(headers, "Set-Cookie")
        self.cookie = cookie.split(";")[0].split("=", 1)[1]
        return cookie

    def test_without_a_session_pages_go_to_sign_in_and_writes_are_refused(self):
        for path in ("/", "/tasks", "/settings", "/usage", "/tasks/example-site-901"):
            status, headers, _ = self.call(path)
            self.assertEqual(status, "303 See Other", path)
            self.assertEqual(self.header(headers, "Location"), ["/signin"])
        status, _, _ = self.call(
            "/stop", "POST", b"token=form-token", CONTENT_TYPE="application/x-www-form-urlencoded"
        )
        self.assertEqual(status, "403 Forbidden")
        self.assertEqual(self.stops, [])

    def test_the_sign_in_pages_need_tailscale_but_no_session(self):
        for path in ("/signin", "/enroll", "/static/passkey.js", "/static/app.css"):
            self.assertEqual(self.call(path)[0], "200 OK", path)
            self.assertEqual(self.call(path, login=OTHER)[0], "403 Forbidden", path)

    def test_only_the_sign_in_pages_may_run_a_script(self):
        for path in ("/signin", "/enroll"):
            _, headers, body = self.call(path)
            self.assertEqual(self.header(headers, "Content-Security-Policy"), [SIGNIN_CSP])
            self.assertIn(b'<script src="/static/passkey.js" defer></script>', body)
            self.assertNotRegex(body.decode(), r"<script(?![^>]*src=)")  # no inline script
            self.assertNotRegex(body.decode(), r" on[a-z]+=")  # no inline handlers
        self.enroll_and_sign_in(SoftKey(ORIGIN))
        for path in ("/", "/tasks", "/settings"):
            _, headers, body = self.call(path)
            (csp,) = self.header(headers, "Content-Security-Policy")
            self.assertEqual(csp, dict(SECURITY_HEADERS)["Content-Security-Policy"])
            self.assertNotIn("script-src", csp)
            self.assertNotIn(b"<script", body)

    def test_the_whole_flow(self):
        cookie = self.enroll_and_sign_in(SoftKey(ORIGIN))
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertEqual(self.call("/")[0], "200 OK")
        _, _, body = self.call("/settings")
        self.assertIn(b'action="/signout"', body)
        status, _, _ = self.call(
            "/stop", "POST", b"token=form-token", CONTENT_TYPE="application/x-www-form-urlencoded"
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(self.stops, [1])
        status, headers, _ = self.call(
            "/signout",
            "POST",
            b"token=form-token",
            CONTENT_TYPE="application/x-www-form-urlencoded",
        )
        self.assertEqual(status, "303 See Other")
        self.assertIn("Max-Age=0", self.header(headers, "Set-Cookie")[0])
        self.assertEqual(self.call("/")[0], "303 See Other")

    def test_a_valid_session_without_tailscale_is_refused(self):
        self.enroll_and_sign_in(SoftKey(ORIGIN))
        self.assertEqual(self.call("/", login=None)[0], "403 Forbidden")
        self.assertEqual(self.call("/", login=OTHER)[0], "403 Forbidden")

    def test_the_passkey_endpoints_refuse_cross_site_and_malformed_posts(self):
        cases = {
            "cross-origin": {"HTTP_ORIGIN": "https://evil.example"},
            "no fetch metadata": {"HTTP_SEC_FETCH_SITE": None},
            "same-site": {"HTTP_SEC_FETCH_SITE": "same-site"},
            "form type": {"CONTENT_TYPE": "application/x-www-form-urlencoded"},
            "oversized": {"CONTENT_LENGTH": "16385"},
        }
        self.service.signin_rate.limit = 1000  # this test sends many requests on purpose
        for path in ("/enroll/begin", "/enroll/complete", "/signin/begin", "/signin/complete"):
            for name, headers in cases.items():
                status, _, _ = self.call(path, "POST", {}, **headers)
                self.assertEqual(status, "403 Forbidden", (path, name))
            self.assertEqual(self.call(path, "POST", b"[1]")[0], "403 Forbidden")
            self.assertEqual(self.call(path, "POST", b"{nope")[0], "403 Forbidden")
            self.assertEqual(self.call(path, "GET")[0], "405 Method Not Allowed")

    def test_failures_are_generic_to_the_browser_and_specific_in_the_log(self):
        status, _, out = self.call("/enroll/begin", "POST", {"code": "AAAAA-AAAAA"})
        self.assertEqual((status, json.loads(out)), ("400 Bad Request", {"ok": False}))
        db = sqlite3.connect(self.cfg.events_db)
        self.addCleanup(db.close)
        last = json.loads(db.execute("SELECT record FROM events ORDER BY id DESC").fetchone()[0])
        self.assertEqual((last["kind"], last["result"]), ("enroll-begin", "failed:code"))

    def test_the_log_never_holds_a_code_challenge_or_cookie(self):
        code = self.auth.new_enroll_code("iPhone")
        self.cookie = None
        key = SoftKey(ORIGIN)
        status, _, out = self.call("/enroll/begin", "POST", {"code": code})
        challenge = json.loads(out)["options"]["challenge"]
        self.enroll_and_sign_in(key)
        log = Path(self.cfg.events_db).read_bytes()
        for secret in (code, code.replace("-", ""), challenge, self.cookie):
            self.assertNotIn(secret.encode(), log)

    def test_sign_in_attempts_are_rate_limited(self):
        self.service.signin_rate.limit = 3
        statuses = [self.call("/signin/begin", "POST", {})[0] for _ in range(5)]
        self.assertEqual(statuses[-1], "429 Too Many Requests")

    def test_an_expired_session_redirects_and_clears_the_cookie(self):
        self.enroll_and_sign_in(SoftKey(ORIGIN))
        self.auth.clock = lambda: 10**12
        status, headers, _ = self.call("/")
        self.assertEqual(status, "303 See Other")
        self.assertIn("Max-Age=0", self.header(headers, "Set-Cookie")[0])


# ---------------------------------------------------------------- the server shell


class ShellCommands(unittest.TestCase):
    def setUp(self):
        base = tmp(self)
        (base / "state").mkdir()
        self.cfg = parse_app(
            json.dumps(
                {
                    "origin": ORIGIN,
                    "owner_login": OWNER,
                    "service_account": "mission-control",
                    "stop_account": "billy-stop",
                    "proxy_uids": [0],
                    "stop_socket": str(base / "stop.sock"),
                    "events_db": str(base / "state" / "events.db"),
                    "auth_db": str(base / "state" / "auth.db"),
                    "forbidden_paths": [str(base / "key.pem")],
                }
            )
        )
        Events(self.cfg.events_db).initialise()

    def run_cmd(self, action, credential=None, label="iPhone", answer=""):
        args = argparse.Namespace(action=action, credential=credential, label=label)
        out = io.StringIO()
        from contextlib import redirect_stderr, redirect_stdout

        with redirect_stdout(out), redirect_stderr(out):
            code = passkey_main(args, self.cfg, confirm=lambda prompt: answer)
        return code, out.getvalue()

    def test_enroll_prints_a_code_and_list_shows_passkeys(self):
        code, out = self.run_cmd("enroll")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"One-time code: [A-Z2-9]{5}-[A-Z2-9]{5}")
        code, out = self.run_cmd("list")
        self.assertIn("0 passkey(s); at most 2.", out)

    def test_reset_and_revoking_the_last_need_typed_confirmation(self):
        auth = Auth(self.cfg.auth_db, ORIGIN, OWNER)
        auth.initialise()
        code = auth.new_enroll_code("iPhone")
        begin = auth.enroll_begin(code, OWNER)
        cid = auth.enroll_complete(begin["ticket"], SoftKey(ORIGIN).create(begin["options"]), OWNER)
        self.assertEqual(self.run_cmd("revoke", cid, answer="no")[0], 2)
        self.assertEqual(len(auth.credentials()), 1)
        self.assertEqual(self.run_cmd("reset", answer="yes")[0], 2)
        self.assertEqual(len(auth.credentials()), 1)
        self.assertEqual(self.run_cmd("revoke", cid, answer="revoke")[0], 0)
        self.assertEqual(auth.credentials(), [])
        self.assertEqual(self.run_cmd("reset", answer="reset")[0], 0)

    def test_revoke_needs_a_real_id(self):
        self.assertEqual(self.run_cmd("revoke")[0], 2)
        self.assertEqual(self.run_cmd("revoke", "nope")[0], 2)

    def test_actions_are_logged(self):
        self.run_cmd("enroll")
        self.run_cmd("reset", answer="reset")
        db = sqlite3.connect(self.cfg.events_db)
        self.addCleanup(db.close)
        kinds = [json.loads(r)["kind"] for (r,) in db.execute("SELECT record FROM events")]
        self.assertEqual(kinds, ["passkey-code", "passkey-reset"])


# ---------------------------------------------------------------- policies


class Policies(unittest.TestCase):
    def test_only_the_auth_package_imports_fido2(self):
        for path in sorted((ROOT / "mission_control").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            modules = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            modules |= {
                n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module
            }
            uses = {m for m in modules if m == "fido2" or m.startswith("fido2.")}
            if uses:
                self.assertEqual(
                    path.relative_to(ROOT).as_posix(), "mission_control/auth/passkeys.py"
                )

    def test_the_rest_of_the_app_loads_without_fido2(self):
        code = (
            "import sys; sys.modules['fido2'] = None;"
            "import mission_control.app, mission_control.stopper, mission_control.service;"
            "print('ok')"
        )
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True
        )
        self.assertEqual(result.stdout.strip(), "ok", result.stderr)

    def test_requirements_are_pinned_by_version_and_hash(self):
        text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        pins = re.findall(r"^([A-Za-z0-9._-]+)==(\S+) \\$", text, re.M)
        self.assertEqual([name for name, _ in pins], ["fido2", "cryptography", "cffi", "pycparser"])
        for name, _ in pins:
            block = text.split(f"{name}==", 1)[1].split("\n\n")[0]
            self.assertRegex(block, r"--hash=sha256:[0-9a-f]{64}", name)
        self.assertNotRegex(text, r"(?m)^[A-Za-z0-9._-]+(>=|~=|<)")

    def test_the_script_writes_text_only_and_talks_only_to_the_app(self):
        js = (ROOT / "mission_control" / "static" / "passkey.js").read_text(encoding="utf-8")
        for banned in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "eval(",
            "Function(",
            "document.write",
            "localStorage",
            "sessionStorage",
            "http://",
            "https://",
        ):
            self.assertNotIn(banned, js, banned)
        self.assertEqual(
            sorted(set(re.findall(r'post\("([^"]+)"', js))),
            ["/enroll/begin", "/enroll/complete", "/signin/begin", "/signin/complete"],
        )

    def test_the_rules_are_the_issues(self):
        self.assertEqual(auth_module.MAX_CREDENTIALS, 2)
        self.assertEqual(CODE_TTL, 600)
        self.assertEqual(CHALLENGE_TTL, 120)
        self.assertEqual(IDLE_TIMEOUT, 1800)
        self.assertEqual(ABSOLUTE_TIMEOUT, 43200)
        self.assertTrue(COOKIE.startswith("__Host-"))


class CodexReviewOf9bad79d(Fixture):
    """Codex's review of 9bad79d (blocking): a revoke or reset between a sign-in's reading of
    the passkeys and its creating the session left a session for a removed passkey."""

    def setUp(self):
        super().setUp()
        self.key = SoftKey(ORIGIN)
        self.cid = self.enroll(self.key)

    def race(self, shell_action):
        """Run `shell_action` (from another connection) while a sign-in is inside its check."""
        import threading

        real = auth_module._passkeys().authenticate
        started, done = threading.Event(), []

        def slow_authenticate(*args, **kwargs):
            started.set()
            result = real(*args, **kwargs)
            threading.Event().wait(0.3)  # the window Codex found
            return result

        other = Auth(self.base / "auth.db", ORIGIN, OWNER, clock=self.clock)

        def shell():
            started.wait(5)
            done.append(shell_action(other))

        thread = threading.Thread(target=shell)
        thread.start()
        begin = self.auth.signin_begin(OWNER)
        response = self.key.get(begin["options"])
        from unittest import mock

        with mock.patch.object(auth_module._passkeys(), "authenticate", slow_authenticate):
            token = self.auth.signin_complete(begin["ticket"], response, OWNER)
        thread.join(5)
        self.assertEqual(len(done), 1, "the shell action never finished")
        return token

    def test_a_revoke_during_sign_in_leaves_no_session(self):
        token = self.race(lambda other: other.revoke(self.cid))
        self.assertEqual(self.auth.credentials(), [])
        self.assertEqual(self.auth.check_session(token, OWNER), "no-session")

    def test_a_reset_during_sign_in_leaves_no_session(self):
        token = self.race(lambda other: other.reset())
        self.assertEqual(self.auth.credentials(), [])
        self.assertEqual(self.auth.check_session(token, OWNER), "no-session")

    def test_a_revoke_before_sign_in_means_no_sign_in(self):
        begin = self.auth.signin_begin(OWNER)
        response = self.key.get(begin["options"])
        self.auth.revoke(self.cid)
        self.refused("rejected", self.auth.signin_complete, begin["ticket"], response, OWNER)

    def test_a_failed_sign_in_still_spends_its_ticket(self):
        begin = self.auth.signin_begin(OWNER)
        bad = self.key.get(begin["options"], tamper=True)
        self.refused("rejected", self.auth.signin_complete, begin["ticket"], bad, OWNER)
        good = self.key.get(begin["options"])
        self.refused("ticket-reused", self.auth.signin_complete, begin["ticket"], good, OWNER)


if __name__ == "__main__":
    unittest.main()
