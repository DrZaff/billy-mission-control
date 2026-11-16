"""Phase A4a: the service, the stop helper, the events log and the start-up checks.

No network: everything runs on Unix sockets and files in a temporary folder.
"""

from __future__ import annotations

import io
import json
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from wsgiref.util import setup_testing_defaults

from mission_control import checks, stopper
from mission_control.app import LOGIN_KEY, RateLimit, Service, make_app
from mission_control.config import ConfigError, parse_app, parse_stopper
from mission_control.events import Events
from mission_control.service import UnixWSGIServer, systemd_socket, trusted_login

ROOT = Path(__file__).resolve().parent.parent
UID = os.getuid()
OWNER = "owner@example.com"
ORIGIN = "https://mission-control.example.invalid"


def tmpdir(case: unittest.TestCase) -> Path:
    path = Path(tempfile.mkdtemp())
    os.chmod(path, 0o755)
    case.addCleanup(subprocess.run, ["rm", "-rf", str(path)], check=False)
    return path


def app_config_text(base: Path, **over) -> str:
    data = {
        "origin": ORIGIN,
        "owner_login": OWNER,
        "service_account": "mission-control",
        "proxy_uids": [0],
        "stop_socket": str(base / "run" / "stop.sock"),
        "events_db": str(base / "state" / "events.db"),
        "forbidden_paths": [str(base / "key.pem")],
    }
    data.update(over)
    return json.dumps(data)


# ---------------------------------------------------------------- config


class Config(unittest.TestCase):
    def test_the_committed_examples_parse(self):
        app = parse_app((ROOT / "config.example.json").read_text(encoding="utf-8"))
        stop = parse_stopper((ROOT / "stopper.example.json").read_text(encoding="utf-8"))
        self.assertEqual(app.origin, ORIGIN)
        self.assertEqual(stop.account, "billy-stop")
        self.assertEqual(stop.client_account, app.service_account)

    def test_bad_configs_are_refused(self):
        base = Path("/x")
        good = json.loads(app_config_text(base))
        bad = [
            "not json",
            json.dumps({k: v for k, v in good.items() if k != "origin"}),
            json.dumps({**good, "extra": 1}),
            json.dumps({**good, "origin": "http://insecure.example"}),
            json.dumps({**good, "origin": "https://evil.example/path"}),
            json.dumps({**good, "owner_login": "a b"}),
            json.dumps({**good, "owner_login": "<script>"}),
            json.dumps({**good, "service_account": "root"}),
            json.dumps({**good, "proxy_uids": []}),
            json.dumps({**good, "proxy_uids": [True]}),
            json.dumps({**good, "proxy_uids": [-1]}),
            json.dumps({**good, "events_db": "relative/events.db"}),
            json.dumps({**good, "events_db": "/x/../y.db"}),
            json.dumps({**good, "forbidden_paths": []}),
        ]
        for text in bad:
            with self.assertRaises(ConfigError, msg=text[:80]):
                parse_app(text)

    def test_the_stopper_and_the_app_must_be_different_accounts(self):
        text = json.dumps(
            {
                "account": "mission-control",
                "control_dir": "/x/control",
                "client_account": "mission-control",
                "forbidden_paths": ["/x/key"],
            }
        )
        with self.assertRaises(ConfigError):
            parse_stopper(text)


# ---------------------------------------------------------------- start-up checks


class StartupChecks(unittest.TestCase):
    def setUp(self):
        self.base = tmpdir(self)

    def test_root_and_the_wrong_account_are_refused(self):
        self.assertFalse(checks.not_root(0).ok)
        self.assertTrue(checks.not_root(1000).ok)
        self.assertFalse(checks.running_as("mission-control", 1000, lambda uid: "agent").ok)
        self.assertTrue(
            checks.running_as("mission-control", 1000, lambda uid: "mission-control").ok
        )

    def test_a_private_config(self):
        path = self.base / "config.json"
        path.write_text("{}")
        os.chmod(path, 0o600)
        self.assertTrue(checks.private_file(path, UID).ok)
        for mode in (0o644, 0o604, 0o620):
            os.chmod(path, mode)
            self.assertFalse(checks.private_file(path, UID).ok, oct(mode))
        os.chmod(path, 0o600)
        self.assertFalse(checks.private_file(path, UID + 1).ok)
        link = self.base / "link.json"
        link.symlink_to(path)
        self.assertFalse(checks.private_file(link, UID).ok)
        self.assertFalse(checks.private_file(self.base / "missing.json", UID).ok)

    def test_an_own_folder(self):
        folder = self.base / "state"
        folder.mkdir(mode=0o700)
        self.assertTrue(checks.own_folder(folder, UID, "state").ok)
        os.chmod(folder, 0o770)
        self.assertFalse(checks.own_folder(folder, UID, "state").ok)
        os.chmod(folder, 0o700)
        self.assertFalse(checks.own_folder(folder, UID + 1, "state").ok)
        link = self.base / "state-link"
        link.symlink_to(folder)
        self.assertFalse(checks.own_folder(link, UID, "state").ok)

    def test_folders_above_must_be_protected(self):
        deep = self.base / "a" / "b"
        deep.mkdir(parents=True)
        target = deep / "file"
        trusted = {0, UID}
        self.assertTrue(checks.protected_above(target, trusted).ok)
        os.chmod(self.base / "a", 0o777)
        self.assertFalse(checks.protected_above(target, trusted).ok)
        os.chmod(self.base / "a", 0o1777)  # sticky: others can't replace our entries
        self.assertTrue(checks.protected_above(target, trusted).ok)
        os.chmod(self.base / "a", 0o755)
        self.assertFalse(checks.protected_above(target, {123456}).ok)
        (self.base / "link").symlink_to(self.base / "a")
        self.assertFalse(checks.protected_above(self.base / "link" / "b" / "file", trusted).ok)

    def test_forbidden_paths_must_be_unreadable_and_real(self):
        def refused(path):
            raise PermissionError(path)

        def missing(path):
            raise FileNotFoundError(path)

        key = self.base / "refused.pem"
        key.write_text("x")
        self.assertTrue(checks.cannot_read(key, refused).ok)
        self.assertFalse(checks.cannot_read(Path("/x/key"), missing).ok)
        readable = self.base / "key.pem"
        readable.write_text("not a key")
        result = checks.cannot_read(readable)
        self.assertFalse(result.ok)
        self.assertIn("READABLE", result.detail)

    def layout(self):
        (self.base / "state").mkdir(mode=0o700)
        (self.base / "run").mkdir(mode=0o755)
        (self.base / "key.pem").write_text("x")
        cfg_path = self.base / "config.json"
        cfg_path.write_text(app_config_text(self.base))
        os.chmod(cfg_path, 0o600)
        return parse_app(cfg_path.read_text()), cfg_path

    def test_a_correct_layout_passes_every_check_but_root(self):
        cfg, path = self.layout()

        def refused(p):
            raise PermissionError(p)

        results = checks.app_checks(
            cfg, path, uid=UID, account_of=lambda u: "mission-control", opener=refused
        )
        for c in results:
            if c.name == "not root":
                self.assertEqual(c.ok, UID != 0)
            else:
                self.assertTrue(c.ok, c)

    def test_a_readable_key_fails_the_app_checks(self):
        cfg, path = self.layout()
        results = checks.app_checks(cfg, path, uid=UID, account_of=lambda u: "mission-control")
        self.assertTrue(any("READABLE" in c.detail for c in checks.failures(results)))
        self.assertIn("FAIL: cannot read", checks.report(results))


# ---------------------------------------------------------------- the stop helper


class StopHelper(unittest.TestCase):
    def setUp(self):
        self.base = tmpdir(self)
        self.control = self.base / "control"
        self.control.mkdir(mode=0o755)
        self.marker = self.control / stopper.MARKER

    def test_sets_a_durable_marker_and_is_idempotent(self):
        with mock.patch.object(stopper.os, "fsync", wraps=os.fsync) as fsync:
            self.assertTrue(stopper.set_marker(self.control, UID))
        self.assertEqual(fsync.call_count, 2)  # the file, then its folder
        info = os.lstat(self.marker)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
        self.assertEqual(info.st_uid, UID)
        self.assertTrue(stopper.set_marker(self.control, UID))  # already stopped: still true

    def test_refuses_a_symlink_or_folder_in_the_markers_place(self):
        target = self.base / "elsewhere"
        target.write_text("untouched")
        self.marker.symlink_to(target)
        self.assertFalse(stopper.set_marker(self.control, UID))
        self.assertEqual(target.read_text(), "untouched")
        self.marker.unlink()
        self.marker.mkdir()
        self.assertFalse(stopper.set_marker(self.control, UID))

    def test_refuses_a_folder_it_does_not_own_or_others_can_write(self):
        self.assertFalse(stopper.set_marker(self.control, UID + 1))
        os.chmod(self.control, 0o777)
        self.assertFalse(stopper.set_marker(self.control, UID))
        os.chmod(self.control, 0o755)
        link = self.base / "control-link"
        link.symlink_to(self.control)
        self.assertFalse(stopper.set_marker(link, UID))
        self.assertFalse(self.marker.exists())

    def converse(self, request: bytes, client_uid: int) -> tuple[str, bytes]:
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with server, client:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            result = stopper.handle(server, self.control, UID, client_uid)
            client.settimeout(2)
            return result, client.recv(64)

    def test_only_the_web_apps_account_may_ask(self):
        result, reply = self.converse(stopper.REQUEST, client_uid=UID + 1)
        self.assertEqual(reply, stopper.REFUSED)
        self.assertIn("wrong account", result)
        self.assertFalse(self.marker.exists())

    def test_only_the_exact_request_is_accepted(self):
        for request in (b"STOP", b"stop\n", b"STOP /tmp/x\n", b"RESUME\n", b"STOP\nSTOP\n"):
            result, reply = self.converse(request, client_uid=UID)
            self.assertEqual(reply, stopper.REFUSED, request)
            self.assertFalse(self.marker.exists(), request)

    def test_a_stop_is_confirmed_only_after_the_marker_is_on_disk(self):
        order = []
        conn = mock.Mock()
        conn.recv.side_effect = [stopper.REQUEST]
        conn.sendall.side_effect = lambda data: order.append(("reply", data))
        real_fsync = os.fsync
        with (
            mock.patch.object(stopper, "peer_uid", return_value=UID),
            mock.patch.object(
                stopper.os,
                "fsync",
                side_effect=lambda fd: (order.append(("fsync", None)), real_fsync(fd)),
            ),
        ):
            self.assertEqual(stopper.handle(conn, self.control, UID, UID), "stopped")
        self.assertEqual(order, [("fsync", None), ("fsync", None), ("reply", stopper.STOPPED)])

    def test_a_failed_marker_is_reported_as_failed(self):
        os.chmod(self.control, 0o777)
        result, reply = self.converse(stopper.REQUEST, client_uid=UID)
        self.assertEqual(reply, stopper.FAILED)
        self.assertIn("error", result)

    def test_end_to_end_over_a_real_socket(self):
        path = self.base / "stop.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        self.addCleanup(listener.close)
        lines = []
        thread = threading.Thread(
            target=stopper.serve,
            args=(listener, self.control, UID, UID),
            kwargs={"log": lines.append, "once": True},
        )
        thread.start()
        self.assertTrue(stopper.request_stop(path))
        thread.join(5)
        self.assertTrue(self.marker.exists())
        self.assertEqual(lines, ["stop helper: stopped"])

    def test_request_stop_is_false_when_the_helper_is_unreachable(self):
        self.assertFalse(stopper.request_stop(self.base / "missing.sock", timeout=0.5))


# ---------------------------------------------------------------- events


class EventsLog(unittest.TestCase):
    def setUp(self):
        self.base = tmpdir(self)
        self.events = Events(self.base / "events.db", clock=lambda: "2026-11-16T10:00:00.000+00:00")
        self.events.initialise()

    def rows(self):
        db = sqlite3.connect(self.base / "events.db")
        try:
            return [
                (seq, json.loads(r))
                for seq, r in db.execute("SELECT seq, record FROM events ORDER BY id")
            ]
        finally:
            db.close()

    def test_private_file_and_idempotent_schema(self):
        self.events.initialise()
        self.assertEqual(stat.S_IMODE(os.stat(self.base / "events.db").st_mode), 0o600)

    def test_records_are_clean_capped_and_ordered(self):
        self.assertTrue(
            self.events.append(
                "request",
                method="GET",
                path="/tasks/\x1b[31m" + "x" * 500,
                status=200,
                login="owner\n@example.com",
                cookie="secret",  # not a known field: never stored
                token="also secret",
            )
        )
        self.events.append("stop", result="stopped")
        (seq1, first), (seq2, second) = self.rows()
        self.assertEqual((seq1, seq2), (1, 2))
        self.assertEqual(set(first), {"kind", "method", "path", "status", "login"})
        self.assertNotIn("\x1b", first["path"])
        self.assertLessEqual(len(first["path"]), 200)
        self.assertEqual(first["login"], "owner?@example.com")
        self.assertEqual(second, {"kind": "stop", "result": "stopped"})

    def test_rows_cannot_be_changed_or_deleted(self):
        self.events.append("request", status=200)
        db = sqlite3.connect(self.base / "events.db")
        self.addCleanup(db.close)
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("UPDATE events SET record = '{}'")
        with self.assertRaises(sqlite3.DatabaseError):
            db.execute("DELETE FROM events")

    def test_an_unwritable_log_returns_false_never_raises(self):
        broken = Events(self.base / "no-such-folder" / "events.db")
        self.assertFalse(broken.append("request", status=200))

    def test_export_writes_json_lines_and_never_overwrites(self):
        self.events.append("request", method="GET", path="/", status=200, login=OWNER)
        out = self.base / "export.jsonl"
        self.assertEqual(self.events.export("2026-11-16", out), 1)
        line = json.loads(out.read_text().strip())
        self.assertEqual((line["kind"], line["seq"], line["status"]), ("request", 1, 200))
        self.assertEqual(self.events.export("2026-11-17", self.base / "later.jsonl"), 0)
        with self.assertRaises(FileExistsError):
            self.events.export("2026-11-16", out)
        with self.assertRaises(ValueError):
            self.events.export("yesterday", self.base / "bad.jsonl")


# ---------------------------------------------------------------- the app in service mode


class ServiceMode(unittest.TestCase):
    def setUp(self):
        self.base = tmpdir(self)
        self.cfg = parse_app(app_config_text(self.base))
        self.events = Events(self.base / "events.db")
        self.events.initialise()
        self.stops = []
        self.stop_result = True
        self.service = Service(
            config=self.cfg, events=self.events, stop=self.fake_stop, token="test-token"
        )
        self.app = make_app(service=self.service)

    def fake_stop(self) -> bool:
        self.stops.append(True)
        return self.stop_result

    def call(self, path="/", method="GET", login=OWNER, body=b"", **headers):
        environ = {"PATH_INFO": path, "REQUEST_METHOD": method}
        setup_testing_defaults(environ)
        environ[LOGIN_KEY] = login
        environ["wsgi.input"] = io.BytesIO(body)
        environ.update(headers)
        captured = {}

        def start_response(status, response_headers, exc_info=None):
            captured["status"], captured["headers"] = status, dict(response_headers)

        out = b"".join(self.app(environ, start_response)).decode("utf-8")
        return captured["status"], captured["headers"], out

    def stop_post(self, token="test-token", **over):
        body = f"token={token}".encode()
        headers = {
            "HTTP_ORIGIN": ORIGIN,
            "HTTP_SEC_FETCH_SITE": "same-origin",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(body)),
        }
        headers.update(over)
        for key in [k for k, v in headers.items() if v is None]:
            del headers[key]
        login = headers.pop("login", OWNER)
        return self.call("/stop", "POST", login=login, body=body, **headers)

    def logged(self):
        db = sqlite3.connect(self.base / "events.db")
        try:
            return [json.loads(r) for (r,) in db.execute("SELECT record FROM events ORDER BY id")]
        finally:
            db.close()

    def test_every_route_needs_the_owners_exact_login(self):
        for login in (None, "", "someone@example.com", OWNER.upper(), OWNER + " ", "x" * 300):
            for path in ("/", "/tasks", "/settings", "/static/app.css", "/healthz", "/nope"):
                status, _, body = self.call(path, login=login)
                self.assertEqual(status, "403 Forbidden", (login, path))
                self.assertEqual(body, "Not available.\n")
        self.assertEqual(self.logged()[0]["login"], "(none)")

    def test_the_owner_sees_the_pages_and_no_health_route(self):
        for path in ("/", "/tasks", "/usage", "/settings", "/static/app.css"):
            self.assertEqual(self.call(path)[0], "200 OK", path)
        self.assertEqual(self.call("/healthz")[0], "404 Not Found")
        record = self.logged()[0]
        self.assertEqual(
            (record["kind"], record["status"], record["login"]), ("request", 200, OWNER)
        )

    def test_settings_carries_the_stop_form_and_says_what_it_stops(self):
        _, headers, body = self.call("/settings")
        self.assertIn('<form method="post" action="/stop">', body)
        self.assertIn('name="token" value="test-token"', body)
        self.assertIn("Stops new Billy review and publish steps.", body)
        self.assertIn("not affected", body)
        self.assertIn("Only the owner clears it, on the server.", body)
        self.assertIn("form-action 'self'", headers["Content-Security-Policy"])

    def test_a_valid_stop(self):
        status, _, body = self.stop_post()
        self.assertEqual(status, "200 OK")
        self.assertIn("Billy is stopped", body)
        self.assertEqual(len(self.stops), 1)
        self.assertEqual(self.logged()[-1]["result"], "stopped")

    def test_every_check_on_the_stop_post_refuses(self):
        cases = {
            "cross-origin": {"HTTP_ORIGIN": "https://evil.example"},
            "no origin": {"HTTP_ORIGIN": None},
            "origin with a path": {"HTTP_ORIGIN": ORIGIN + "/"},
            "no fetch metadata": {"HTTP_SEC_FETCH_SITE": None},
            "same-site": {"HTTP_SEC_FETCH_SITE": "same-site"},
            "cross-site": {"HTTP_SEC_FETCH_SITE": "cross-site"},
            "wrong content type": {"CONTENT_TYPE": "text/plain"},
            "multipart": {"CONTENT_TYPE": "multipart/form-data"},
            "no length": {"CONTENT_LENGTH": None},
            "oversized": {"CONTENT_LENGTH": "513"},
            "bad length": {"CONTENT_LENGTH": "ten"},
        }
        for name, over in cases.items():
            status, _, _ = self.stop_post(**over)
            self.assertEqual(status, "403 Forbidden", name)
        for token in ("wrong", "", "test-token&token=test-token"):
            self.assertEqual(self.stop_post(token=token)[0], "403 Forbidden", token)
        self.assertEqual(self.stop_post(login="someone@example.com")[0], "403 Forbidden")
        self.assertEqual(self.stops, [])
        refusals = [r["result"] for r in self.logged() if r.get("kind") == "stop"]
        self.assertTrue(all(r.startswith("refused:") for r in refusals))

    def test_a_token_from_before_a_restart_is_refused(self):
        restarted = Service(config=self.cfg, events=self.events, stop=self.fake_stop)
        self.assertNotEqual(restarted.token, "test-token")
        self.app = make_app(service=restarted)
        status, _, body = self.stop_post()
        self.assertEqual(status, "403 Forbidden")
        self.assertIn("Reload", body)
        self.assertEqual(self.stops, [])

    def test_other_methods_on_stop_and_writes_elsewhere(self):
        status, headers, _ = self.call("/stop", "GET")
        self.assertEqual((status, headers["Allow"]), ("405 Method Not Allowed", "POST"))
        for method in ("POST", "PUT", "DELETE"):
            self.assertEqual(self.call("/settings", method)[0], "405 Method Not Allowed")
        self.assertEqual(self.stops, [])

    def test_a_failed_stop_is_never_shown_as_success(self):
        self.stop_result = False
        status, _, body = self.stop_post()
        self.assertEqual(status, "503 Service Unavailable")
        self.assertIn("could NOT be confirmed", body)
        self.assertNotIn("Billy is stopped<", body)
        self.assertEqual(self.logged()[-1]["result"], "failed")

    def test_the_stop_works_when_the_log_is_down(self):
        self.service.events = Events(self.base / "no-such-folder" / "events.db")
        status, _, body = self.stop_post()
        self.assertEqual(status, "200 OK")
        self.assertEqual(len(self.stops), 1)
        self.assertIn("Logging degraded", body)
        self.assertIn("Billy is stopped", body)
        status, _, body = self.call("/")
        self.assertEqual(status, "200 OK")
        self.assertIn("Logging degraded", body)

    def test_too_many_requests(self):
        now = [0.0]
        self.service.rate = RateLimit(limit=3, window=60, clock=lambda: now[0])
        for _ in range(3):
            self.assertEqual(self.call("/")[0], "200 OK")
        self.assertEqual(self.call("/")[0], "429 Too Many Requests")
        now[0] = 61
        self.assertEqual(self.call("/")[0], "200 OK")

    def test_development_mode_is_unchanged(self):
        dev = make_app()
        environ = {"PATH_INFO": "/stop", "REQUEST_METHOD": "POST"}
        setup_testing_defaults(environ)
        captured = {}
        dev(environ, lambda s, h, e=None: captured.update(status=s))
        self.assertEqual(captured["status"], "405 Method Not Allowed")


# ---------------------------------------------------------------- the server on a Unix socket


class UnixServer(unittest.TestCase):
    def setUp(self):
        self.base = tmpdir(self)
        self.cfg = parse_app(app_config_text(self.base))
        self.events = Events(self.base / "events.db")
        self.events.initialise()
        self.refused = []
        self.service = Service(config=self.cfg, events=self.events, stop=lambda: True)

    def serve(self, proxy_uids, raw: bytes) -> bytes:
        path = self.base / "app.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        server = UnixWSGIServer(
            listener, make_app(service=self.service), proxy_uids, self.refused.append
        )
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(path))
            client.sendall(raw)
            data = b""
            try:
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except ConnectionResetError:
                pass  # a refused connection is closed without a reply
        thread.join(5)
        path.unlink()
        return data

    def request(self, *headers: str) -> bytes:
        lines = ["GET / HTTP/1.1", "Host: mission-control", "Connection: close", *headers]
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def status(self, data: bytes) -> str:
        return data.split(b"\r\n", 1)[0].decode()

    def test_the_owner_through_the_proxy(self):
        data = self.serve({UID}, self.request(f"Tailscale-User-Login: {OWNER}"))
        self.assertIn("200", self.status(data))

    def test_another_local_account_cannot_connect(self):
        data = self.serve({UID + 1}, self.request(f"Tailscale-User-Login: {OWNER}"))
        self.assertEqual(data, b"")
        self.assertEqual(self.refused, [UID])

    def test_forged_or_doubled_logins_get_no_identity(self):
        for headers in (
            (f"Tailscale_User_Login: {OWNER}",),
            (f"tailscale_user_login: {OWNER}",),
            (f"Tailscale_User_Login: {OWNER}", "Tailscale-User-Login: someone@example.com"),
            ("Tailscale-User-Login: someone@example.com", f"Tailscale_User_Login: {OWNER}"),
            (f"Tailscale-User-Login: {OWNER}", f"Tailscale-User-Login: {OWNER}"),
            ("Tailscale-User-Login: ",),
            (),
        ):
            data = self.serve({UID}, self.request(*headers))
            self.assertIn("403", self.status(data), headers)

    def test_too_many_headers(self):
        many = [f"X-Filler-{i}: x" for i in range(45)]
        data = self.serve({UID}, self.request(f"Tailscale-User-Login: {OWNER}", *many))
        self.assertIn("431", self.status(data))

    def test_trusted_login_reads_one_exact_header(self):
        from email.message import Message

        def headers(*pairs):
            m = Message()
            for k, v in pairs:
                m[k] = v
            return m

        self.assertEqual(trusted_login(headers(("Tailscale-User-Login", OWNER))), OWNER)
        self.assertEqual(trusted_login(headers(("tailscale-user-login", OWNER))), OWNER)
        self.assertIsNone(trusted_login(headers(("Tailscale-User-Name", OWNER))))
        self.assertIsNone(
            trusted_login(headers(("Tailscale-User-Login", OWNER), ("Tailscale_User_Login", "x")))
        )


class SocketActivation(unittest.TestCase):
    def test_refuses_without_systemd(self):
        for environ in ({}, {"LISTEN_PID": "1", "LISTEN_FDS": "1"}, {"LISTEN_FDS": "2"}):
            with self.assertRaises(RuntimeError):
                systemd_socket(dict(environ, LISTEN_PID=environ.get("LISTEN_PID", "1")), pid=99)

    def test_accepts_the_unix_socket_systemd_passes(self):
        code = (
            f"import os, socket, sys; sys.path.insert(0, {str(ROOT)!r});"
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); os.dup2(s.fileno(), 3);"
            "os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS='1');"
            "from mission_control.service import systemd_socket;"
            "print(systemd_socket().family == socket.AF_UNIX)"
        )
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "True", result.stderr)


# ---------------------------------------------------------------- the command line


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "mission_control", *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            env={k: v for k, v in os.environ.items() if not k.startswith("LISTEN_")},
        )

    def test_selfcheck_reports_failures_and_exits_1(self):
        base = tmpdir(self)
        path = base / "config.json"
        path.write_text(app_config_text(base))
        os.chmod(path, 0o644)  # readable by others: must fail
        result = self.run_cli("selfcheck", "app", "--config", str(path))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("FAIL: config config.json", result.stdout)
        self.assertIn("checks passed", result.stdout)

    def test_serve_and_stopper_never_start_when_checks_fail(self):
        base = tmpdir(self)
        path = base / "config.json"
        path.write_text(app_config_text(base))
        os.chmod(path, 0o600)
        result = self.run_cli("serve", "--config", str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("STOP:", result.stderr)
        self.assertNotIn("ready", result.stdout)

    def test_a_symlinked_config_is_refused(self):
        base = tmpdir(self)
        real = base / "real.json"
        real.write_text(app_config_text(base))
        link = base / "config.json"
        link.symlink_to(real)
        result = self.run_cli("selfcheck", "app", "--config", str(link))
        self.assertEqual(result.returncode, 2)
        self.assertIn("could not be read", result.stderr)

    def test_the_development_server_is_still_the_default(self):
        result = self.run_cli("--host", "0.0.0.0")  # noqa: S104 - must be refused
        self.assertEqual(result.returncode, 2)
        self.assertIn("loopback", result.stderr)


class CodexReviewOfAfb72d5(unittest.TestCase):
    """Codex's review of afb72d5: an existing events database must be private (blocking); a
    group-readable config is not private; an existing marker is written to disk again."""

    def setUp(self):
        self.base = tmpdir(self)

    def test_an_existing_database_that_others_can_read_is_refused(self):
        db = self.base / "events.db"
        for mode in (0o644, 0o640, 0o604, 0o660, 0o606):
            db.write_text("")
            os.chmod(db, mode)
            with self.assertRaises(PermissionError, msg=oct(mode)):
                Events(db).initialise()
            self.assertFalse(checks.private_database(db, UID).ok, oct(mode))
            db.unlink()

    def test_a_symlinked_database_is_refused(self):
        real = self.base / "real.db"
        real.write_text("")
        os.chmod(real, 0o600)
        link = self.base / "events.db"
        link.symlink_to(real)
        with self.assertRaises(OSError):
            Events(link).initialise()
        self.assertFalse(checks.private_database(link, UID).ok)

    def test_sqlite_side_files_must_be_private_too(self):
        db = self.base / "events.db"
        Events(db).initialise()
        self.assertTrue(checks.private_database(db, UID).ok)
        wal = self.base / "events.db-wal"
        wal.write_text("")
        os.chmod(wal, 0o644)
        self.assertFalse(checks.private_database(db, UID).ok)
        os.chmod(wal, 0o600)
        self.assertTrue(checks.private_database(db, UID).ok)
        self.assertFalse(checks.private_database(db, UID + 1).ok)

    def test_a_missing_database_is_fine_and_is_created_private(self):
        db = self.base / "events.db"
        self.assertTrue(checks.private_database(db, UID).ok)
        Events(db).initialise()
        self.assertEqual(stat.S_IMODE(os.stat(db).st_mode), 0o600)

    def test_the_app_checks_include_the_database(self):
        (self.base / "state").mkdir(mode=0o700)
        (self.base / "run").mkdir(mode=0o755)
        db = self.base / "state" / "events.db"
        db.write_text("")
        os.chmod(db, 0o644)
        path = self.base / "config.json"
        path.write_text(app_config_text(self.base))
        os.chmod(path, 0o600)
        results = checks.app_checks(parse_app(path.read_text()), path, uid=UID)
        self.assertIn("events database", [c.name for c in checks.failures(results)])

    def test_a_group_readable_config_is_not_private(self):
        path = self.base / "config.json"
        path.write_text("{}")
        for mode in (0o640, 0o660, 0o604, 0o610):
            os.chmod(path, mode)
            self.assertFalse(checks.private_file(path, UID).ok, oct(mode))
        os.chmod(path, 0o600)
        self.assertTrue(checks.private_file(path, UID).ok)

    def test_an_existing_marker_is_written_to_disk_again(self):
        control = self.base / "control"
        control.mkdir(mode=0o755)
        marker = control / stopper.MARKER
        marker.write_text("left by an earlier attempt")
        os.chmod(marker, 0o644)
        synced = []
        real = os.fsync

        def record(fd):
            synced.append(stat.S_ISREG(os.fstat(fd).st_mode))
            real(fd)

        with mock.patch.object(stopper.os, "fsync", side_effect=record):
            self.assertTrue(stopper.set_marker(control, UID))
        self.assertEqual(synced, [True, False])  # the marker file, then its folder


class CodexReviewOfA89371f(unittest.TestCase):
    """Codex's review of a89371f (should fix): a FIFO in the marker's place must not hang the
    helper, and requests refused while their headers are read must reach the events log."""

    def test_a_fifo_in_the_markers_place_is_refused_without_hanging(self):
        base = tmpdir(self)
        control = base / "control"
        control.mkdir(mode=0o755)
        os.mkfifo(control / stopper.MARKER, 0o644)
        result = []
        thread = threading.Thread(target=lambda: result.append(stopper.set_marker(control, UID)))
        thread.daemon = True
        thread.start()
        thread.join(3)
        self.assertFalse(thread.is_alive(), "set_marker blocked on a FIFO")
        self.assertEqual(result, [False])

    def serve_raw(self, raw: bytes):
        base = tmpdir(self)
        cfg = parse_app(app_config_text(base))
        events = Events(base / "events.db")
        events.initialise()
        rejected = []
        path = base / "app.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        server = UnixWSGIServer(
            listener,
            make_app(service=Service(config=cfg, events=events, stop=lambda: True)),
            {UID},
            on_rejected=rejected.append,
        )
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(path))
            client.sendall(raw)
            client.shutdown(socket.SHUT_WR)
            reply = b""
            try:
                while chunk := client.recv(65536):
                    reply += chunk
            except ConnectionResetError:
                pass
        thread.join(5)
        return reply, rejected

    def test_too_many_headers_is_recorded(self):
        filler = "".join(f"X-Filler-{i}: x\r\n" for i in range(45))
        reply, rejected = self.serve_raw(
            ("GET / HTTP/1.1\r\nHost: x\r\n" + filler + "\r\n").encode()
        )
        self.assertIn(b"431", reply.split(b"\r\n", 1)[0])
        self.assertEqual(rejected, [431])

    def test_a_malformed_request_is_recorded(self):
        reply, rejected = self.serve_raw(b"NONSENSE\r\n\r\n")
        self.assertIn(b"400", reply.split(b"\r\n", 1)[0])
        self.assertEqual(rejected, [400])


class CodexReviewOf39a39c3(unittest.TestCase):
    """Codex's review of 39a39c3 (blocking): a forbidden folder that can't be listed but can be
    entered still lets known files inside be opened, so it must not pass."""

    def setUp(self):
        self.base = tmpdir(self)

    @staticmethod
    def refused(path):
        raise PermissionError(path)

    def test_an_enterable_but_unlistable_folder_fails(self):
        folder = self.base / "credentials"
        folder.mkdir()
        result = checks.cannot_read(folder, self.refused, can_enter=lambda p: True)
        self.assertFalse(result.ok)
        self.assertIn("ENTERABLE", result.detail)

    def test_a_folder_that_cant_be_entered_passes(self):
        folder = self.base / "credentials"
        folder.mkdir()
        self.assertTrue(checks.cannot_read(folder, self.refused, can_enter=lambda p: False).ok)

    def test_an_unreadable_file_passes_whatever_its_execute_bit(self):
        key = self.base / "key.pem"
        key.write_text("x")
        self.assertTrue(checks.cannot_read(key, self.refused, can_enter=lambda p: True).ok)

    def test_a_path_behind_an_unenterable_folder_passes(self):
        with mock.patch.object(checks.os, "stat", side_effect=PermissionError):
            self.assertTrue(checks.cannot_read(self.base / "x" / "key", self.refused).ok)

    def test_a_folder_that_can_be_listed_fails(self):
        folder = self.base / "credentials"
        folder.mkdir()
        flags = os.O_RDONLY | os.O_DIRECTORY
        self.assertFalse(checks.cannot_read(folder, lambda p: os.open(p, flags)).ok)


if __name__ == "__main__":
    unittest.main()
