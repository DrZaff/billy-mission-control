"""Phase A5a (issue #16): the fetcher's foundation, against a fake GitHub: its config, the
GitHub client and the read-only App checks, and its start-up checks. No network."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization

from mission_fetcher import config as fconfig
from mission_fetcher import github as gh
from mission_fetcher.checks import fetcher_checks, shared_with_web_app
from tests.fetcher_fixtures import (
    APP_ID,
    KEY,
    NOW,
    OWNER,
    REPO_A,
    REPO_B,
    TOKEN,
    Base,
    FakeGitHub,
    client,
    make_cfg,
)


class Config(Base):
    def test_the_example_parses(self):
        text = (Path(__file__).resolve().parent.parent / "fetcher.example.json").read_text()
        cfg = fconfig.parse_fetcher(text)
        self.assertEqual(len(cfg.repos), 2)

    def test_refuses_bad_shapes(self):
        for over in (
            {"client_account": "fetcher-account"},
            {"app_id": "5909789"},
            {"app_id": True},
            {"repos": {}},
            {"repos": {"not a repo": {"required_checks": ["x"], "clinical_paths": []}}},
            {
                "repos": {
                    "example-org/..": {
                        "required_checks": ["x"],
                        "clinical_paths": [],
                        "checks_app": "github-actions",
                    }
                }
            },
            {
                "repos": {
                    "example-org/.": {
                        "required_checks": ["x"],
                        "clinical_paths": [],
                        "checks_app": "github-actions",
                    }
                }
            },
            {
                "repos": {
                    REPO_A: {
                        "required_checks": ["x"],
                        "clinical_paths": [],
                        "checks_app": "Not A Slug",
                    }
                }
            },
            {"repos": {REPO_A: {"required_checks": [], "clinical_paths": []}}},
            {"repos": {REPO_A: {"required_checks": ["x"]}}},
            {"owner": "bad login!"},
            {"clinicians": []},
            {"key": "relative/key.pem"},
            {"extra": 1},
        ):
            with self.subTest(over=over), self.assertRaises(fconfig.ConfigError):
                make_cfg(self.base, **over)


class ReadOnlyApp(Base):
    def test_the_jwt_is_signed_by_the_app_key(self):
        gh_client = client(self.fake)
        gh_client.installation(OWNER, [REPO_A, REPO_B])
        self.assertEqual(self.fake.jwts[0]["iss"], str(APP_ID))
        self.assertEqual(self.fake.jwts[0]["iat"], int(NOW.timestamp()) - 60)

    def test_a_good_app_passes(self):
        gh_client = client(self.fake)
        self.assertEqual(gh_client.installation(OWNER, [REPO_A, REPO_B]), 77)
        self.assertEqual(gh_client.token(77), TOKEN)
        gh_client.repositories(TOKEN, [REPO_A, REPO_B])

    def refused(self, code, step="installation"):
        gh_client = client(self.fake)
        with self.assertRaises(gh.FetchError) as caught:
            if step == "installation":
                gh_client.installation(OWNER, [REPO_A, REPO_B])
            elif step == "token":
                gh_client.token(77)
            else:
                gh_client.repositories(TOKEN, [REPO_A, REPO_B])
        self.assertEqual(caught.exception.code, code)

    def test_an_extra_permission_is_refused(self):
        self.fake.permissions["contents"] = "read"
        self.refused("not-read-only")

    def test_a_write_permission_is_refused(self):
        self.fake.permissions["issues"] = "write"
        self.refused("not-read-only")

    def test_an_installation_on_all_repositories_is_refused(self):
        self.fake.selection = "all"
        self.refused("not-selected-repositories")

    def test_a_third_repository_is_refused(self):
        self.fake.installed.append("example-owner/other")
        self.refused("wrong-repositories", step="repositories")

    def test_a_refused_token_that_could_not_be_revoked_says_so(self):
        # Codex's review of f37d0c7.
        self.fake.token_permissions["pull_requests"] = "write"
        self.fake.fail["/installation/token"] = (500, {}, b"")
        self.refused("token-not-read-only+token-not-revoked", step="token")

    def test_a_token_that_is_not_read_only_is_refused_and_revoked(self):
        # Codex's review of f772122 (blocking): it was refused but left valid for its hour.
        self.fake.token_permissions["pull_requests"] = "write"
        self.refused("token-not-read-only", step="token")
        self.assertEqual(self.fake.revoked, 1)

    def test_current_and_legacy_token_formats_are_accepted(self):
        # Codex's review of bf76866 (blocking): newer installation tokens are longer and have
        # dots, and the old ghs_ pattern refused them, so every refresh would fail.
        for token in ("ghs_" + "T" * 36, "ghs_" + "a" * 60 + "." + "b" * 300 + "." + "c" * 80):
            with self.subTest(length=len(token)):
                self.assertTrue(gh.TOKEN_SHAPE.fullmatch(token))
        for bad in ("short", "has space " * 4, "line\nbreak" * 4, "x" * 5000):
            with self.subTest(bad=bad[:12]):
                self.assertIsNone(gh.TOKEN_SHAPE.fullmatch(bad))

    def test_tls_never_writes_a_key_log(self):
        # Codex's review of f772122 (blocking): create_default_context() reads SSLKEYLOGFILE.
        keylog = self.base / "keys.log"
        saved = os.environ.get("SSLKEYLOGFILE")
        os.environ["SSLKEYLOGFILE"] = str(keylog)
        try:
            context = gh.tls_context()
        finally:
            if saved is None:
                del os.environ["SSLKEYLOGFILE"]
            else:
                os.environ["SSLKEYLOGFILE"] = saved
        self.assertIsNone(context.keylog_filename)
        self.assertFalse(keylog.exists())
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, __import__("ssl").CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, __import__("ssl").TLSVersion.TLSv1_2)

    def test_another_app_account_or_a_suspended_one_is_refused(self):
        for attr, value, code in (
            ("app_id", APP_ID + 1, "wrong-app"),
            ("account", "someone-else", "wrong-account"),
            ("suspended", "2026-11-01T00:00:00Z", "suspended"),
        ):
            with self.subTest(attr=attr):
                self.fake = FakeGitHub()
                setattr(self.fake, attr, value)
                self.refused(code)


class StartupChecks(Base):
    def setUp(self):
        super().setUp()
        self.uid, self.gid = os.getuid(), os.getgid()
        self.config_path = self.base / "fetcher.json"
        self.config_path.write_text("{}")
        os.chmod(self.config_path, 0o600)
        (self.base / "key.pem").write_text("synthetic")
        os.chmod(self.base / "key.pem", 0o600)
        os.chmod(self.base, 0o755)
        (self.base / "publisher.pem").write_text("x")

    @property
    def alone(self):
        return ("web-account", lambda a: self.gid, lambda g: {"web-account"})

    def checks(self, **kw):
        return {
            c.name: c
            for c in fetcher_checks(
                self.cfg,
                self.config_path,
                uid=self.uid,
                account_of=lambda uid: "fetcher-account",
                gid_of=lambda a: self.gid,
                **kw,
            )
        }

    def test_a_readable_key_fails(self):
        os.chmod(self.base / "key.pem", 0o644)
        self.assertFalse(self.checks()["reader key"].ok)

    def test_the_snapshot_folder_is_for_the_web_app_only(self):
        folder = self.cfg.snapshot_dir
        # Setgid is required, so new files take the folder's group (Codex, f772122).
        cases = ((0o2750, True), (0o750, False), (0o2755, False), (0o2700, False), (0o2770, False))
        for mode, ok in cases:
            with self.subTest(mode=oct(mode)):
                os.chmod(folder, mode)
                self.assertEqual(shared_with_web_app(folder, *self.alone).ok, ok)
        os.chmod(folder, 0o2750)
        wrong_group = ("web-account", lambda a: self.gid + 1, lambda g: {"web-account"})
        self.assertFalse(shared_with_web_app(folder, *wrong_group).ok)

    def test_files_in_the_snapshot_folder_are_the_fetchers_own(self):
        # Codex's review of b7d568e (blocking): an existing status file was trusted unchecked.
        from mission_fetcher.checks import folder_files

        folder = self.cfg.snapshot_dir
        status = folder / "status.json"
        self.assertTrue(folder_files(folder, self.uid).ok)  # empty
        status.write_text("{}")
        for mode, ok in ((0o640, True), (0o600, True), (0o660, False), (0o642, False)):
            with self.subTest(mode=oct(mode)):
                os.chmod(status, mode)
                self.assertEqual(folder_files(folder, self.uid).ok, ok)
        os.chmod(status, 0o640)
        self.assertFalse(folder_files(folder, self.uid + 1).ok)  # someone else's file
        status.unlink()
        status.symlink_to(self.base / "key.pem")
        self.assertFalse(folder_files(folder, self.uid).ok)
        status.unlink()
        self.assertIn("snapshot folder's files", self.checks())

    def test_the_web_app_can_reach_the_snapshot_folder(self):
        # Codex's review of 23bfb61: protected folders above it could still shut the web app out.
        from mission_fetcher.checks import reachable_by

        folder = self.cfg.snapshot_dir
        stranger = lambda account: (65534, {65534})  # noqa: E731 - an account in no group here
        os.chmod(self.base, 0o755)
        self.assertTrue(reachable_by(folder, "web-account", groups_of=stranger).ok)
        os.chmod(self.base, 0o750)  # only the owner and the group may pass
        check = reachable_by(folder, "web-account", groups_of=stranger)
        self.assertFalse(check.ok)
        self.assertIn(str(self.base), check.detail)
        member = lambda account: (65534, {os.stat(self.base).st_gid})  # noqa: E731
        self.assertTrue(reachable_by(folder, "web-account", groups_of=member).ok)
        os.chmod(self.base, 0o755)

    def test_an_acl_above_the_snapshot_folder_fails_the_path_check(self):
        # Codex's review of ab64500: an ACL can shut one account out whatever the mode bits say,
        # and this process can't evaluate it for another account.
        import struct

        from mission_fetcher.checks import reachable_by

        u = 0xFFFFFFFF
        entries = [(0x01, 7, u), (0x02, 0, 65534), (0x04, 5, u), (0x10, 5, u), (0x20, 5, u)]
        acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *e) for e in entries)
        os.chmod(self.base, 0o755)
        try:
            os.setxattr(self.base, "system.posix_acl_access", acl)
        except OSError:
            self.skipTest("this file system or account can't set an ACL")
        self.addCleanup(lambda: os.removexattr(self.base, "system.posix_acl_access"))
        check = reachable_by(
            self.cfg.snapshot_dir, "web-account", groups_of=lambda a: (65534, {65534})
        )
        self.assertFalse(check.ok)
        self.assertIn("ACL", check.detail)

    def test_an_acl_probe_that_cannot_look_fails_closed(self):
        # Codex's review of b24ac2d: every read failure counted as "no ACL".
        import errno

        from mission_fetcher import checks as fchecks

        for err, has in ((errno.ENOTSUP, False), (errno.EACCES, True), (errno.EIO, True)):
            with (
                self.subTest(errno=errno.errorcode[err]),
                mock.patch.object(fchecks.os, "listxattr", side_effect=OSError(err, "x")),
            ):
                self.assertEqual(fchecks._has_acl("/anything"), has)

    def test_an_acl_on_the_folder_or_a_file_fails(self):
        # Codex's review of bf76866 (blocking): a named ACL could let another account read the
        # snapshot; a default ACL would pass that on to every new file.
        from mission_fetcher.checks import no_acls

        folder = self.cfg.snapshot_dir
        (folder / "snapshot.json").write_text("{}")
        self.assertTrue(no_acls(folder).ok)
        for marked in (str(folder), str(folder / "snapshot.json")):
            with self.subTest(marked=marked):
                check = no_acls(folder, has_acl=lambda p, m=marked: p == m)
                self.assertFalse(check.ok)
                self.assertIn("setfacl -b", check.detail)

    def test_a_real_acl_is_seen(self):
        # A real ACL, written through the kernel's attribute (setfacl may not be installed).
        import struct

        from mission_fetcher.checks import no_acls

        folder = self.cfg.snapshot_dir
        u = 0xFFFFFFFF
        entries = [(0x01, 7, u), (0x02, 5, 65534), (0x04, 5, u), (0x10, 5, u), (0x20, 0, u)]
        acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *e) for e in entries)
        try:
            os.setxattr(folder, "system.posix_acl_access", acl)
        except OSError:
            self.skipTest("this file system or account can't set an ACL")
        self.assertFalse(no_acls(folder).ok)

    def test_the_group_holds_the_web_app_alone(self):
        # Codex's review of 1cc6cf8 (blocking): any other member could read the snapshot.
        folder = self.cfg.snapshot_dir
        os.chmod(folder, 0o2750)
        shared = ("web-account", lambda a: self.gid, lambda g: {"web-account", "intruder"})
        check = shared_with_web_app(folder, *shared)
        self.assertFalse(check.ok)
        self.assertIn("intruder", check.detail)

    def test_a_snapshot_folder_the_fetcher_cannot_write_fails(self):
        # Codex's review of df5912d (should fix): every refresh would fail after start-up.
        folder = self.base / "snapshot"
        os.chmod(folder, 0o550)
        self.addCleanup(os.chmod, folder, 0o750)
        self.assertFalse(self.checks()["fetcher can write the snapshot folder"].ok)
        os.chmod(folder, 0o750)
        self.assertTrue(self.checks()["fetcher can write the snapshot folder"].ok)

    def test_every_start_up_check_is_run(self):
        startup = self._startup()
        names = list(StartupChecks.checks(startup))
        # The exact list: dropping any one check fails here (audit of 8c62413).
        expected = {
            "not root",
            "runs as fetcher-account",
            "web app account web-account",
            "config fetcher.json",
            "folders above fetcher.json",
            "reader key",
            "folders above key.pem",
            "snapshot folder",
            "fetcher can write the snapshot folder",
            "snapshot folder's files",
            "snapshot folder shared with the web app only",
            "no ACLs on the snapshot folder or its files",
            "folders above snapshot",
            "web-account can reach the snapshot folder",
        }
        expected |= {f"cannot read {p}" for p in startup.cfg.forbidden_paths}
        self.assertEqual(set(names), expected)
        self.assertTrue(startup.cfg.forbidden_paths)
        # And each is made by fetcher_checks itself, once.
        made = fetcher_checks(
            startup.cfg,
            startup.config_path,
            uid=startup.uid,
            account_of=lambda uid: "fetcher-account",
            gid_of=lambda a: startup.gid,
        )
        self.assertEqual(sorted(c.name for c in made), sorted(expected))

    def _startup(self):
        startup = StartupChecks("test_a_readable_key_fails")
        startup.setUp()
        self.addCleanup(startup.doCleanups)
        return startup


class GitHubClient(Base):
    """The client's transport, TLS and answers, apart from the snapshot."""

    def test_a_slow_connection_setup_is_cut_off_by_the_request_limit(self):
        # Codex's review of 0cf099c: the watchdog couldn't reach a socket still connecting
        # (name lookup, TCP, TLS).
        import time as tm

        closed = []

        class SlowConnection:
            def __init__(self, held, expired, *a, **k):
                self.sock = None

            def connect(self):
                tm.sleep(2)  # setup that takes far longer than the limit

            def close(self):
                closed.append(1)

        limit = gh._LIMIT.set(0.3)
        started = tm.monotonic()
        try:
            with mock.patch.object(gh, "_Connection", SlowConnection):
                with self.assertRaises(gh.FetchError) as caught:
                    gh.https_transport("GET", "/x", {}, None)
        finally:
            gh._LIMIT.reset(limit)
        self.assertEqual(caught.exception.code, "timeout")
        self.assertLess(tm.monotonic() - started, 1.5)
        tm.sleep(2)  # the late connection closes itself too
        self.assertGreaterEqual(len(closed), 2)

    def test_deeply_nested_json_from_github_is_a_bad_response(self):
        # Finding 8.
        github = gh.GitHub(
            APP_ID,
            KEY,
            transport=lambda *a: (200, {}, b"[" * 200000 + b"]" * 200000),
            clock=lambda: NOW.timestamp(),
        )
        with self.assertRaises(gh.FetchError) as caught:
            github.graphql(TOKEN, "query { x }", {})
        self.assertEqual(caught.exception.code, "bad-response")

    def test_graphql_never_returns_partial_data_as_if_it_were_whole(self):
        # Codex's review of c3ee86b: the partial answer travels with the error only.
        answer = {
            "data": {"repository": {"p0": {"files": None}}},
            "errors": [{"type": "X", "path": ["repository", "p0", "files"]}],
        }
        fake = lambda *a: (200, {}, json.dumps(answer).encode())  # noqa: E731
        github = gh.GitHub(APP_ID, KEY, transport=fake, clock=lambda: NOW.timestamp())
        with self.assertRaises(gh.FetchError) as caught:
            github.graphql(TOKEN, "query { x }", {})
        self.assertEqual(caught.exception.code, "graphql-error")
        self.assertEqual(caught.exception.paths, (("repository", "p0", "files"),))
        self.assertEqual(caught.exception.data, answer["data"])

    def test_an_errors_field_that_is_not_a_list_is_a_bad_response(self):
        # Codex's review of c3ee86b: an empty object, an empty string or false was read as
        # "no errors".
        for errors in ({}, "", False, 0, None, {"a": 1}, "x"):
            with self.subTest(errors=errors):
                answer = {"data": {"repository": {}}, "errors": errors}
                fake = lambda *a, answer=answer: (200, {}, json.dumps(answer).encode())  # noqa: E731
                github = gh.GitHub(APP_ID, KEY, transport=fake, clock=lambda: NOW.timestamp())
                with self.assertRaises(gh.FetchError) as caught:
                    github.graphql(TOKEN, "query { x }", {})
                self.assertEqual(caught.exception.code, "bad-response")
        answer = {"data": {"repository": {}}, "errors": []}
        fake = lambda *a: (200, {}, json.dumps(answer).encode())  # noqa: E731
        github = gh.GitHub(APP_ID, KEY, transport=fake, clock=lambda: NOW.timestamp())
        self.assertEqual(github.graphql(TOKEN, "query { x }", {}), {"repository": {}})

    def test_strange_graphql_error_types_never_raise(self):
        # Codex's review of 7faf35a: a list or object type raised TypeError.
        for kind in (["RATE_LIMITED"], {"a": 1}, None, 7):
            with self.subTest(kind=kind):
                answer = {"data": None, "errors": [{"type": kind}]}
                fake = lambda *a, answer=answer: (200, {}, json.dumps(answer).encode())  # noqa: E731
                github = gh.GitHub(APP_ID, KEY, transport=fake, clock=lambda: NOW.timestamp())
                with self.assertRaises(gh.FetchError) as caught:
                    github.graphql(TOKEN, "query { x }", {})
                self.assertEqual(caught.exception.code, "graphql-error")

    def test_the_trust_store_never_comes_from_the_environment(self):
        # Real files at the variables' paths (audit of 24973b8: with paths that didn't exist,
        # code reading the variables passed too).
        other_ca = self.base / "other-ca.pem"
        other_ca.write_text(
            KEY.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        (self.base / "other-certs").mkdir()
        loaded = []
        real = __import__("ssl").SSLContext.load_verify_locations

        def spy(context, cafile=None, capath=None, cadata=None):
            loaded.append((cafile, capath))
            return real(context, cafile=cafile, capath=capath, cadata=cadata)

        with (
            mock.patch.dict(
                os.environ,
                {
                    "SSL_CERT_FILE": str(self.base / "other-ca.pem"),
                    "SSL_CERT_DIR": str(self.base / "other-certs"),
                },
            ),
            mock.patch.object(gh.ssl.SSLContext, "load_verify_locations", spy),
            mock.patch.object(
                gh.ssl.SSLContext,
                "load_default_certs",
                side_effect=AssertionError("reads the environment"),
            ),
        ):
            gh.tls_context()
        paths = gh.ssl.get_default_verify_paths()
        self.assertEqual(len(loaded), 1)
        cafile, capath = loaded[0]
        self.assertEqual(
            cafile, paths.openssl_cafile if os.path.isfile(paths.openssl_cafile) else None
        )
        self.assertEqual(
            capath, paths.openssl_capath if os.path.isdir(paths.openssl_capath) else None
        )
        self.assertNotIn(str(self.base), f"{cafile}{capath}")

    def test_a_dripping_handshake_is_cut_off_and_leaves_no_thread(self):
        import socket as so
        import threading as th
        import time as tm

        listener = so.socket(so.AF_INET, so.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def drip():
            conn, _ = listener.accept()
            with conn:
                # A TLS record header promising 16 KB of handshake, then its body one byte at a
                # time: each read waits, never long enough to time the socket out.
                conn.sendall(b"\x16\x03\x03\x40\x00")
                ends = tm.monotonic() + 6
                while tm.monotonic() < ends:
                    try:
                        conn.sendall(b"\x00")
                    except OSError:
                        return
                    tm.sleep(0.05)

        th.Thread(target=drip, daemon=True).start()
        before = th.active_count()
        limit = gh._LIMIT.set(0.5)
        started = tm.monotonic()
        try:
            with mock.patch.object(gh, "HOST", "127.0.0.1"), mock.patch.object(gh, "PORT", port):
                with self.assertRaises(gh.FetchError) as caught:
                    gh.https_transport("GET", "/x", {}, None)
        finally:
            gh._LIMIT.reset(limit)
        self.assertEqual(caught.exception.code, "timeout")
        self.assertLess(tm.monotonic() - started, 3)
        for _ in range(40):  # the connect thread ends once the watchdog shuts its socket
            if th.active_count() <= before:
                break
            tm.sleep(0.05)
        self.assertLessEqual(th.active_count(), before)
        listener.close()

    def test_the_connection_hands_its_socket_over_before_the_handshake(self):
        import socket as so

        listener = so.socket(so.AF_INET, so.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        seen = []

        def handshake(sock):
            seen.append(sock in held)  # already reachable by the watchdog
            raise OSError("stop here")

        held, expired = [], __import__("threading").Event()
        conn = gh._Connection(held, expired, "127.0.0.1", port, timeout=2, context=gh.tls_context())
        with mock.patch.object(gh.ssl.SSLSocket, "do_handshake", handshake):
            with self.assertRaises(OSError):
                conn.connect()
        conn.close()
        self.assertEqual(seen, [True])
        # Past the limit already: no handshake at all.
        held, expired = [], __import__("threading").Event()
        expired.set()
        conn = gh._Connection(held, expired, "127.0.0.1", port, timeout=2, context=gh.tls_context())
        with mock.patch.object(
            gh.ssl.SSLSocket,
            "do_handshake",
            side_effect=AssertionError("handshake after the limit"),
        ):
            with self.assertRaises(TimeoutError):
                conn.connect()
        conn.close()

    def transport_with(self, body: bytes, length: str | None):
        """https_transport against a connection whose response is `body`, announced as
        `length` bytes (no Content-Length when None)."""
        asked = []

        class Response:
            status = 200

            def read(self, n=None):
                asked.append(n)
                return body[:n]

            def getheader(self, name):
                return length if name == "Content-Length" else None

            def getheaders(self):
                return [] if length is None else [("Content-Length", length)]

        class Connection:
            def __init__(self, held, expired, *a, **k):
                self.sock = None

            def connect(self):
                pass

            def request(self, *a, **k):
                pass

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with mock.patch.object(gh, "_Connection", Connection):
            gh.https_transport("GET", "/x", {}, None)
        return asked

    def test_the_transport_reads_no_more_than_its_cap(self):
        asked = self.transport_with(b"x" * (gh.MAX_RESPONSE * 2), None)
        self.assertEqual(asked, [gh.MAX_RESPONSE + 1])

    def test_an_answer_cut_short_is_never_whole(self):
        # Codex's review of df5912d (blocking): an early end gave fewer bytes with no error.
        for length in ("100", "not a number", "-1"):
            with self.subTest(length=length), self.assertRaises(gh.FetchError) as caught:
                self.transport_with(b'{"a": 1}', length)
            self.assertEqual(caught.exception.code, "network")
        self.transport_with(b'{"a": 1}', "8")  # whole: fine
        self.transport_with(b'{"a": 1}', None)  # read to the end: fine

    def test_an_odd_or_repeated_repository_row_is_never_skipped(self):
        # Codex's review of df5912d (should fix).
        real = self.fake.__call__
        good = [{"full_name": REPO_A}, {"full_name": REPO_B}]
        for rows, total, code in (
            ([*good, "junk"], 2, "bad-response"),
            ([{"full_name": REPO_A}, {"full_name": {"x": 1}}], 2, "bad-response"),
            ([*good, {"full_name": REPO_A}], 2, "wrong-repositories"),
            ([{"full_name": REPO_A}, {"full_name": REPO_A}], 2, "wrong-repositories"),
        ):
            with self.subTest(rows=rows):

                def call(method, path, headers, body, rows=rows, total=total):
                    if path == "/installation/repositories?per_page=100":
                        answer = {"total_count": total, "repositories": rows}
                        return 200, {}, json.dumps(answer).encode()
                    return real(method, path, headers, body)

                github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
                with self.assertRaises(gh.FetchError) as caught:
                    github.repositories(TOKEN, [REPO_A, REPO_B])
                self.assertEqual(caught.exception.code, code)

    def test_two_installations_are_refused(self):
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == f"/repos/{REPO_B}/installation":
                answer = json.loads(data)
                answer["id"] = 78
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        with self.assertRaises(gh.FetchError) as caught:
            github.installation(OWNER, [REPO_A, REPO_B])
        self.assertEqual(caught.exception.code, "several-installations")


if __name__ == "__main__":
    unittest.main()
