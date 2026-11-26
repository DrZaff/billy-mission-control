"""Phase A5a (issue #16): the fetcher's service, command line and stop handling, against a fake
GitHub. No network; the App's key is generated at run time, never committed."""

from __future__ import annotations

import json
import os
import queue
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization

from mission_fetcher import __main__ as entry
from mission_fetcher import config as fconfig
from mission_fetcher import github as gh
from mission_fetcher import server, snapshot
from mission_fetcher.__main__ import github_checks
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
    config_data,
)

# ---------------------------------------------------------------- config


class ServicePieces(Base):
    def test_a_symlinked_key_is_never_followed(self):
        real_key = self.base / "real.pem"
        real_key.write_text("synthetic")
        link = self.base / "link.pem"
        link.symlink_to(real_key)
        with self.assertRaises(gh.FetchError):
            server.read_key(link)

    def test_running_out_of_requests_has_its_own_reason(self):
        self.assertRegex("over-budget", server.REASON)

    def test_the_command_line_shows_config_errors_that_way(self):
        import contextlib
        import io

        from mission_fetcher.__main__ import main

        bad = self.base / "bad.json"
        data = config_data(self.base)
        data["odd\nkey\x1b[31m" + "x" * 5000] = 1  # an unknown key, quoted in the error
        bad.write_text(json.dumps(data))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertNotEqual(main(["selfcheck", "--config", str(bad)]), 0)
        message = err.getvalue().rstrip("\n")
        self.assertIn("1 unknown key(s)", message)
        self.assertNotIn("odd", message)  # never the key itself (Codex's review of 9650d02)
        self.assertNotRegex(message, "[\x00-\x1f\x7f-\x9f]")
        self.assertLess(len(message), 300)  # never the file's text at length


class SelfCheck(Base):
    """`selfcheck --github`: the App checked as every refresh checks it."""

    def test_selfcheck_reports_each_step_and_revokes(self):
        results = github_checks(self.cfg_for_repos(), client(self.fake))
        self.assertTrue(all(c.ok for c in results), results)
        self.assertEqual(self.fake.revoked, 1)
        # The repositories are counted, never named: they are the config's own text.
        self.assertFalse(any(REPO_A in c.name + c.detail for c in results))
        self.fake.permissions["checks"] = "write"
        results = github_checks(self.cfg_for_repos(), client(self.fake))
        self.assertEqual([(c.ok, c.detail) for c in results], [(False, "not-read-only")])

    def cfg_for_repos(self):
        return self.cfg


class RefresherFiles(Base):
    def make(self, clock, boot=None):
        """A refresher on a fake wall clock and, unless given, a fake time since boot that
        follows it in the same boot."""
        key = KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        (self.base / "key.pem").write_bytes(key)
        os.chmod(self.base / "key.pem", 0o600)
        return server.Refresher(
            self.cfg,
            github=lambda cfg: gh.GitHub(
                APP_ID, gh.load_key(server.read_key(cfg.key)), transport=self.fake, clock=clock
            ),
            clock=clock,
            boot=boot or (lambda: ("boot-1", clock() - NOW.timestamp() + 1000.0)),
        )

    def test_ok_writes_the_snapshot_and_status_readable_by_the_group_only(self):
        reply = self.make(lambda: NOW.timestamp()).run()
        self.assertEqual(reply, server.OK)
        snap = self.cfg.snapshot_dir / snapshot.SNAPSHOT
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual(stat.S_IMODE(os.stat(snap).st_mode), 0o640)
        self.assertEqual(status["result"], "ok")
        self.assertEqual(status["items"], 3)
        self.assertFalse([n for n in os.listdir(self.cfg.snapshot_dir) if n.endswith(".tmp")])

    def test_a_failure_keeps_the_last_good_snapshot(self):
        now = [NOW.timestamp()]
        refresher = self.make(lambda: now[0])
        self.assertEqual(refresher.run(), server.OK)
        good = (self.cfg.snapshot_dir / snapshot.SNAPSHOT).read_bytes()
        now[0] += 120
        self.fake.fail["/graphql"] = (502, {}, b"")
        self.assertEqual(refresher.run(), b"failed:http-502\n")
        self.assertEqual((self.cfg.snapshot_dir / snapshot.SNAPSHOT).read_bytes(), good)
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual((status["result"], status["reason"]), ("failed", "http-502"))
        self.assertEqual(status["snapshot_at"], NOW.isoformat())

    def test_at_most_one_refresh_a_minute_even_after_a_restart(self):
        now = [NOW.timestamp()]
        self.assertEqual(self.make(lambda: now[0]).run(), server.OK)
        now[0] += 30
        self.assertEqual(self.make(lambda: now[0]).run(), server.TOO_SOON)  # a new process
        now[0] += 31
        self.assertEqual(self.make(lambda: now[0]).run(), server.OK)

    def test_an_accept_error_never_stops_the_service(self):
        class Broken:
            def accept(self):
                raise OSError(24, "Too many open files")

        # The second pause ends the test, which passed `once` and never saw the service go on.
        lines, pauses = [], mock.patch.object(server.time, "sleep", side_effect=[None, EOFError])
        with pauses, self.assertRaises(EOFError):
            server.serve(Broken(), object(), os.getuid(), log=lines.append)
        self.assertEqual(lines, ["fetcher: error: accept"] * 2)

    def test_a_wall_clock_change_never_moves_the_floor_within_a_boot(self):
        wall, since_boot = [NOW.timestamp()], [1000.0]

        def make():
            return self.make(lambda: wall[0], boot=lambda: ("boot-1", since_boot[0]))

        self.assertEqual(make().run(), server.OK)
        wall[0] -= 3 * 3600  # the wall clock goes back three hours...
        since_boot[0] += 5  # ...five seconds after the last refresh
        self.assertEqual(make().run(), server.TOO_SOON)
        wall[0] += 5 * 3600  # and forward five hours: still five seconds since boot
        self.assertEqual(make().run(), server.TOO_SOON)
        since_boot[0] += 60  # a real minute later, whatever the wall clock says
        self.assertEqual(make().run(), server.OK)

    def test_an_unreadable_boot_id_still_uses_time_since_boot(self):
        wall, since_boot = [NOW.timestamp()], [1000.0]

        def make():
            return self.make(lambda: wall[0], boot=lambda: (None, since_boot[0]))

        self.assertEqual(make().run(), server.OK)
        wall[0] += 5 * 3600  # the wall clock jumps hours ahead...
        since_boot[0] += 5  # ...five seconds after the last refresh
        self.assertEqual(make().run(), server.TOO_SOON)
        since_boot[0] += 60
        self.assertEqual(make().run(), server.OK)

    def test_without_boot_ids_a_new_boot_can_only_wait_longer(self):
        since_boot = [5.0]
        wall = [NOW.timestamp()]

        def make():
            return self.make(lambda: wall[0], boot=lambda: (None, since_boot[0]))

        self.assertEqual(make().run(), server.OK)
        since_boot[0], wall[0] = 40.0, wall[0] + 40  # a new boot, 40 s on
        self.assertEqual(make().run(), server.TOO_SOON)  # waits: never a bypass
        since_boot[0], wall[0] = 66.0, wall[0] + 26  # 66 s since that boot began
        self.assertEqual(make().run(), server.OK)  # and in fact at least 66 s have passed

    def test_after_a_restart_only_time_since_boot_counts(self):
        wall = [NOW.timestamp()]
        self.assertEqual(
            self.make(lambda: wall[0], boot=lambda: ("boot-1", 5000.0)).run(), server.OK
        )
        wall[0] += 5 * 60  # the clock comes up five minutes fast...
        self.assertEqual(
            self.make(lambda: wall[0], boot=lambda: ("boot-2", 15.0)).run(), server.TOO_SOON
        )  # ...but only 15 s since boot: wait
        self.assertEqual(
            self.make(lambda: wall[0], boot=lambda: (None, 15.0)).run(), server.TOO_SOON
        )  # the same with the boot id unreadable
        self.assertEqual(
            self.make(lambda: wall[0], boot=lambda: ("boot-2", 61.0)).run(), server.OK
        )  # a minute since boot proves a minute since the attempt

    def test_which_boot_an_attempt_was_in_is_never_guessed(self):
        # 160cc5a's mutation sweep: each of these guards could go and every test passed.
        for boot in (
            ("boot-1", 100.0, server.OK),
            ("boot-2", 130.0, server.OK),  # another boot, up over a minute
            (None, 135.0, server.TOO_SOON),  # its id unreadable now: 5 s on
            (None, 190.0, server.OK),  # exactly a minute
            ("boot-2", 195.0, server.TOO_SOON),  # the id unreadable then
            (None, 190.0, server.TOO_SOON),  # no time at all
            (None, 70.0, server.OK),  # no ids, a new boot: no wait for 190 s
            ("boot-3", 60.0, server.OK),  # a minute into another boot
        ):
            reply = self.make(NOW.timestamp, boot=lambda boot=boot: boot[:2]).run()
            self.assertEqual(reply, boot[2])

    def test_an_unreadable_status_file_is_not_no_earlier_attempt(self):
        self.assertEqual(self.make(lambda: NOW.timestamp()).run(), server.OK)
        real_open = os.open

        def refuse(path, *a, **k):
            if str(path).endswith(snapshot.STATUS):
                raise OSError(24, "Too many open files")
            return real_open(path, *a, **k)

        with mock.patch.object(snapshot.os, "open", side_effect=refuse):
            reply = self.make(lambda: NOW.timestamp() + 1).run()
        self.assertEqual(reply, b"failed:status\n")

    def test_a_malformed_status_file_keeps_the_floor_and_heals_itself(self):
        wall = [NOW.timestamp()]
        self.assertEqual(self.make(lambda: wall[0]).run(), server.OK)
        # Deeply nested JSON raised RecursionError past the handler (Codex's review of de9a6fb).
        for bad in (
            b"{not json",
            b"[]",
            b"\xff\xfe",
            b'{"a":' + b"[" * 200000 + b"]" * 200000 + b"}",
        ):
            with self.subTest(bad=bad):
                (self.cfg.snapshot_dir / snapshot.STATUS).write_bytes(bad)
                wall[0] += 1
                self.assertEqual(self.make(lambda: wall[0]).run(), b"failed:status\n")
                wall[0] += 1  # the attempt was recorded: still the floor
                self.assertEqual(self.make(lambda: wall[0]).run(), server.TOO_SOON)
                wall[0] += 61  # a minute later it goes ahead, with nobody repairing anything
                self.assertEqual(self.make(lambda: wall[0]).run(), server.OK)

    def test_a_status_file_with_bad_times_keeps_the_floor(self):
        wall = [NOW.timestamp()]
        self.assertEqual(self.make(lambda: wall[0]).run(), server.OK)
        for bad in (
            b"{}",
            b'{"attempt_epoch": 1}',
            b'{"attempt_epoch": Infinity, "attempt_since_boot": 5}',
            b'{"attempt_epoch": 1, "attempt_since_boot": NaN}',
            b'{"attempt_epoch": 1, "attempt_since_boot": -5}',
            b'{"attempt_epoch": 1, "attempt_since_boot": true}',
            b'{"attempt_epoch": 1, "attempt_since_boot": 5, "boot_id": 7}',
            # Too large for a float (Codex's review of 9fb21c8: OverflowError escaped).
            b'{"attempt_epoch": 1' + b"0" * 400 + b', "attempt_since_boot": 5}',
            b'{"attempt_epoch": 1, "attempt_since_boot": 1' + b"0" * 400 + b"}",
        ):
            with self.subTest(bad=bad):
                (self.cfg.snapshot_dir / snapshot.STATUS).write_bytes(bad)
                wall[0] += 1
                self.assertEqual(self.make(lambda: wall[0]).run(), b"failed:status\n")
                wall[0] += 1
                self.assertEqual(self.make(lambda: wall[0]).run(), server.TOO_SOON)
                wall[0] += 61
                self.assertEqual(self.make(lambda: wall[0]).run(), server.OK)

    def test_an_attempt_recorded_in_the_future_never_freezes_refreshes(self):
        wall = [NOW.timestamp()]
        boot = lambda: ("boot-1", 100.0)  # noqa: E731
        status = {"boot_id": "boot-1", "attempt_since_boot": 2**53, "attempt_epoch": 1}
        (self.cfg.snapshot_dir / snapshot.STATUS).write_text(json.dumps(status))
        self.assertEqual(self.make(lambda: wall[0], boot=boot).run(), b"failed:status\n")
        later = lambda: ("boot-1", 161.0)  # noqa: E731
        self.assertEqual(self.make(lambda: wall[0], boot=later).run(), server.OK)

    def test_only_a_short_iso_time_is_carried_over_as_the_last_snapshot(self):
        for bad in (["x"], "x" * 100, "yesterday", "2026-11-24T10:00:00"):
            with self.subTest(bad=bad):
                self.assertIsNone(server._snapshot_at(bad))
        self.assertEqual(server._snapshot_at(NOW.isoformat()), NOW.isoformat())

    def test_a_failed_write_still_says_when_the_token_outlived_it(self):
        self.fake.fail["/installation/token"] = (500, {}, b"")
        real_replace = os.replace

        def fail_snapshot(src, dst, *a, **k):
            if dst == snapshot.SNAPSHOT:
                raise OSError(28, "No space left on device")
            return real_replace(src, dst, *a, **k)

        with mock.patch.object(snapshot.os, "replace", side_effect=fail_snapshot):
            reply = self.make(lambda: NOW.timestamp()).run()
        self.assertEqual(reply, b"failed:write+token-not-revoked\n")

    def test_a_leftover_temp_file_never_blocks_writes(self):
        leftover = self.cfg.snapshot_dir / f".{snapshot.SNAPSHOT}.{os.getpid()}.tmp"
        leftover.write_text("half")
        self.assertEqual(self.make(lambda: NOW.timestamp()).run(), server.OK)
        self.assertFalse(leftover.exists())

    def test_no_token_or_key_reaches_any_file(self):
        self.make(lambda: NOW.timestamp()).run()
        self.fake.fail["/graphql"] = (502, {}, TOKEN.encode())  # even echoed in a body
        self.make(lambda: NOW.timestamp() + 120).run()
        for name in os.listdir(self.cfg.snapshot_dir):
            text = (self.cfg.snapshot_dir / name).read_text()
            self.assertNotIn(TOKEN, text, name)
            self.assertNotIn("PRIVATE KEY", text, name)

    def test_a_symlinked_snapshot_folder_is_never_written_through(self):
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        os.rmdir(self.cfg.snapshot_dir)
        os.symlink(elsewhere, self.cfg.snapshot_dir)
        self.assertEqual(self.make(lambda: NOW.timestamp()).run(), b"failed:write\n")
        self.assertEqual(os.listdir(elsewhere), [])

    def test_a_surprise_fails_the_refresh_not_the_service(self):
        def broken(cfg):
            raise TypeError("a surprise")

        refresher = self.make(lambda: NOW.timestamp())
        refresher.github = broken
        self.assertEqual(refresher.run(), b"failed:internal\n")
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual((status["result"], status["reason"]), ("failed", "internal"))

    def test_a_short_write_never_leaves_a_truncated_file(self):
        real_write = os.write

        def dribble(fd, data):
            return real_write(fd, bytes(data[:7]))  # a few bytes at a time

        with mock.patch.object(snapshot.os, "write", side_effect=dribble):
            self.assertEqual(self.make(lambda: NOW.timestamp()).run(), server.OK)
        written = snapshot.read_json(self.cfg.snapshot_dir, snapshot.SNAPSHOT)
        self.assertEqual(len(written["items"]), 3)

    def test_a_failed_folder_sync_after_the_rename_is_not_a_failed_write(self):
        real = os.fsync
        folder_syncs = []

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                folder_syncs.append(fd)
                if len(folder_syncs) > 1:
                    raise OSError(5, "sync failed")
            return real(fd)

        with mock.patch.object(snapshot.os, "fsync", side_effect=fsync):
            self.assertEqual(self.make(lambda: NOW.timestamp()).run(), server.OK)
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual(status["snapshot_at"], NOW.isoformat())

    def test_no_network_work_without_a_durably_recorded_attempt(self):
        real = os.fsync

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(5, "sync failed")
            return real(fd)

        with mock.patch.object(snapshot.os, "fsync", side_effect=fsync):
            self.assertEqual(self.make(lambda: NOW.timestamp()).run(), b"failed:write\n")
        self.assertEqual(self.fake.calls, [])  # nothing sent to GitHub

    def test_a_token_that_could_not_be_revoked_is_reported(self):
        self.fake.fail["/installation/token"] = (500, {}, b"")
        self.assertEqual(self.make(lambda: NOW.timestamp()).run(), b"ok:token-not-revoked\n")
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual((status["result"], status["reason"]), ("ok", "token-not-revoked"))
        self.assertTrue((self.cfg.snapshot_dir / snapshot.SNAPSHOT).exists())

    def test_a_file_that_misses_the_folders_group_is_refused(self):
        if os.getuid() != 0:
            self.skipTest("needs root to set the folder's group")
        os.chown(self.cfg.snapshot_dir, -1, 1)  # another group, no setgid
        os.chmod(self.cfg.snapshot_dir, 0o750)
        self.assertEqual(self.make(lambda: NOW.timestamp()).run(), b"failed:write\n")
        self.assertFalse((self.cfg.snapshot_dir / snapshot.SNAPSHOT).exists())

    def test_one_refresh_at_a_time_across_processes(self):
        seen = {}
        refresher = self.make(lambda: NOW.timestamp())
        real = self.fake.__call__

        def during(method, path, headers, body):
            if "busy" not in seen:
                other = server.Refresher(self.cfg, clock=lambda: NOW.timestamp())
                seen["busy"] = other.run()  # a second process, mid-refresh
                seen["status"] = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
            return real(method, path, headers, body)

        self.fake.__call__ = during
        refresher.github = lambda cfg: gh.GitHub(
            APP_ID, KEY, transport=during, clock=lambda: NOW.timestamp()
        )
        self.assertEqual(refresher.run(), server.OK)
        self.assertEqual(seen["busy"], server.BUSY)
        # The attempt was on disk before the first request, so a restart can't skip the floor.
        self.assertEqual(seen["status"]["result"], "running")
        self.assertEqual(seen["status"]["attempt_epoch"], NOW.timestamp())


class Socket(Base):
    def serve_once(self, client_uid, request, once=True):
        path = self.base / "fetch.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        self.addCleanup(listener.close)
        lines = []

        class Fixed:
            def run(self):
                if len(lines) == 1:
                    gh.STOPPING.set()  # the second request is the last
                return server.OK

        self.addCleanup(gh.STOPPING.clear)
        thread = threading.Thread(
            target=server.serve,
            args=(listener, Fixed(), client_uid),
            kwargs={"log": lines.append, "once": once},
            daemon=True,
        )
        thread.start()
        for _ in range(1 if once else 2):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(5)
                conn.connect(str(path))
                try:
                    conn.sendall(request)
                except BrokenPipeError:
                    pass  # refused and closed before it was sent: it failed under load
                reply = conn.recv(64)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        return reply, lines

    def test_the_web_apps_account_gets_a_refresh(self):
        reply, lines = self.serve_once(os.getuid(), server.REQUEST)
        self.assertEqual(reply, server.OK)
        self.assertEqual(lines, ["fetcher: refresh: ok"])

    def test_one_request_after_another_is_answered(self):
        # 160cc5a's sweep: a service that ended after its first request passed every test.
        _, lines = self.serve_once(os.getuid(), server.REQUEST, once=False)
        self.assertEqual(lines, ["fetcher: refresh: ok"] * 2)

    def test_any_other_account_is_refused(self):
        reply, lines = self.serve_once(os.getuid() + 1, server.REQUEST)
        self.assertEqual(reply, server.REFUSED)
        self.assertEqual(lines, ["fetcher: refused: wrong account"])

    def test_anything_but_the_request_is_refused(self):
        reply, _ = self.serve_once(os.getuid(), b"STOP\n")
        self.assertEqual(reply, server.REFUSED)


class AuditOfE58b933(Base):
    """An audit from a different angle: the trust store, the handshake, the start-up gate and
    guards no test exercised."""

    def main_with(self, argv, results):
        from mission_fetcher import __main__ as entry

        with (
            mock.patch.object(entry, "read_config", return_value="{}"),
            mock.patch.object(entry, "parse_fetcher", return_value=self.cfg),
            mock.patch.object(entry, "fetcher_checks", return_value=results),
            mock.patch.object(entry, "github_checks") as github_checks,
            mock.patch("mission_fetcher.server.Refresher") as refresher,
            mock.patch.object(entry.os, "umask") as umask,
        ):
            refresher.return_value.run.return_value = b"ok\n"
            refresher.return_value.results = []
            code = entry.main(argv)
        return code, github_checks, refresher, umask

    def test_nothing_starts_unless_every_check_passes(self):
        from mission_fetcher.checks import Check

        failing = [Check("key file", False, "readable by others")]
        for command in (["serve", "--config", "x"], ["fetch-now", "--config", "x"]):
            with self.subTest(command[0]):
                code, _, refresher, _ = self.main_with(command, failing)
                self.assertEqual(code, 2)
                refresher.assert_not_called()
        code, github_checks, refresher, _ = self.main_with(
            ["selfcheck", "--github", "--config", "x"], failing
        )
        self.assertNotEqual(code, 0)
        github_checks.assert_not_called()
        refresher.assert_not_called()
        # A plain selfcheck asks GitHub nothing (160cc5a's sweep).
        passing = [Check("all", True, "yes")]
        code, _, refresher, _ = self.main_with(["selfcheck", "--config", "x"], passing)
        self.assertEqual(code, 0)
        refresher.assert_not_called()

    def test_fetch_now_writes_privately_and_reports_failure(self):
        from mission_fetcher.checks import Check

        code, _, refresher, umask = self.main_with(
            ["fetch-now", "--config", "x"], [Check("all", True, "yes")]
        )
        umask.assert_called_with(0o077)
        self.assertEqual(code, 0)
        refresher.return_value.run.return_value = b"failed:http-502\n"
        from mission_fetcher import __main__ as entry

        with (
            mock.patch.object(entry, "read_config", return_value="{}"),
            mock.patch.object(entry, "parse_fetcher", return_value=self.cfg),
            mock.patch.object(entry, "fetcher_checks", return_value=[Check("all", True, "yes")]),
            mock.patch("mission_fetcher.server.Refresher") as failing,
            mock.patch.object(entry.os, "umask"),
        ):
            failing.return_value.run.return_value = b"failed:http-502\n"
            self.assertNotEqual(entry.main(["fetch-now", "--config", "x"]), 0)

    def test_the_github_selfcheck_keeps_the_floor_and_records_its_attempt(self):
        refresher = RefresherFiles.make(self, lambda: NOW.timestamp())
        calls = []
        self.assertEqual(refresher.run(lambda: calls.append(1) or []), server.OK)
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual(status["result"], "selfcheck")
        again = RefresherFiles.make(self, lambda: NOW.timestamp() + 5)
        self.assertEqual(again.run(lambda: calls.append(1) or []), server.TOO_SOON)
        self.assertEqual(calls, [1])  # no GitHub work within the minute

    def test_small_guards(self):
        github = client(FakeGitHub())
        with self.assertRaises(gh.FetchError) as caught:
            github.call("GET", "//evil", TOKEN)
        self.assertEqual(caught.exception.code, "bad-path")
        fake = FakeGitHub()
        fake_token = fake.__call__

        def short_token(method, path, headers, body):
            status, h, data = fake_token(method, path, headers, body)
            if path.endswith("/access_tokens"):
                answer = json.loads(data)
                answer["token"] = "short"  # noqa: S105 - a malformed test token
                data = json.dumps(answer).encode()
            return status, h, data

        bad = gh.GitHub(APP_ID, KEY, transport=short_token, clock=lambda: NOW.timestamp())
        with self.assertRaises(gh.FetchError):
            bad.token(bad.installation(OWNER, [REPO_A, REPO_B]))
        big = self.base / "big.pem"
        big.write_bytes(b"x" * (server.MAX_KEY + 1))
        with self.assertRaises(gh.FetchError) as caught:
            server.read_key(big)
        self.assertEqual(caught.exception.code, "key-unreadable")
        data = config_data(self.base)
        data["repos"][REPO_A]["required_checks"] = []
        with self.assertRaises(fconfig.ConfigError):
            fconfig.parse_fetcher(json.dumps(data))


class AuditOf24973b8(Base):
    def selfcheck(self, transport):
        from mission_fetcher import __main__ as entry
        from mission_fetcher.checks import Check

        github = gh.GitHub(APP_ID, KEY, transport=transport, clock=lambda: NOW.timestamp())

        class Steady(server.Refresher):
            """The real Refresher on a fixed time since boot: the default is bound at class
            definition, and a fresh machine's uptime would trip the floor (audit of b69faa7)."""

            def __init__(self, cfg):
                super().__init__(cfg, boot=lambda: (None, 10_000.0 + len(boots)))
                boots.append(1)

        boots = getattr(self, "_boots", [])
        self._boots = boots
        with (
            mock.patch.object(server, "Refresher", Steady),
            mock.patch.object(entry, "read_config", return_value="{}"),
            mock.patch.object(entry, "parse_fetcher", return_value=self.cfg),
            mock.patch.object(entry, "fetcher_checks", return_value=[Check("all", True, "yes")]),
            mock.patch("mission_fetcher.server.github_for", return_value=github),
            mock.patch.object(entry.os, "umask"),
            mock.patch("sys.stdout", new_callable=__import__("io").StringIO) as out,
        ):
            code = entry.main(["selfcheck", "--github", "--config", "x"])
        return code, out.getvalue()

    def test_the_github_selfcheck_goes_through_the_refresher(self):
        fake = FakeGitHub()
        first = []

        def transport(method, path, headers, body):
            if not first:  # the attempt is on record before the first request
                first.append(snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS))
            return fake(method, path, headers, body)

        code, out = self.selfcheck(transport)
        self.assertEqual(code, 0, out)
        self.assertEqual(first[0]["result"], "running")
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual(status["result"], "selfcheck")
        code, out = self.selfcheck(transport)  # within the minute
        self.assertEqual(code, 1)
        self.assertIn("too-soon", out)

    def test_a_failing_selfcheck_is_a_failure_on_record(self):
        fake = FakeGitHub()
        fake.permissions = dict(gh.EXPECTED_PERMISSIONS, contents="write")
        previous = {
            "boot_id": None,
            "attempt_since_boot": 0,
            "attempt_epoch": 0,
            "attempt_at": NOW.isoformat(),
            "snapshot_at": None,
            "result": "failed",
            "reason": "not-read-only",
            "last_refresh": {"result": "failed", "reason": "not-read-only", "at": NOW.isoformat()},
        }
        snapshot.write_json(self.cfg.snapshot_dir, snapshot.STATUS, previous)
        code, out = self.selfcheck(fake)
        self.assertEqual(code, 1, out)
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual(status["result"], "failed")
        self.assertTrue(status["reason"].startswith("selfcheck-failed"))
        self.assertEqual(status["last_refresh"]["reason"], "not-read-only")  # never erased


class AuditOfB69faa7(Base):
    def refresher(self, minute=0, fake=None):
        return server.Refresher(
            self.cfg,
            github=lambda cfg: client(fake or FakeGitHub()),
            clock=lambda: NOW.timestamp() + 60 * minute,
            boot=lambda: ("boot-1", 1000.0 + 60 * minute),
        )

    def status(self):
        return snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)

    def test_every_refresh_writes_its_outcome_and_selfchecks_keep_it(self):
        self.assertEqual(self.refresher(0).run(), server.OK)
        self.assertEqual(self.status()["last_refresh"]["result"], "ok")
        fake = FakeGitHub()
        fake.fail["/graphql"] = (502, {}, b"")
        self.assertNotEqual(self.refresher(2, fake).run(), server.OK)
        kept = self.status()["last_refresh"]
        self.assertEqual((kept["result"], kept["reason"]), ("failed", "http-502"))
        for minute in (4, 6):  # two selfchecks after it
            self.refresher(minute).run(lambda: [])
            self.assertEqual(self.status()["last_refresh"], kept)

    def test_a_wrongly_shaped_last_refresh_is_never_carried_over(self):
        good = {"result": "failed", "reason": "http-502", "at": NOW.isoformat()}
        self.assertEqual(server._last_refresh({"last_refresh": good}), good)
        for bad in (
            dict(good, extra=1),
            dict(good, reason=7),
            dict(good, reason="x" * 65),
            dict(good, reason="<script>\u202e"),
            dict(good, at="not a time \u001b[31m"),
            dict(good, result="maybe"),
            dict(good, result="ok"),  # ok with a failure reason
            dict(good, reason=None),  # failed with no reason
            "text",
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(server._last_refresh({"last_refresh": bad}))

    def test_a_malformed_status_says_the_last_refresh_is_not_known(self):
        (self.cfg.snapshot_dir / snapshot.STATUS).write_text("[]")
        self.assertEqual(self.refresher(0).run(), b"failed:status\n")
        self.assertIn("last_refresh", self.status())
        self.assertIsNone(self.status()["last_refresh"])

    def test_a_refused_token_whose_revoke_failed_is_on_record(self):
        from mission_fetcher.__main__ import github_checks

        fake = FakeGitHub()
        fake.token_permissions = dict(gh.EXPECTED_PERMISSIONS, contents="write")
        fake.fail["/installation/token"] = (500, {}, b"")
        refresher = self.refresher(0)
        reply = refresher.run(lambda: github_checks(self.cfg, client(fake)))
        self.assertEqual(reply, b"failed:selfcheck-failed+token-not-revoked\n")
        self.assertEqual(self.status()["reason"], "selfcheck-failed+token-not-revoked")
        fake.token_permissions = gh.EXPECTED_PERMISSIONS  # every check passes but the revoke
        reply = self.refresher(1).run(lambda: github_checks(self.cfg, client(fake)))
        self.assertEqual(reply, b"failed:selfcheck-failed+token-not-revoked\n")


class NoFifoAnywhere(Base):
    """Codex's review of b1fef32: a FIFO in a file's place can never hang a read."""

    def refused_promptly(self, read):
        outcome = []

        def go():
            try:
                read()
                outcome.append("read")
            except (OSError, ValueError, gh.FetchError) as error:
                outcome.append(type(error).__name__)

        worker = threading.Thread(target=go, daemon=True)
        worker.start()
        worker.join(5)
        self.assertFalse(worker.is_alive(), "the read hung")
        self.assertNotIn("read", outcome)
        return outcome

    def test_a_fifo_is_never_read(self):
        from mission_fetcher.__main__ import read_config

        fifo = self.base / "fifo"
        os.mkfifo(fifo)
        self.refused_promptly(lambda: read_config(str(fifo)))
        self.assertEqual(self.refused_promptly(lambda: server.read_key(fifo)), ["FetchError"])
        self.refused_promptly(lambda: snapshot.read_json(self.base, "fifo", strict=True))
        self.assertIsNone(snapshot.read_json(self.base, "fifo"))

    def test_a_folder_is_never_read_as_a_file(self):
        folder = self.base / "folder"
        folder.mkdir()
        with self.assertRaises(OSError):
            os.close(snapshot.open_regular(folder))


class AuditOf8c62413(unittest.TestCase):
    def test_the_floor_is_measured_on_the_boot_clock(self):
        asked = []

        def clock_gettime(which):
            asked.append(which)
            return 42.0

        with mock.patch.object(server.time, "clock_gettime", clock_gettime):
            self.assertEqual(server.boot_clock()[1], 42.0)
        self.assertEqual(asked, [time.CLOCK_BOOTTIME])


class CodexReviewOfB7d0915(Base):
    """SIGTERM mid-refresh: the refresh ends as an ordinary failure, then the process."""

    make = RefresherFiles.make

    def setUp(self):
        super().setUp()
        self.addCleanup(gh.STOPPING.clear)

    def stop_at(self, when):
        fake = self.fake

        def transport(method, path, headers, body):
            if path.startswith(when):
                gh.STOPPING.set()
            return fake(method, path, headers, body)

        self.fake = transport
        return fake

    def test_a_stop_mid_refresh_fails_it_revokes_the_token_and_keeps_the_snapshot(self):
        now = [NOW.timestamp()]
        refresher = self.make(lambda: now[0])
        self.assertEqual(refresher.run(), server.OK)
        good = (self.cfg.snapshot_dir / snapshot.SNAPSHOT).read_bytes()
        now[0] += 120
        fake = self.stop_at("/graphql")
        self.assertEqual(refresher.run(), b"failed:interrupted\n")
        self.assertEqual(fake.calls[-1], ("DELETE", "/installation/token"))
        self.assertEqual((self.cfg.snapshot_dir / snapshot.SNAPSHOT).read_bytes(), good)
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual((status["result"], status["reason"]), ("failed", "interrupted"))
        self.assertEqual(status["last_refresh"]["reason"], "interrupted")

    def test_a_stop_as_the_last_read_is_answered_still_fails_the_refresh(self):
        # Only the check after every request can catch it (Fable's pre-review of cd6c441).
        now = [NOW.timestamp()]
        refresher = self.make(lambda: now[0])
        self.assertEqual(refresher.run(), server.OK)
        reads = sum(path == "/graphql" for _, path in self.fake.calls)
        good = (self.cfg.snapshot_dir / snapshot.SNAPSHOT).read_bytes()
        fake, seen = self.fake, []

        def transport(method, path, headers, body):
            answer = fake(method, path, headers, body)
            seen.append(path)
            if seen.count("/graphql") == reads and path == "/graphql":
                gh.STOPPING.set()
            return answer

        self.fake = transport
        now[0] += 120
        self.assertEqual(refresher.run(), b"failed:interrupted\n")
        self.assertEqual(seen[-1], "/installation/token")
        self.assertEqual((self.cfg.snapshot_dir / snapshot.SNAPSHOT).read_bytes(), good)

    def test_a_real_sigterm_mid_refresh_ends_the_process_after_revoking(self):
        code = (
            "from tests import test_fetcher_service as t\n"
            "from mission_fetcher import __main__ as entry\n"
            "case = t.CodexReviewOfB7d0915('test_the_service_loop_ends_after_a_stop')\n"
            "case.setUp(); fake = case.fake\n"
            "def transport(method, path, headers, body):\n"
            "    if path == '/graphql' and not fake.calls.count(('POST', '/graphql')):\n"
            "        print('reading', flush=True); t.gh.STOPPING.wait(30)\n"
            "    return fake(method, path, headers, body)\n"
            "case.fake = transport\n"
            "print(case.cfg.snapshot_dir, flush=True)\n"
            "refresher = case.make(lambda: t.NOW.timestamp())\n"
            "entry._main = lambda argv: print(refresher.run(), fake.calls[-1]) or 0\n"
            "entry.main([])\n"
        )
        root = Path(__file__).resolve().parent.parent
        # The child's files go inside this test's own folder, removed with it (Codex, 0f323f6).
        env = dict(os.environ, TMPDIR=str(self.base))
        child = subprocess.Popen(
            [sys.executable, "-c", code], cwd=root, env=env, stdout=subprocess.PIPE, text=True
        )
        self.addCleanup(child.stdout.close)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)  # never left running, whatever fails
        # One thread reads every line into a queue; each wait is 30 s at most (Codex, d99b49a).
        lines: queue.Queue = queue.Queue()

        def pump():
            for text in child.stdout:
                lines.put(text.strip())
            lines.put(None)

        threading.Thread(target=pump, daemon=True).start()
        folder = Path(lines.get(timeout=30))
        self.assertTrue(folder.is_absolute() and folder.is_relative_to(self.base), folder)
        self.assertEqual(lines.get(timeout=30), "reading")
        child.send_signal(signal.SIGTERM)
        self.assertEqual(child.wait(timeout=60), -signal.SIGTERM)
        out = list(iter(lambda: lines.get(timeout=30), None))
        out = "\n".join(out)
        self.assertIn("b'failed:interrupted\\n' ('DELETE', '/installation/token')", out)
        status = snapshot.read_json(folder, snapshot.STATUS)
        self.assertEqual((status["result"], status["reason"]), ("failed", "interrupted"))

    def test_a_stop_mid_refresh_says_when_the_token_outlived_it(self):
        fake = self.stop_at("/graphql")
        fake.fail["/installation/token"] = (500, {}, b"")
        reply = self.make(lambda: NOW.timestamp()).run()
        self.assertEqual(reply, b"failed:interrupted+token-not-revoked\n")

    def test_a_stop_during_the_revocation_never_cuts_it_off(self):
        fake = self.stop_at("/installation/token")
        self.assertEqual(self.make(lambda: NOW.timestamp()).run(), server.OK)
        self.assertEqual(fake.revoked, 1)
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual((status["result"], status["reason"]), ("ok", None))

    def test_a_stopped_selfcheck_keeps_the_last_refresh_and_revokes(self):
        now = [NOW.timestamp()]
        refresher = self.make(lambda: now[0])
        self.assertEqual(refresher.run(), server.OK)
        now[0] += 120
        fake = self.stop_at("/app/installations/")

        def work():
            github = gh.GitHub(APP_ID, KEY, transport=self.fake, clock=lambda: now[0])
            return github_checks(self.cfg, github)

        self.assertEqual(refresher.run(work), b"failed:selfcheck-failed\n")
        self.assertEqual(fake.calls[-1], ("DELETE", "/installation/token"))
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual(status["last_refresh"]["result"], "ok")

    def test_sigterm_ends_at_once_when_idle_and_after_the_refresh_otherwise(self):
        before = signal.signal(signal.SIGTERM, entry._on_sigterm)
        killed = []
        with mock.patch.object(entry.signal, "raise_signal", killed.append):
            server.ACTIVE.set()
            try:
                entry._on_sigterm(signal.SIGTERM, None)
            finally:
                server.ACTIVE.clear()
            self.assertEqual(killed, [])  # mid-refresh: only marked
            self.assertTrue(gh.STOPPING.is_set())
            self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)  # a second one ends
            entry._on_sigterm(signal.SIGTERM, None)
            self.assertEqual(killed, [signal.SIGTERM])  # idle: now
        signal.signal(signal.SIGTERM, before)

    def test_main_ends_by_the_signal_once_a_stop_was_asked_and_restores_the_handler(self):
        before = signal.getsignal(signal.SIGTERM)
        seen, killed = [], []

        def fake_main(argv):
            seen.append(signal.getsignal(signal.SIGTERM))
            gh.STOPPING.set()
            return 0

        with mock.patch.object(entry, "_main", lambda argv: 0):
            entry.main([])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)  # restored
        with (
            mock.patch.object(entry, "_main", fake_main),
            mock.patch.object(entry.signal, "raise_signal", killed.append),
        ):
            entry.main([])
        self.assertEqual((seen, killed), ([entry._on_sigterm], [signal.SIGTERM]))
        signal.signal(signal.SIGTERM, before)

    def test_the_service_loop_ends_after_a_stop(self):
        class Listener:
            def accept(self):
                if gh.STOPPING.is_set():
                    raise AssertionError("served on after the stop")
                gh.STOPPING.set()
                a, b = socket.socketpair()
                b.close()
                return a, None

        server.serve(
            Listener(), self.make(lambda: NOW.timestamp()), os.getuid(), log=lambda _: None
        )


if __name__ == "__main__":
    unittest.main()
