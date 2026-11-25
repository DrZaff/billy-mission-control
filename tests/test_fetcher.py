"""Phase A5a (issue #16): the fetcher, against a fake GitHub. No network: every response is
synthetic, and the App's key is generated at run time, never committed."""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import threading
import time
import unittest
from datetime import UTC, timedelta
from unittest import mock

from cryptography.hazmat.primitives import serialization

from mission_control import tasks, views
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
    SHA1,
    SHA2,
    TOKEN,
    Base,
    FakeGitHub,
    client,
    config_data,
    issue_node,
    make_cfg,
    pr_node,
    review_node,
)

# ---------------------------------------------------------------- config


# ---------------------------------------------------------------- the App on GitHub


# ---------------------------------------------------------------- one refresh


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


class Refresh(Base):
    def run_refresh(self):
        return snapshot.refresh(self.cfg, client(self.fake), NOW)

    def reviewed(self, item):
        """The item's task with a synthetic finished build and passing review of its head:
        the state where the model weighs the required checks before the owner merges."""
        task = self.task_of(item)
        branch, sha = task["branch"]["name"], task["branch"]["head"]
        repo = task["repo"]
        task["runs"] = [
            {
                "step": "build",
                "repo": repo,
                "branch": branch,
                "sha": sha,
                "at": "2026-11-21T10:00:00+00:00",
                "status": "finished",
            },
            {
                "step": "review",
                "repo": repo,
                "branch": branch,
                "sha": sha,
                "at": "2026-11-21T11:00:00+00:00",
                "status": "finished",
                "verdict": "no_blocking_findings",
                "findings": [],
            },
        ]
        return task

    def task_of(self, item):
        return dict(item["task"], paused=False)  # A5b adds paused from the stop marker

    def test_the_snapshot_feeds_the_task_model(self):
        snap = self.run_refresh()
        self.assertEqual(snap["repos"], [REPO_A, REPO_B])
        self.assertEqual(
            [i["id"] for i in snap["items"]], [f"{REPO_A}#1", f"{REPO_A}#2", f"{REPO_B}#3"]
        )
        linked = [i for i in snap["items"] if i["linked_issues"] == 1]
        self.assertEqual(len(linked), 2)
        for item in linked:
            tasks.parse(self.task_of(item))  # passes the model's input checks
            self.assertNotEqual(tasks.derive(self.task_of(item)).state, tasks.State.UNKNOWN)
            self.assertIsNone(item["task"]["runs"])  # not read; never "no review"
        unlinked = next(i for i in snap["items"] if i["id"] == f"{REPO_A}#2")
        self.assertIsNone(unlinked["task"]["issue"])
        self.assertEqual(tasks.derive(self.task_of(unlinked)).state, tasks.State.NOT_LINKED)
        self.assertEqual(self.fake.revoked, 1)

    def test_settings_and_links_come_from_the_config_and_the_fetcher(self):
        snap = self.run_refresh()
        item = snap["items"][0]
        self.assertEqual(item["url"], f"https://github.com/{REPO_A}/pull/1")
        self.assertEqual(item["issue"]["url"], f"https://github.com/{REPO_A}/issues/10")
        self.assertEqual(item["task"]["required_checks"], ["lint", "test"])
        self.assertEqual(item["task"]["clinical_paths"], ["evidence/*"])
        self.assertEqual(item["task"]["owner"], OWNER)

    def test_untrusted_text_is_cleaned_and_capped(self):
        self.fake.prs[REPO_A]["open"][0]["title"] = "Fix‮\x00 the\nthing " + "x" * 500
        title = self.run_refresh()["items"][0]["title"]
        self.assertTrue(title.startswith("Fix the thing "))
        self.assertLessEqual(len(title), snapshot.MAX_TITLE)
        self.assertNotIn("‮", title)

    def test_recently_closed_pull_requests_only(self):
        recent = (NOW - timedelta(days=3)).isoformat()
        old = (NOW - timedelta(days=20)).isoformat()
        self.fake.prs[REPO_B]["closed"] = [
            pr_node(4, state="MERGED", merged=True, closed_at=recent),
            pr_node(5, state="CLOSED", closed_at=old),
        ]
        ids = [i["id"] for i in self.run_refresh()["items"]]
        self.assertIn(f"{REPO_B}#4", ids)
        self.assertNotIn(f"{REPO_B}#5", ids)

    def test_an_incomplete_part_is_left_out_so_the_model_says_unknown(self):
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("a",), files_total=500
        )
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["task"]["pull_request"]["files"], ["a"])  # the known part
        self.assertIs(item["task"]["pull_request"]["files_complete"], False)
        state = tasks.derive(self.reviewed(item))
        # Unknown files may be clinical: a reviewed PR waits for a clinician, never "ready".
        self.assertEqual(state.state, tasks.State.CLINICAL_REVIEW)
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, state.flags)
        self.assertNotIn(tasks.Flag.CLINICAL, state.flags)  # and isn't claimed to be clinical

    def test_several_closing_issues_give_no_guess(self):
        node = pr_node(1)
        node["closingIssuesReferences"] = {
            "totalCount": 2,
            "nodes": [issue_node(10), issue_node(12)],
        }
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["linked_issues"], 2)
        self.assertIsNone(item["task"]["issue"])

    def test_paths_are_kept_exactly_so_clinical_rules_still_match(self):
        # Codex's review of f772122 (blocking): cleaning collapsed distinct paths, and a path
        # covered by a clinical rule could lose its match.
        paths = ("evidence/a  b.md", "evidence/a b.md", "evidence/\u202ex.md", "site/x\ty.html")
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10), files=paths)
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["task"]["pull_request"]["files"], list(paths))
        state = tasks.derive(self.task_of(item))
        self.assertIn(tasks.Flag.CLINICAL, state.flags)

    def test_a_label_name_is_never_cleaned_into_the_authorisation_label(self):
        # Codex's review of 1cc6cf8 (blocking): cleaning "agent:ready " (or one with a control
        # character) gave "agent:ready", an authorisation.
        for name in ("agent:ready ", "agent:ready\u200b", "agent:\x01ready", " agent:ready"):
            with self.subTest(name=repr(name)):
                self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10, label=name))
                item = self.run_refresh()["items"][0]
                labels = [e["label"] for e in item["task"].get("issue", {}).get("timeline", [])]
                self.assertNotIn("agent:ready", labels)
                self.assertEqual(tasks.derive(self.task_of(item)).state, tasks.State.UNSAFE)

    def test_check_names_are_matched_exactly(self):
        # Codex's review of 1cc6cf8 (blocking): cleaning made " lint" satisfy "lint", and kept
        # a configured name with doubled spaces from ever matching. An open pull request with a
        # passing review is where the model weighs the required checks.
        for required, ran, flag in (
            ("unit  tests", "unit  tests", tasks.Flag.CHECKS_PASSED),
            ("lint", " lint", tasks.Flag.CHECKS_MISSING),
            ("lint", "lint\u200b", tasks.Flag.CHECKS_MISSING),
            ("lint", "lint", tasks.Flag.CHECKS_PASSED),
        ):
            with self.subTest(required=required, ran=repr(ran)):
                data = config_data(self.base)
                data["repos"][REPO_A]["required_checks"] = [required]
                self.cfg = fconfig.parse_fetcher(json.dumps(data))
                self.fake.prs[REPO_A]["closed"] = []
                self.fake.prs[REPO_A]["open"] = [
                    pr_node(
                        1,
                        issue=issue_node(10),
                        checks=(ran,),
                    )
                ]
                item = self.run_refresh()["items"][0]
                names = [c["name"] for c in item["task"]["pull_request"]["checks"]]
                # Exactly the required name is kept, verbatim; a lookalike is never kept
                # (dc1eb14: only required names are).
                self.assertEqual(names, [ran] if ran == required else [])
                self.assertIn(flag, tasks.derive(self.reviewed(item)).flags)

    def test_only_the_configured_apps_checks_count(self):
        # Codex's review of bf76866 (blocking): a same-named check from another app could pass a
        # required check.
        for app, flag in (
            ("github-actions", tasks.Flag.CHECKS_PASSED),
            ("someone-elses-app", tasks.Flag.CHECKS_MISSING),
        ):
            with self.subTest(app=app):
                self.fake.prs[REPO_A]["closed"] = []
                self.fake.prs[REPO_A]["open"] = [
                    pr_node(
                        1,
                        issue=issue_node(10),
                        checks_app=app,
                    )
                ]
                item = self.run_refresh()["items"][0]
                self.assertIn(flag, tasks.derive(self.reviewed(item)).flags)

    def test_results_on_the_test_merge_commit_leave_the_checks_out(self):
        # Codex's review of 23bfb61 (blocking): GitHub judges the test merge commit when it has
        # results; reading only the head could look greener than GitHub.
        clean = {"oid": SHA2, "status": None, "checkSuites": {"totalCount": 0}}
        with_status = dict(clean, status={"contexts": [{"context": "ci/other"}]})
        with_suite = dict(clean, checkSuites={"totalCount": 1})
        for merge, has_checks in (
            (None, True),
            (clean, True),
            (with_status, False),
            (with_suite, False),
        ):
            with self.subTest(merge=merge):
                self.fake.prs[REPO_A]["open"][0] = pr_node(
                    1, issue=issue_node(10), merge_commit=merge
                )
                item = self.run_refresh()["items"][0]
                pull = item["task"]["pull_request"]
                # Results on the test merge commit make the head's partial: never passed.
                self.assertEqual(pull.get("checks_complete", True), has_checks)
                passed = tasks.Flag.CHECKS_PASSED in tasks.derive(self.reviewed(item)).flags
                self.assertEqual(passed, has_checks)

    def test_a_commit_status_can_only_add_caution(self):
        # Codex's review of ab64500 (blocking): when a status and a check run share a required
        # name, GitHub needs both to pass. A status that isn't a success counts against the name;
        # a successful one never makes a check pass.
        for checks, statuses, flag in (
            (("lint", "test"), [("lint", "FAILURE")], tasks.Flag.CHECKS_FAILING),
            (("lint", "test"), [("lint", "ERROR")], tasks.Flag.CHECKS_FAILING),
            (("lint", "test"), [("lint", "PENDING")], tasks.Flag.CHECKS_PENDING),
            (("lint", "test"), [("lint", "SUCCESS")], tasks.Flag.CHECKS_PASSED),
            (("test",), [("lint", "SUCCESS")], tasks.Flag.CHECKS_MISSING),
            (("lint", "test"), [("deploy/preview", "FAILURE")], tasks.Flag.CHECKS_PASSED),
        ):
            with self.subTest(checks=checks, statuses=statuses):
                self.fake.prs[REPO_A]["closed"] = []
                self.fake.prs[REPO_A]["open"] = [
                    pr_node(
                        1,
                        issue=issue_node(10),
                        checks=checks,
                        statuses=statuses,
                    )
                ]
                item = self.run_refresh()["items"][0]
                self.assertIn(flag, tasks.derive(self.reviewed(item)).flags)

    def test_an_internal_error_also_says_when_the_token_outlived_it(self):
        # Codex's review of ab64500: only a FetchError carried the failed-revoke warning.
        self.fake.fail["/graphql"] = ValueError("a surprise")
        self.fake.fail["/installation/token"] = (500, {}, b"")
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, "internal+token-not-revoked")

    def test_a_malformed_check_status_makes_that_pr_unreadable(self):
        # Codex's review of 23bfb61: an unhashable status raised TypeError and stopped the
        # fetcher. Since de9a6fb it makes that one pull request unreadable (UNKNOWN), and the
        # rest are still read.
        node = pr_node(1, issue=issue_node(10))
        suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["checkRuns"]["nodes"][0]["status"] = ["COMPLETED"]
        self.fake.prs[REPO_A]["open"][0] = node
        items = self.run_refresh()["items"]
        bad = next(i for i in items if i["number"] == 1)
        # Since 7faf35a only that part is "not known"; since 4945de9 the checks are kept as
        # partial (a failure would still count), and they never pass.
        self.assertIs(bad["task"]["pull_request"]["checks_complete"], False)
        flags = tasks.derive(self.task_of(bad)).flags
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, flags)
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)
        self.assertEqual([i["number"] for i in items], [1, 2, 3])

    def test_a_field_error_on_one_pr_never_stalls_the_others(self):
        # Codex's review of de9a6fb (blocking): a GraphQL error on one pull request's field
        # discarded the whole answer and failed the refresh for every repository.
        self.fake.prs[REPO_A]["open"] = [pr_node(n, issue=issue_node(10)) for n in range(1, 8)]
        real = self.fake.__call__

        def call(method, path, headers, body):
            if path == "/graphql" and b"pullRequest(number: 4)" in body:
                errors = [{"type": "SOMETHING", "path": ["repository", "p0", "files"]}]
                return 200, {}, json.dumps({"data": None, "errors": errors}).encode()
            return real(method, path, headers, body)

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        items = [i for i in snapshot.refresh(self.cfg, github, NOW)["items"] if i["repo"] == REPO_A]
        self.assertEqual([i["number"] for i in items], list(range(1, 8)))
        for item in items:
            if item["number"] == 4:
                self.assertIsNone(item["task"])  # unreadable: UNKNOWN
            else:
                self.assertEqual(item["task"]["pull_request"]["files"], ["site/a.html"])

    def test_a_pr_missing_from_githubs_answer_is_never_silently_dropped(self):
        # Codex's review of 48929aa (blocking).
        self.fake.prs[REPO_A]["open"] = [pr_node(n, issue=issue_node(10)) for n in range(1, 4)]
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number: 2)" in body:
                answer = json.loads(data)
                answer["data"]["repository"] = {
                    k: v for k, v in answer["data"]["repository"].items() if v and v["number"] != 2
                }
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        items = [i for i in snapshot.refresh(self.cfg, github, NOW)["items"] if i["repo"] == REPO_A]
        self.assertEqual([i["number"] for i in items], [1, 2, 3])
        self.assertIsNone(next(i for i in items if i["number"] == 2)["task"])  # unreadable

    def test_any_wrongly_shaped_value_makes_only_that_pr_unreadable(self):
        # Codex's review of 48929aa (blocking): an unhashable review state raised TypeError.
        bad_review = review_node()
        bad_review["state"] = ["APPROVED"]
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10), reviews=[bad_review])
        items = self.run_refresh()["items"]
        self.assertEqual([i["number"] for i in items], [1, 2, 3])
        self.assertIsNone(items[0]["task"]["pull_request"]["reviews"])  # that part: not known
        self.assertIsNotNone(items[1]["task"]["pull_request"]["reviews"])

    def test_a_query_wide_graphql_error_fails_the_refresh(self):
        # Codex's review of 7faf35a (blocking): an error about the whole query (no place in
        # the answer) made every pull request unreadable while the refresh reported success.
        real = self.fake.__call__

        def call(method, path, headers, body):
            if path == "/graphql" and b"pullRequest(number:" in body:
                errors = [{"type": "FORBIDDEN", "message": "x"}]
                return 200, {}, json.dumps({"data": None, "errors": errors}).encode()
            return real(method, path, headers, body)

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        with self.assertRaises(gh.FetchError) as caught:
            snapshot.refresh(self.cfg, github, NOW)
        self.assertEqual(caught.exception.code, "graphql-error")

    def test_every_pr_unreadable_fails_rather_than_replacing_the_snapshot(self):
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number:" in body:
                answer = json.loads(data)
                answer["data"]["repository"] = {}
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        with self.assertRaises(gh.FetchError) as caught:
            snapshot.refresh(self.cfg, github, NOW)
        self.assertEqual(caught.exception.code, "bad-response")

    def with_field_errors(self, errors_for, extra=()):
        """A GitHub whose detail answers are partial, as GitHub's are: each field named in
        `errors_for` (number -> fields) is null, with an error whose path locates it."""
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number:" in body:
                answer = json.loads(data)
                errors = list(extra)
                for alias, node in answer["data"]["repository"].items():
                    for field in errors_for.get(node["number"], ()):
                        if field in node:  # the lite query doesn't ask for every field
                            node[field] = None
                            errors.append(
                                {
                                    "type": "SERVICE_UNAVAILABLE",
                                    "path": ["repository", alias, field],
                                }
                            )
                if errors:
                    answer["errors"] = errors
                    data = json.dumps(answer).encode()
            return status, h, data

        return gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())

    # ------------------------------------------------ Fable's pre-review of 8152df0

    def test_cutting_the_snapshot_never_drops_an_unsafe_merge_for_strangers_lists(self):
        # Finding 1: long clinical-looking paths kept strangers' lists while a known unsafe
        # merge was cut as an old closed item.
        recent = (NOW - timedelta(days=12)).isoformat()
        merge = pr_node(5, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        merge["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        long = ("evidence/" + "\x01" * 1000,)
        self.fake.prs[REPO_A]["open"] = [
            pr_node(100 + n, issue=issue_node(10), files=long) for n in range(12)
        ]
        self.fake.prs[REPO_A]["closed"] = [merge]
        full = len(snapshot.encode(self.run_refresh()))
        saved = snapshot.MAX_SNAPSHOT
        snapshot.MAX_SNAPSHOT = full - 20000
        try:
            snap = self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        kept = next(i for i in snap["items"] if i["number"] == 5)
        self.assertEqual(tasks.derive(self.task_of(kept)).state, tasks.State.UNSAFE)
        for item in snap["items"]:  # a cut list never keeps a long path as its clinical one
            pull = item["task"]["pull_request"] if item["task"] else {}
            if pull.get("files") and pull.get("files_complete") is False:
                self.assertTrue(all(len(json.dumps(f)) <= 512 for f in pull["files"]))
        self.assertEqual(snapshot._compact(list(long), ("evidence/*",)), None)
        self.assertEqual(
            snapshot._compact([long[0], "evidence/a.json"], ("evidence/*",)), ["evidence/a.json"]
        )

    def test_cutting_a_list_never_erases_that_it_was_clinical(self):
        # Codex's review of 9dbb868 (blocking): a clinical path over 512 bytes as written, or
        # the step that nulls every list, erased the evidence, and with it the warning that
        # clinical files were merged without a clinician.
        recent = (NOW - timedelta(days=1)).isoformat()
        long_clinical = "evidence/" + "\u00e9" * 3000  # ~18 KB as written: over the cap
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=recent,
            issue=issue_node(10),
            files=(long_clinical,),
        )
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        item = self.run_refresh()["items"][0]
        pull = item["task"]["pull_request"]
        self.assertIsNone(pull["files"])
        self.assertIs(pull["clinical_known"], True)
        state = tasks.derive(self.task_of(item))
        self.assertIn(tasks.Flag.CLINICAL, state.flags)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)
        # The same through the step that nulls every remaining list.
        snap = {
            "items": [
                {
                    "task": {
                        "clinical_paths": ["evidence/*"],
                        "pull_request": {"files": ["evidence/a.json"]},
                    }
                }
            ]
        }
        snapshot._cut(snap["items"][0]["task"]["pull_request"], ("evidence/*",), False)
        self.assertEqual(
            snap["items"][0]["task"]["pull_request"], {"files": None, "clinical_known": True}
        )

    def test_a_request_that_ends_past_the_time_limit_fails_the_refresh(self):
        # Codex's review of 9dbb868: the limit was checked only before detail requests.
        times = iter([0.0] + [10_000.0] * 1000)  # the start, then everything is too late
        with mock.patch.object(snapshot.time, "monotonic", side_effect=lambda: next(times)):
            with self.assertRaises(gh.FetchError) as caught:
                self.run_refresh()
        self.assertEqual(caught.exception.code, "too-slow")

    def test_item_ids_are_unique_across_owners(self):
        # Codex's review of 0cf099c: IDs held the short name only.
        self.assertNotEqual(
            snapshot._unreadable("one/site", 1)["id"], snapshot._unreadable("two/site", 1)["id"]
        )
        self.assertEqual(self.run_refresh()["items"][0]["id"], f"{REPO_A}#1")

    def test_a_slow_drip_answer_is_cut_off_by_the_request_limit(self):
        # Codex's review of 9dbb868, and Fable's pre-review of a21bd27: a check between reads
        # never ran, since one read (or the headers) can drip a byte at a time. A real
        # loopback server drips here; the watchdog must end the request near the limit.
        import http.client as hc
        import socket as so
        import threading as th
        import time as tm

        def serve(listener, prefix):
            conn, _ = listener.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(prefix)
                ends = tm.monotonic() + 5
                while tm.monotonic() < ends:
                    try:
                        conn.sendall(b"x")
                    except OSError:
                        return
                    tm.sleep(0.05)

        headers_then_body = b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"
        closing = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 100000\r\n\r\n"
        for name, prefix in (
            ("headers", b"HTTP/1.1 200 OK\r\nX-Slow: "),
            ("body", headers_then_body),
            # The connection lets go of its socket for "Connection: close" (Codex's review of
            # d75f891); the watchdog must still reach it.
            ("body after Connection: close", closing),
        ):
            with self.subTest(drip=name):
                listener = so.socket(so.AF_INET, so.SOCK_STREAM)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                port = listener.getsockname()[1]
                th.Thread(target=serve, args=(listener, prefix), daemon=True).start()

                class Plain(hc.HTTPConnection):
                    """Plain HTTP to the local server, handing its socket over as the real
                    connection class does."""

                    def __init__(self, held, expired, host, p, timeout, context, port=port):
                        super().__init__("127.0.0.1", port, timeout=timeout)
                        self._held = held

                    def connect(self):
                        super().connect()
                        self._held.append(self.sock)

                started = tm.monotonic()
                limit = gh._LIMIT.set(0.5)  # as GitHub.call sets it for each request
                try:
                    with mock.patch.object(gh, "_Connection", Plain):
                        with self.assertRaises(gh.FetchError) as caught:
                            gh.https_transport("GET", "/x", {}, None)
                finally:
                    gh._LIMIT.reset(limit)
                listener.close()
                self.assertEqual(caught.exception.code, "timeout")
                self.assertLess(tm.monotonic() - started, 3)  # not the 5 s drip

    # ------------------------------------------------ Fable's pre-review of a21bd27

    def test_an_unsafe_merge_is_cut_last_after_any_number_of_fork_prs(self):
        # Finding 2: fork PRs (attention) outranked a known unsafe merge when items were cut.
        recent = (NOW - timedelta(days=3)).isoformat()
        merge = pr_node(900, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        merge["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        forks = []
        for n in range(1, 41):
            node = pr_node(n, issue=issue_node(10), title="\U0001f600" * 200, files=())
            node["isCrossRepository"] = True
            forks.append(node)
        self.fake.prs[REPO_A]["open"] = forks
        self.fake.prs[REPO_A]["closed"] = [merge]
        full = len(snapshot.encode(self.run_refresh()))
        saved = snapshot.MAX_SNAPSHOT
        snapshot.MAX_SNAPSHOT = full // 2  # only cutting whole items can fit it
        try:
            snap = self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        self.assertIn(REPO_A, snap["truncated"])
        kept = next(i for i in snap["items"] if i["number"] == 900)
        self.assertEqual(tasks.derive(self.task_of(kept)).state, tasks.State.UNSAFE)

    def test_a_lone_unreadable_pr_never_stalls_every_repository(self):
        # Finding 3.
        node = pr_node(3, issue=issue_node(11, repo=REPO_B))
        node["isDraft"] = "no"  # wrongly shaped: this PR's own data
        self.fake.prs[REPO_B]["open"] = [node]
        snap = self.run_refresh()  # no bad-response
        lone = next(i for i in snap["items"] if i["repo"] == REPO_B)
        self.assertIsNone(lone["task"])  # shown, as unreadable
        self.assertTrue(any(i["task"] for i in snap["items"] if i["repo"] == REPO_A))

    def test_an_open_pr_with_a_closing_time_is_never_dropped(self):
        # Finding 4: state OPEN with an old closedAt fell out of the window silently.
        node = pr_node(1, issue=issue_node(10))
        node["closedAt"] = (NOW - timedelta(days=60)).isoformat()
        self.fake.prs[REPO_A]["open"][0] = node
        items = self.run_refresh()["items"]
        bad = next(i for i in items if i["number"] == 1)
        self.assertIsNone(bad["task"])  # unreadable: UNKNOWN

    def test_fitting_measures_the_snapshot_a_handful_of_times(self):
        # Finding 5: re-measuring after every cut took up to 38 s at worst case.
        paths = tuple(f"d/{i:02d}" + "x" * 100 for i in range(100))
        self.fake.prs[REPO_A]["open"] = [
            pr_node(n, issue=issue_node(10), files=paths) for n in range(1, 41)
        ]
        full = len(snapshot.encode(self.run_refresh()))
        calls = []
        real = snapshot.encode

        def counted(data):
            if "items" in data:
                calls.append(1)
            return real(data)

        saved = snapshot.MAX_SNAPSHOT
        snapshot.MAX_SNAPSHOT = full // 4
        try:
            with mock.patch.object(snapshot, "encode", side_effect=counted):
                snap = self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        self.assertLessEqual(len(real(snap)), full // 4)
        self.assertLess(len(calls), 10)  # not one per cut list (40)

    def test_an_error_inside_one_file_entry_keeps_its_clinical_siblings(self):
        # Codex's review of c5adbba (blocking): an error on one file's entry discarded the
        # whole list, and with it the evidence that a merged change was clinical.
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=recent,
            issue=issue_node(10),
            files=("site/a.html", "evidence/table.json", "site/b.html"),
        )
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number:" in body and b"files(" in body:
                answer = json.loads(data)
                answer["data"]["repository"]["p0"]["files"]["nodes"][0] = None
                answer["errors"] = [
                    {
                        "type": "SERVICE_UNAVAILABLE",
                        "path": ["repository", "p0", "files", "nodes", 0, "path"],
                    }
                ]
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
        pull = item["task"]["pull_request"]
        self.assertIsNone(pull["files"])  # the list itself: not known
        self.assertIs(pull["clinical_known"], True)  # but the clinical path was seen
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_every_request_keeps_within_the_refresh_limit(self):
        # Codex's review of c5adbba: the installation, token and repository requests ran
        # outside the limit, and a request could start with less time left than its own limit.
        limits = []
        real = self.fake.__call__

        def call(method, path, headers, body):
            limits.append((path, gh._LIMIT.get()))
            return real(method, path, headers, body)

        # One clock for everything (both modules use the same `time`): the refresh starts at 0,
        # and every later look is 170 s on, 10 s before the limit.
        clock = iter([0.0] + [170.0] * 10_000)
        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        with mock.patch.object(gh.time, "monotonic", side_effect=lambda: next(clock)):
            snapshot.refresh(self.cfg, github, NOW)
        asked = [limit for path, limit in limits if path != "/installation/token"]
        self.assertTrue(asked)
        self.assertTrue(all(limit <= 10.0 for limit in asked), asked)
        # Past the limit, nothing starts, not even the installation check; the token is still
        # revoked.
        limits.clear()
        github.deadline = 180.0
        with mock.patch.object(gh.time, "monotonic", side_effect=lambda: 500.0):
            with self.assertRaises(gh.FetchError) as caught:
                github.installation(OWNER, [REPO_A, REPO_B])
            self.assertEqual(caught.exception.code, "too-slow")
            self.assertEqual(limits, [])
        self.assertTrue(github.revoke(TOKEN))  # revocation always runs

    def test_a_contradictory_merge_state_is_never_read_as_the_calmer_half(self):
        # Finding 3: state MERGED with merged false read as closed without merging.
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        node["merged"] = False
        self.fake.prs[REPO_A]["closed"] = [node]
        item = next(i for i in self.run_refresh()["items"] if i["number"] == 1)
        self.assertIsNone(item["task"])  # unreadable: UNKNOWN, an alert
        self.assertIsNone(item["linked_issues"])  # finding 5: not known, never 0

    def test_a_pr_from_a_fork_always_needs_attention(self):
        # Finding 4: a stranger's fork PR claiming an authorised issue looked like Billy's work.
        node = pr_node(1, issue=issue_node(10))
        node["isCrossRepository"] = True
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertIs(item["task"]["pull_request"]["from_fork"], True)
        state = tasks.derive(self.task_of(item))
        self.assertIn(tasks.Flag.FROM_FORK, state.flags)
        self.assertTrue(state.needs_attention)

    def test_every_pr_read_only_lite_is_shown_never_clean(self):
        # Finding 6 asked that an all-lite reading not say "ok" with everything not known;
        # the audit of 28009de showed that rejecting it let two huge PRs from anyone stall
        # every repository. A lite read is now shown: reviews read, files and checks "not
        # known" and alerting, never greener.
        real = self.fake.__call__

        def call(method, path, headers, body):
            if path == "/graphql" and b"files(" in body:
                return 502, {}, b""
            return real(method, path, headers, body)

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        for item in snapshot.refresh(self.cfg, github, NOW)["items"]:
            state = tasks.derive(self.task_of(item))
            self.assertNotIn(tasks.Flag.CHECKS_PASSED, state.flags)
            self.assertTrue(state.needs_attention)

    def test_hidden_characters_and_lone_surrogates_are_cleaned_or_refused(self):
        # Finding 7.
        node = pr_node(1, issue=issue_node(10), title="\u202e\u202e\u200e\u200b")
        node["headRefName"] = "claude/x\ud800"
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["title"], snapshot.NO_TITLE)  # nothing left once cleaned
        self.assertIsNone(item["task"]["branch"])  # not plain text: not known
        self.assertEqual(snapshot._str("a\u200eb\u0085c\u2028d"), "a b c d")

    def test_a_closed_pr_without_a_closing_time_is_a_bad_answer(self):
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="CLOSED", closed_at=recent)
        node["closedAt"] = None
        self.fake.prs[REPO_A]["closed"] = [node]
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, "bad-response")

    def test_a_refresh_has_an_overall_time_limit(self):
        clock = iter(range(0, 10**6, 100))  # each look at the clock: 100 s later
        with mock.patch.object(snapshot.time, "monotonic", side_effect=lambda: next(clock)):
            with self.assertRaises(gh.FetchError) as caught:
                self.run_refresh()
        self.assertEqual(caught.exception.code, "too-slow")

    def test_a_pr_nulled_whole_for_an_optional_field_is_read_by_its_core(self):
        # Codex's review of 8152df0 (blocking): an error on a non-null optional field (the
        # title) makes GitHub null the whole pull request; it was marked unreadable, hiding a
        # merge by someone other than the owner.
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        core_fields = (
            "number",
            "state",
            "isDraft",
            "isCrossRepository",
            "merged",
            "closedAt",
            "mergedAt",
            "mergedBy",
            "headRefOid",
        )
        real = self.fake.__call__
        nulled = []

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number:" in body:
                answer = json.loads(data)
                repository = answer["data"]["repository"]
                # The core query asks for no optional piece (Codex's review of b1f5a1a: the text
                # matched before is in every query, so no request was ever nulled).
                optional = (b"\n  title", b"files(", b"closingIssuesReferences", b"commits(")
                if not any(m in body for m in optional):
                    for alias, pr in repository.items():
                        repository[alias] = {k: pr[k] for k in core_fields}
                else:
                    nulled.append(1)
                    for alias in repository:
                        repository[alias] = None
                    answer["errors"] = [
                        {"type": "SERVICE_UNAVAILABLE", "path": ["repository", a, "title"]}
                        for a in repository
                    ]
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
        self.assertTrue(nulled)  # the full read was nulled, so the core read is what was kept
        self.assertIsNotNone(item["task"])
        self.assertEqual(item["title"], snapshot.NO_TITLE)
        pull = item["task"]["pull_request"]
        self.assertEqual((pull["files"], pull["reviews"], pull["checks"]), (None, None, None))
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, state.flags)

    def test_tasks_the_model_rejects_never_replace_the_snapshot(self):
        # Codex's review of 8152df0 (blocking): any built task counted as readable.
        real_item = snapshot._item

        def rejected(*args, **kwargs):
            item = real_item(*args, **kwargs)
            item["task"]["pull_request"]["head_sha"] = "not a sha"  # the model rejects it
            return item

        with mock.patch.object(snapshot, "_item", side_effect=rejected):
            with self.assertRaises(gh.FetchError) as caught:
                self.run_refresh()
        self.assertEqual(caught.exception.code, "bad-response")

    def test_an_error_on_an_optional_field_never_hides_a_known_unsafe_merge(self):
        # Codex's review of c3ee86b (blocking): a GraphQL error on one optional field threw
        # away the whole partial answer, so a merge by someone else showed as UNKNOWN.
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["open"] = [pr_node(2)]
        self.fake.prs[REPO_A]["closed"] = [node]
        for field in ("closingIssuesReferences", "files", "reviews", "title", "headRefName"):
            with self.subTest(field=field):
                github = self.with_field_errors({1: [field]})
                item = next(
                    i for i in snapshot.refresh(self.cfg, github, NOW)["items"] if i["number"] == 1
                )
                state = tasks.derive(self.task_of(item))
                self.assertEqual(state.state, tasks.State.UNSAFE)
                self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, state.flags)

    def test_a_field_github_nulled_for_an_error_is_never_read_as_clean(self):
        # Codex's review of c3ee86b: GitHub sets the errored field to null. Null must mean
        # "not known", never no files, no result on the test merge commit or no linked issue.
        self.fake.prs[REPO_A]["open"] = [
            pr_node(n, issue=issue_node(10), files=("evidence/a.json",), reviews=[review_node()])
            for n in range(1, 6)
        ]
        github = self.with_field_errors(
            # rv0: the first clinician's reviews (one connection each since 4945de9)
            {1: ["files"], 2: ["potentialMergeCommit"], 3: ["commits"], 4: ["rv0"]}
        )
        snap = snapshot.refresh(self.cfg, github, NOW)
        pulls = {
            i["number"]: i["task"]["pull_request"] for i in snap["items"] if i["repo"] == REPO_A
        }
        self.assertIsNone(pulls[1]["files"])  # not []
        self.assertNotIn("files_complete", pulls[1])
        self.assertIsNotNone(pulls[1]["reviews"])  # the rest is still read whole
        self.assertIsNotNone(pulls[1]["checks"])
        # A null test merge commit isn't "no results": the checks are partial, never passed.
        self.assertIs(pulls[2]["checks_complete"], False)
        self.assertIsNone(pulls[3]["checks"])
        self.assertIsNone(pulls[4]["reviews"])
        self.assertEqual(pulls[4]["files"], ["evidence/a.json"])
        self.assertEqual(pulls[5]["files"], ["evidence/a.json"])  # untouched
        self.assertEqual(len(pulls[5]["checks"]), 2)
        by_number = {i["number"]: i for i in snap["items"] if i["repo"] == REPO_A}
        flags = {n: tasks.derive(self.task_of(by_number[n])).flags for n in by_number}
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, flags[1])
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, flags[2])
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags[2])
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, flags[3])
        self.assertIn(tasks.Flag.REVIEWS_UNVERIFIED, flags[4])
        # One answer was enough: nothing was split or read again.
        details = [q for q in self.fake.queries if "pullRequest(number: 1)" in q]
        self.assertEqual(len(details), 1)

    def test_an_errored_issue_link_gives_no_issue(self):
        # Codex's review of c3ee86b: the link is "not known" (null), and nothing is shown.
        self.fake.prs[REPO_A]["open"] = [pr_node(1, issue=issue_node(10)), pr_node(2)]
        github = self.with_field_errors({1: ["closingIssuesReferences"]})
        item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
        self.assertIsNone(item["task"]["issue"])
        self.assertIsNone(item["issue"])
        self.assertEqual(item["task"]["pull_request"]["files"], ["site/a.html"])
        self.assertEqual(tasks.derive(self.task_of(item)).state, tasks.State.NOT_LINKED)

    def test_an_error_on_a_core_field_makes_only_that_pr_unreadable(self):
        # Codex's review of c3ee86b: who merged it can't be judged from a null GitHub put
        # there for an error.
        recent = (NOW - timedelta(days=1)).isoformat()
        for field in ("mergedBy", "merged", "state", "headRefOid", "mergedAt", "closedAt"):
            with self.subTest(field=field):
                self.fake.prs[REPO_A]["open"] = [pr_node(2)]
                self.fake.prs[REPO_A]["closed"] = [
                    pr_node(1, state="MERGED", merged=True, closed_at=recent)
                ]
                github = self.with_field_errors({1: [field]})
                items = snapshot.refresh(self.cfg, github, NOW)["items"]
                by_number = {i["number"]: i for i in items if i["repo"] == REPO_A}
                self.assertIsNone(by_number[1]["task"])  # UNKNOWN, an alert
                self.assertIsNotNone(by_number[2]["task"])

    def test_partial_data_with_an_error_outside_the_pull_requests_fails_the_refresh(self):
        # Codex's review of c3ee86b: partial data is used only when every error is inside a
        # pull request that was asked for.
        for path in (None, ["repository"], ["repository", "p9", "files"], ["rateLimit"], "p0"):
            with self.subTest(path=path):
                error = {"type": "FORBIDDEN"} if path is None else {"type": "X", "path": path}
                github = self.with_field_errors({1: ["files"]}, extra=[error])
                with self.assertRaises(gh.FetchError) as caught:
                    snapshot.refresh(self.cfg, github, NOW)
                self.assertEqual(caught.exception.code, "graphql-error")

    def test_prs_that_all_fail_validation_never_replace_the_snapshot(self):
        # Codex's review of c3ee86b (blocking): the all-unreadable guard looked at GitHub's
        # answer before the items were built, so pull requests that were all there but all
        # wrongly shaped passed it, and the refresh reported success.
        self.fake.prs[REPO_A]["open"] = [pr_node(1, head="not-a-sha"), pr_node(2, head="nor-this")]
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, "bad-response")
        self.assertEqual(self.fake.revoked, 1)
        # One unreadable pull request among readable ones is still only that one.
        self.fake.prs[REPO_A]["open"] = [pr_node(1, head="not-a-sha"), pr_node(2)]
        items = self.run_refresh()["items"]
        self.assertEqual([i["task"] is None for i in items], [True, False, False])

    def test_core_errors_on_every_pr_never_replace_the_snapshot(self):
        # Codex's review of c3ee86b: the same guard, when every pull request is unreadable
        # because of GitHub's errors on fields it can't be judged without.
        github = self.with_field_errors({1: ["state"], 2: ["merged"]})
        with self.assertRaises(gh.FetchError) as caught:
            snapshot.refresh(self.cfg, github, NOW)
        self.assertEqual(caught.exception.code, "bad-response")

    def test_a_bad_issue_never_hides_a_known_unsafe_merge(self):
        # Codex's review of 7faf35a (blocking).
        recent = (NOW - timedelta(days=1)).isoformat()
        issue = issue_node(10)
        issue["state"] = ["OPEN"]  # wrongly shaped
        node = pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue)
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        item = self.run_refresh()["items"][0]
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, state.flags)

    def test_another_apps_checks_need_no_workflow_run(self):
        # Codex's review of de9a6fb: suites of an app other than GitHub Actions have no
        # workflow run, so their required checks showed as missing.
        data = config_data(self.base)
        data["repos"][REPO_A]["checks_app"] = "other-ci"
        self.cfg = fconfig.parse_fetcher(json.dumps(data))
        node = pr_node(1, issue=issue_node(10), checks_app="other-ci")
        node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["workflowRun"] = None
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        names = sorted(c["name"] for c in item["task"]["pull_request"]["checks"])
        self.assertEqual(names, ["lint", "test"])
        self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_too_large_also_says_when_the_token_outlived_it(self):
        # Codex's review of 23bfb61: the size error dropped the failed-revoke warning.
        self.fake.fail["/installation/token"] = (500, {}, b"")
        saved = snapshot.MAX_SNAPSHOT
        snapshot.MAX_SNAPSHOT = 100
        try:
            with self.assertRaises(gh.FetchError) as caught:
                self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        self.assertEqual(caught.exception.code, "too-large+token-not-revoked")

    def test_a_merged_or_closed_pull_request_makes_no_check_claim(self):
        # Owner's decision, 2026-11-25, after Codex's review of a1e05e5: once merged, GitHub no
        # longer shows the test merge commit it judged, so no reading can match its verdict.
        recent = (NOW - timedelta(days=1)).isoformat()
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [
            pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10)),
            pr_node(2, state="CLOSED", closed_at=recent, issue=issue_node(11)),
        ]
        merged, closed = self.run_refresh()["items"][:2]
        for item in (merged, closed):
            with self.subTest(id=item["id"]):
                self.assertIsNone(item["task"]["pull_request"]["checks"])  # "not known"
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.task_of(item)).flags)
        # Codex's review of b24ac2d (blocking): leaving the checks out made the whole PR
        # unreadable. With "not known", the model still judges everything else.
        state = tasks.derive(self.task_of(merged))
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, state.flags)  # never judged after a merge
        self.assertEqual(tasks.derive(self.task_of(closed)).state, tasks.State.CLOSED)

    def test_an_owner_merge_is_never_called_unreviewed_for_lack_of_run_records(self):
        # Codex's review of 9537b08 (blocking): the snapshot sent an empty run list, which the
        # model read as proof that no review happened, so every merged PR showed as unsafe.
        # Run records are not read in A5a: null, and no claim either way.
        recent = (NOW - timedelta(days=1)).isoformat()
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [
            pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        ]
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["runs"])
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.MERGED)
        self.assertNotIn(tasks.Flag.MERGED_UNREVIEWED, state.flags)
        self.assertIn(tasks.Flag.RUNS_UNVERIFIED, state.flags)
        self.assertIsNone(state.reviewed_sha)  # merged, but no review is claimed
        # Another account's merge is still unsafe without the records.
        node = pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["closed"] = [node]
        other = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertEqual(other.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, other.flags)

    def test_an_open_pr_is_never_said_to_skip_review_for_lack_of_run_records(self):
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertEqual(state.state, tasks.State.BUILT)
        self.assertIn(tasks.Flag.RUNS_UNVERIFIED, state.flags)
        self.assertNotIn(tasks.Flag.PR_BEFORE_REVIEW, state.flags)
        self.assertNotIn(tasks.Flag.REVIEW_MISSING, state.flags)
        self.assertIsNone(state.reviewed_sha)

    def test_unknown_checks_on_an_open_pr_never_count_as_passed(self):
        # The model's side of "not known" (pull_request.checks null): an open, reviewed PR whose
        # checks aren't known waits, flagged, rather than looking ready to merge.
        item = self.run_refresh()["items"][0]
        task = self.reviewed(item)
        self.assertEqual(tasks.derive(task).state, tasks.State.AWAITING_OWNER)  # known: ready
        task["pull_request"] = dict(task["pull_request"], checks=None)
        state = tasks.derive(task)
        self.assertEqual(state.state, tasks.State.PUBLISHED)
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, state.flags)
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, state.flags)

    def test_someone_elses_merge_is_still_flagged(self):
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["open"], self.fake.prs[REPO_A]["closed"] = [], [node]
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, state.flags)

    def test_review_and_deployment_runs_count(self):
        # Codex's review of a1e05e5: GitHub documents these as sources of required checks.
        for event in ("pull_request_review", "deployment", "deployment_status"):
            with self.subTest(event=event):
                self.fake.prs[REPO_A]["open"] = [
                    pr_node(1, issue=issue_node(10), check_event=event)
                ]
                item = self.run_refresh()["items"][0]
                self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_an_open_pr_is_never_closed_by_its_issue(self):
        # Pre-review of 9537b08: a PR that "fixes" an already closed issue showed as closed,
        # calmly, though it was open and mergeable.
        issue = issue_node(10)
        issue["state"] = "CLOSED"
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue)
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertNotEqual(state.state, tasks.State.CLOSED)
        self.assertIn(tasks.Flag.ISSUE_CLOSED_PR_OPEN, state.flags)
        self.assertTrue(state.needs_attention)

    def test_long_paths_in_one_pr_never_stop_the_refresh(self):
        # Pre-review of 9537b08: six PRs of 100 files on ~4000-character paths pushed every
        # snapshot over its limit, freezing it for all repositories.
        long_files = tuple("d/" + "x" * 3990 + f"{i:03d}" for i in range(100))
        self.fake.prs[REPO_A]["open"] = [
            pr_node(n, issue=issue_node(10), files=long_files) for n in range(1, 7)
        ]
        snap = self.run_refresh()  # no too-large
        for item in snap["items"][:6]:
            self.assertIsNone(item["task"]["pull_request"]["files"])  # "not known"
            self.assertIn(tasks.Flag.FILES_UNVERIFIED, tasks.derive(self.task_of(item)).flags)

    def test_the_path_cap_counts_escaped_bytes(self):
        # Codex's review of 72607b3 (blocking): raw UTF-8 was counted, but each "é" is written
        # as a six-byte escape.
        paths = tuple(f"d/{i:02d}" + "é" * 200 for i in range(30))  # 12 KB raw, 36 KB written
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10), files=paths)
        self.assertIsNone(self.run_refresh()["items"][0]["task"]["pull_request"]["files"])

    def test_a_snapshot_over_its_limit_drops_file_lists_rather_than_failing(self):
        # Codex's review of 72607b3 (blocking): PRs each within the per-PR cap could together
        # push the snapshot over its limit, and every refresh failed.
        paths = tuple(f"d/{i:02d}" + "x" * 100 for i in range(100))  # ~11 KB each
        self.fake.prs[REPO_A]["open"] = [
            pr_node(n, issue=issue_node(10), files=paths) for n in range(1, 5)
        ]
        full = len(snapshot.encode(self.run_refresh()))
        saved = snapshot.MAX_SNAPSHOT
        snapshot.MAX_SNAPSHOT = full - 15000  # room for two of the four lists, not all
        try:
            snap = self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        self.assertLessEqual(len(snapshot.encode(snap)), full - 15000)
        files = [i["task"]["pull_request"]["files"] for i in snap["items"][:4]]
        self.assertIn(None, files)  # dropped to "not known"...
        self.assertIn(list(paths), files)  # ...only as many as needed
        for item in snap["items"][:4]:
            if item["task"]["pull_request"]["files"] is None:
                self.assertIn(tasks.Flag.FILES_UNVERIFIED, tasks.derive(self.task_of(item)).flags)

    def test_a_cut_list_keeps_a_known_clinical_path(self):
        # Codex's review of 69ed8e3 (blocking): cutting a list erased a path that already made
        # the change clinical, and so the warning that no clinician approved it.
        recent = (NOW - timedelta(days=1)).isoformat()
        long_files = tuple("d/" + "x" * 3990 + f"{i:03d}" for i in range(10))
        files = (*long_files, "evidence/table.json")
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [
            pr_node(
                1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10), files=files
            )
        ]
        item = self.run_refresh()["items"][0]
        pull = item["task"]["pull_request"]
        self.assertEqual(pull["files"], ["evidence/table.json"])
        self.assertIs(pull["files_complete"], False)
        state = tasks.derive(self.task_of(item))
        self.assertIn(tasks.Flag.CLINICAL, state.flags)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)
        self.assertEqual(state.state, tasks.State.UNSAFE)

    def test_fitting_the_snapshot_keeps_known_clinical_paths(self):
        paths = tuple(f"d/{i:02d}" + "x" * 100 for i in range(100)) + ("evidence/a.json",)
        self.fake.prs[REPO_A]["open"] = [
            pr_node(n, issue=issue_node(10), files=paths) for n in range(1, 5)
        ]
        full = len(snapshot.encode(self.run_refresh()))
        saved = snapshot.MAX_SNAPSHOT
        snapshot.MAX_SNAPSHOT = full - 15000
        try:
            snap = self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        files = [i["task"]["pull_request"]["files"] for i in snap["items"][:4]]
        self.assertIn(["evidence/a.json"], files)
        self.assertNotIn(None, files)
        for item in snap["items"][:4]:
            self.assertIn(tasks.Flag.CLINICAL, tasks.derive(self.task_of(item)).flags)

    def test_an_open_pr_still_shows_failing_checks_and_missing_approval(self):
        # Codex's review of 69ed8e3: with run records not read, an open PR returned before its
        # checks and clinician approval were judged.
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",))
        suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["checkRuns"]["nodes"][0]["conclusion"] = "FAILURE"
        self.fake.prs[REPO_A]["open"][0] = node
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertEqual(state.state, tasks.State.BUILT)
        self.assertIn(tasks.Flag.CHECKS_FAILING, state.flags)
        self.assertIn(tasks.Flag.CLINICAL_APPROVAL_MISSING, state.flags)
        self.assertTrue(state.needs_attention)

    def test_only_clinicians_reviews_are_kept(self):
        # Codex's review of 9fb21c8 (blocking): anyone can review a public PR, and every review
        # was kept, so ordinary review volume could push the snapshot over its limit.
        crowd = [review_node(f"user{i}", "COMMENTED") for i in range(90)]
        crowd += [review_node("helper[bot]", "APPROVED", bot=True), review_node()]
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10), reviews=crowd)
        reviews = self.run_refresh()["items"][0]["task"]["pull_request"]["reviews"]
        self.assertEqual([r["user"] for r in reviews], [OWNER])  # OWNER is the clinician here

    def test_fitting_cuts_reviews_and_checks_to_what_the_verdict_reads(self):
        # Codex's review of d75f891 (blocking): nulling a complete review list turned a known
        # clinical merge without a clinician into "reviews not verified" (MERGED). Reviews and
        # checks are now cut to what the verdict reads, and every verdict stays the same.
        recent = (NOW - timedelta(days=1)).isoformat()
        many = [review_node(state="COMMENTED", at=f"2026-11-22T00:{i:02d}:00Z") for i in range(50)]
        approved = many + [review_node(at="2026-11-22T01:00:00Z")]
        later_change = approved + [
            review_node(state="CHANGES_REQUESTED", at="2026-11-22T02:00:00Z")
        ]
        unsafe = pr_node(
            9,
            state="MERGED",
            merged=True,
            closed_at=recent,
            issue=issue_node(10),
            files=("evidence/a.json",),
            reviews=many,  # no clinician's approval: UNSAFE
        )
        failing = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=approved)
        suite = failing["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["checkRuns"]["nodes"] += [
            {"name": "lint", "status": "COMPLETED", "conclusion": "SUCCESS"} for _ in range(20)
        ] + [{"name": "test", "status": "COMPLETED", "conclusion": "FAILURE"}]
        self.fake.prs[REPO_A]["open"] = [
            failing,
            pr_node(2, issue=issue_node(10), files=("evidence/a.json",), reviews=later_change),
        ]
        self.fake.prs[REPO_A]["closed"] = [unsafe]
        before = {i["number"]: tasks.derive(self.task_of(i)) for i in self.run_refresh()["items"]}
        full = len(snapshot.encode(self.run_refresh()))
        saved = snapshot.MAX_SNAPSHOT
        snapshot.MAX_SNAPSHOT = full - 6000  # file lists alone can't make room
        try:
            snap = self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        self.assertLessEqual(len(snapshot.encode(snap)), full - 6000)
        for item in snap["items"]:
            pull = item["task"]["pull_request"]
            self.assertIsNotNone(pull["reviews"])  # never "not known" for size
            after = tasks.derive(self.task_of(item))
            self.assertEqual(after.state, before[item["number"]].state, item["number"])
        states = {i["number"]: tasks.derive(self.task_of(i)) for i in snap["items"]}
        self.assertEqual(states[9].state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, states[9].flags)
        self.assertIn(tasks.Flag.CHECKS_FAILING, states[1].flags)

    def test_short_reviews_and_checks_never_change_a_verdict(self):
        # The claim the cut rests on, tried on random lists: the model's state and flags are
        # the same from the short lists as from the full ones (Codex's review of d75f891).
        import random

        rng = random.Random(7)  # noqa: S311 - test data, not security
        recent = (NOW - timedelta(days=1)).isoformat()
        templates = []
        for merged in (False, True):
            node = (
                pr_node(
                    1,
                    state="MERGED",
                    merged=True,
                    closed_at=recent,
                    issue=issue_node(10),
                    files=("evidence/a.json",),
                )
                if merged
                else pr_node(1, issue=issue_node(10), files=("evidence/a.json",))
            )
            self.fake.prs[REPO_A]["open"] = [] if merged else [node]
            self.fake.prs[REPO_A]["closed"] = [node] if merged else []
            templates.append(self.run_refresh()["items"][0])
        other = "b" * 40
        for trial in range(400):
            item = json.loads(json.dumps(rng.choice(templates)))
            pull = item["task"]["pull_request"]
            head = pull["head_sha"]
            pull["reviews"] = [
                {
                    "user": rng.choice([OWNER, "clinician-two"]),
                    "user_type": "User",
                    "state": rng.choice(
                        ["APPROVED", "CHANGES_REQUESTED", "DISMISSED", "COMMENTED"]
                    ),
                    "commit_id": rng.choice([head, head, other]),
                    "at": f"2026-11-2{rng.randint(0, 5)}T0{rng.randint(0, 3)}:00:00+00:00",
                }
                for _ in range(rng.randint(0, 8))
            ]
            if pull["merged"]:
                pull["merged_at"] = f"2026-11-2{rng.randint(0, 5)}T02:00:00+00:00"
            else:
                pull["checks"] = [
                    {
                        "name": rng.choice(["lint", "test"]),
                        "head_sha": head,
                        "status": rng.choice(["completed", "completed", "in_progress", "queued"]),
                        "conclusion": rng.choice(["success", "success", "failure", None]),
                    }
                    for _ in range(rng.randint(0, 6))
                ]
            item["task"]["clinicians"] = [OWNER, "clinician-two"]
            full = tasks.derive(self.task_of(item))
            short = json.loads(json.dumps(item))
            sp = short["task"]["pull_request"]
            sp["reviews"] = snapshot._essential_reviews(sp["reviews"], head, sp)
            if sp.get("checks") is not None:
                sp["checks"] = snapshot._essential_checks(sp["checks"], head)
            cut = tasks.derive(self.task_of(short))
            self.assertEqual((cut.state, cut.flags), (full.state, full.flags), trial)

    def test_a_review_dismissed_after_the_merge_keeps_the_evidence(self):
        # Codex's review of 84df535 (blocking): a dismissed review submitted after the merge
        # discarded every clinician review, hiding the missing-approval warning.
        merged_at = (NOW - timedelta(days=1)).isoformat()
        later = (NOW - timedelta(hours=1)).isoformat()
        reviews = [review_node(state="DISMISSED", at=later)]  # no approval before the merge
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=merged_at,
            issue=issue_node(10),
            files=("evidence/a.json",),
            reviews=reviews,
        )
        node["mergedAt"] = merged_at
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        item = self.run_refresh()["items"][0]
        self.assertIsNotNone(item["task"]["pull_request"]["reviews"])
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    # ------------------------------------------------ Codex's review of 5d06878

    def test_an_old_success_never_passes_a_required_check(self):
        for done, passed in (
            ("2026-11-23T00:00:00Z", True),
            ("2026-11-10T00:00:00Z", False),
            (None, False),
        ):
            with self.subTest(done=done):
                node = pr_node(1, issue=issue_node(10))
                suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
                for check in suite["checkRuns"]["nodes"]:
                    check["completedAt"] = done
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertEqual(tasks.Flag.CHECKS_PASSED in flags, passed)

    def test_a_review_after_the_merge_never_discards_the_evidence(self):
        merged_at = (NOW - timedelta(days=1)).isoformat()
        later = review_node(at=(NOW - timedelta(hours=1)).isoformat())
        later["commit"] = None  # its commit is gone
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=merged_at,
            issue=issue_node(10),
            files=("evidence/a.json",),
            reviews=[later],
        )
        node["mergedAt"] = merged_at
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["task"]["pull_request"]["reviews"], [])
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_a_known_unsafe_merge_is_shown_even_when_all_was_read_lite(self):
        recent = (NOW - timedelta(days=1)).isoformat()
        merge = pr_node(9, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        merge["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["closed"] = [merge]
        real = self.fake.__call__

        def call(method, path, headers, body):
            # Only this repository's full reads fail (another one read lite only for a
            # transient reason would fail the refresh, by design: Fable's pre-review of 4945de9).
            if path == "/graphql" and b"files(" in body and b'"name": "site"' in body:
                return 502, {}, b""
            return real(method, path, headers, body)

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        snap = snapshot.refresh(self.cfg, github, NOW)  # not held back
        item = next(i for i in snap["items"] if i["number"] == 9)
        self.assertEqual(tasks.derive(self.task_of(item)).state, tasks.State.UNSAFE)

    # ------------------------------------------------ Fable's pre-review of 4945de9

    def failing_lint(self, **kw):
        node = pr_node(1, issue=issue_node(10), **kw)
        suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["checkRuns"]["nodes"][0]["conclusion"] = "FAILURE"
        return node, node["commits"]["nodes"][0]["commit"]

    def assert_failing(self, node, github=None):
        self.fake.prs[REPO_A]["open"][0] = node
        snap = snapshot.refresh(self.cfg, github, NOW) if github else self.run_refresh()
        state = tasks.derive(self.task_of(snap["items"][0]))
        self.assertIn(tasks.Flag.CHECKS_FAILING, state.flags)
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, state.flags)
        self.assertTrue(state.needs_attention)

    def test_a_reported_failure_survives_any_degraded_checks_reading(self):
        # Finding 1 (blocking): the failure GitHub supplied was thrown away.
        node, commit = self.failing_lint()
        commit["checkSuites"]["totalCount"] = 21  # more suites than read
        self.assert_failing(node)
        node, _ = self.failing_lint(
            merge_commit={"oid": "b" * 40, "status": None, "checkSuites": {"totalCount": 1}}
        )
        self.assert_failing(node)
        node, commit = self.failing_lint()
        suite = commit["checkSuites"]["nodes"][0]
        suite["checkRuns"]["nodes"].append(
            {"name": "x" * 300, "status": "COMPLETED", "conclusion": "SUCCESS"}
        )  # not required
        self.assert_failing(node)
        node, commit = self.failing_lint(statuses=[("c" * 300, "FAILURE")])  # not required
        self.assert_failing(node)
        node, _ = self.failing_lint()
        github = self.with_field_errors({}, extra=())
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number: 1)" in body and b"commits(" in body:
                answer = json.loads(data)
                answer["data"]["repository"]["p0"]["commits"]["nodes"][0]["commit"]["status"] = None
                answer["errors"] = [
                    {
                        "type": "X",
                        "path": ["repository", "p0", "commits", "nodes", 0, "commit", "status"],
                    }
                ]
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        self.assert_failing(node, github)

    def test_checks_that_cant_be_read_on_an_open_pr_need_attention(self):
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10))
        self.fake.too_large = {1}  # read lite: checks not known
        self.fake.prs[REPO_A]["open"].append(pr_node(5, issue=issue_node(10)))
        item = next(i for i in self.run_refresh()["items"] if i["number"] == 1)
        state = tasks.derive(self.task_of(item))
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, state.flags)
        self.assertTrue(state.needs_attention)

    def merged_clinical(self, reviews, **extra):
        merged_at = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=merged_at,
            issue=issue_node(10),
            files=("evidence/a.json",),
            reviews=reviews,
        )
        node.update(extra)
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        item = self.run_refresh()["items"][0]
        return item, tasks.derive(self.task_of(item))

    def test_strangers_reviews_never_hide_a_clinical_merge_without_a_clinician(self):
        # Finding 2 (blocking): 100 strangers' comments pushed the list over its limit.
        later = (NOW - timedelta(hours=1)).isoformat()
        crowd = [review_node(f"user{i}", "COMMENTED", at=later) for i in range(101)]
        crowd.append(review_node("odd_login", "WEIRD"))  # a stranger's odd review
        item, state = self.merged_clinical(crowd)
        self.assertEqual(item["task"]["pull_request"]["reviews"], [])
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_a_stale_dismissed_approval_never_hides_a_merge_without_approval(self):
        # Finding 3 (blocking): an approval of an older commit, dismissed as stale, nulled the
        # reviews; so did a review whose commit was force-pushed away.
        before = (NOW - timedelta(days=2)).isoformat()
        stale = review_node(state="DISMISSED", at=before, commit="b" * 40)
        gone = review_node(state="COMMENTED", at=before)
        gone["commit"] = None
        item, state = self.merged_clinical([stale, gone])
        self.assertIsNotNone(item["task"]["pull_request"]["reviews"])
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)
        # A dismissed review of the head, before the merge, may have been an approval: the
        # model says "not known" (the reviews are kept since 42a3721).
        head_dismissed = review_node(state="DISMISSED", at=before)
        item, state = self.merged_clinical([head_dismissed])
        self.assertIsNotNone(item["task"]["pull_request"]["reviews"])
        self.assertIn(tasks.Flag.DISMISSAL_UNPLACED, state.flags)
        self.assertNotIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_a_lone_pr_is_asked_for_again_after_a_transient_error(self):
        # Finding 4: one 502 read a lone PR lite at once, under "ok".
        merged_at = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(
            3,
            state="MERGED",
            merged=True,
            closed_at=merged_at,
            issue=issue_node(11, repo=REPO_B),
            files=("docs/a.md",),
        )
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}  # unsafe on its own
        self.fake.prs[REPO_B]["open"], self.fake.prs[REPO_B]["closed"] = [], [node]
        failures = [1]
        real = self.fake.__call__

        def once(method, path, headers, body):
            if path == "/graphql" and b"files(" in body and b'"name": "tools"' in body and failures:
                failures.pop()
                return 502, {}, b""
            return real(method, path, headers, body)

        github = gh.GitHub(APP_ID, KEY, transport=once, clock=lambda: NOW.timestamp())
        snap = snapshot.refresh(self.cfg, github, NOW)
        item = next(i for i in snap["items"] if i["repo"] == REPO_B)
        self.assertEqual(item["task"]["pull_request"]["files"], ["docs/a.md"])  # read whole
        self.assertEqual(tasks.derive(self.task_of(item)).state, tasks.State.UNSAFE)

        def always(method, path, headers, body):
            if path == "/graphql" and b"files(" in body and b'"name": "tools"' in body:
                return 502, {}, b""
            return real(method, path, headers, body)

        # One that keeps failing in full is shown lite after the extra try, like a too-large
        # one: a stranger's PR must never stall every repository (audit of 42a3721).
        node["mergedBy"] = {"__typename": "User", "login": OWNER}
        github = gh.GitHub(APP_ID, KEY, transport=always, clock=lambda: NOW.timestamp())
        item = next(
            i for i in snapshot.refresh(self.cfg, github, NOW)["items"] if i["repo"] == REPO_B
        )
        self.assertIsNone(item["task"]["pull_request"]["files"])

    def test_a_retry_leaves_out_only_the_pieces_in_error(self):
        # Finding 5: an error on the title nulled the PR, and the retry went straight to the
        # core, dropping files and reviews that were readable.
        merged_at = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=merged_at,
            issue=issue_node(10),
            files=("evidence/a.json",),
        )
        self.fake.prs[REPO_A]["open"], self.fake.prs[REPO_A]["closed"] = [], [node]
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number: 1)" in body and b"\\n  title" in body:
                answer = json.loads(data)
                answer["data"]["repository"]["p0"] = None
                answer["errors"] = [{"type": "X", "path": ["repository", "p0", "title"]}]
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
        pull = item["task"]["pull_request"]
        self.assertEqual(pull["files"], ["evidence/a.json"])  # not dropped with the title
        self.assertIsNotNone(pull["reviews"])
        self.assertEqual(item["title"], snapshot.NO_TITLE)
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_a_second_piece_in_error_goes_straight_to_the_core(self):
        # Codex's review of 0e2139f (blocking): retries alternated between two pieces. And of
        # 0f79663 (blocking): one retry per piece could spend the budget before the core read.
        real = self.fake.__call__
        calls = []

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number: 1)" in body:
                calls.append(1)
                bad = [f for f in ("title", "headRefName") if f"\\n  {f}".encode() in body]
                if bad:
                    answer = json.loads(data)
                    answer["data"]["repository"]["p0"] = None
                    answer["errors"] = [
                        {"type": "X", "path": ["repository", "p0", bad[len(calls) % len(bad)]]}
                    ]
                    data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
        self.assertIsNotNone(item["task"])  # read, with its core
        self.assertIsNone(item["task"]["pull_request"]["files"])  # left out: not known
        self.assertEqual(len(calls), 3)  # the full read, one retry, the core

    def test_an_odd_check_time_never_discards_a_known_failure(self):
        # Codex's review of 0e2139f (blocking).
        node, commit = self.failing_lint()
        runs = commit["checkSuites"]["nodes"][0]["checkRuns"]["nodes"]
        runs[1]["completedAt"] = "not a time"  # "test" succeeded, at an odd time
        self.assert_failing(node)

    # ------------------------------------------------ audit of 42a3721

    def nulled_once(self, numbers, fields, when=lambda body: True):
        """A GitHub that nulls these PRs once, for errors on these fields, then answers."""
        real = self.fake.__call__
        done = set()

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number:" in body and when(body):
                answer = json.loads(data)
                errors = []
                for alias, node in answer["data"]["repository"].items():
                    if node and node["number"] in numbers and node["number"] not in done:
                        done.add(node["number"])
                        answer["data"]["repository"][alias] = None
                        errors += [{"type": "X", "path": ["repository", alias, *f]} for f in fields]
                if errors:
                    answer["errors"] = errors
                    data = json.dumps(answer).encode()
            return status, h, data

        return gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())

    def test_a_retry_without_the_test_merge_commit_is_never_passed(self):
        node = pr_node(
            1,
            issue=issue_node(10),
            merge_commit={"oid": "b" * 40, "status": None, "checkSuites": {"totalCount": 3}},
        )
        self.fake.prs[REPO_A]["open"][0] = node
        github = self.nulled_once({1}, [["title"], ["potentialMergeCommit", "oid"]])
        item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
        self.assertIs(item["task"]["pull_request"]["checks_complete"], False)
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_a_lite_reads_retry_never_asks_for_the_large_pieces_again(self):
        self.fake.prs[REPO_A]["open"] = [
            pr_node(1, issue=issue_node(10)),
            pr_node(2, issue=issue_node(10)),
        ]
        self.fake.too_large = {1}
        github = self.nulled_once({1}, [["title"]], when=lambda body: b"files(" not in body)
        snap = snapshot.refresh(self.cfg, github, NOW)  # not "too-large" for every repository
        item = next(i for i in snap["items"] if i["number"] == 1)
        self.assertIsNone(item["task"]["pull_request"]["files"])

    def test_title_only_retries_are_not_lite_reads(self):
        self.fake.prs[REPO_A]["open"] = [
            pr_node(1, issue=issue_node(10)),
            pr_node(2, issue=issue_node(10)),
        ]
        github = self.nulled_once({1, 2}, [["title"]])
        snap = snapshot.refresh(self.cfg, github, NOW)  # not rejected as all-lite
        for item in snap["items"][:2]:
            self.assertEqual(item["task"]["pull_request"]["files"], ["site/a.html"])

    def test_skipped_and_neutral_required_checks_pass(self):
        for conclusion in ("SKIPPED", "NEUTRAL"):
            with self.subTest(conclusion):
                node = pr_node(1, issue=issue_node(10))
                suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
                suite["checkRuns"]["nodes"][0]["conclusion"] = conclusion
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_a_wrongly_shaped_suite_is_never_skipped_silently(self):
        for field, value in (
            ("app", "github-actions"),
            ("app", {"slug": 5}),
            ("workflowRun", 0),
            ("workflowRun", ""),
            ("workflowRun", {"event": 0}),
        ):
            with self.subTest(field=field, value=value):
                node, commit = self.failing_lint()
                suites = commit["checkSuites"]
                good = json.loads(json.dumps(suites["nodes"][0]))
                good["checkRuns"]["nodes"][0]["conclusion"] = "SUCCESS"
                suites["nodes"][0][field] = value  # the failing suite, wrongly shaped
                suites["nodes"].append(good)
                suites["totalCount"] = 2
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    # ------------------------------------------------ audit of 28009de

    def test_a_wrongly_typed_check_name_is_never_skipped_silently(self):
        for where in ("run", "status", "app key", "no workflow run"):
            with self.subTest(where):
                node, commit = self.failing_lint()
                suites = commit["checkSuites"]
                failing = suites["nodes"][0]
                good = json.loads(json.dumps(failing))
                good["checkRuns"]["nodes"][0]["conclusion"] = "SUCCESS"
                if where == "run":
                    failing["checkRuns"]["nodes"][0]["name"] = None
                elif where == "app key":
                    del failing["app"]
                elif where == "no workflow run":
                    failing["workflowRun"] = None
                suites["nodes"].append(good)
                suites["totalCount"] = 2
                if where == "status":
                    failing["checkRuns"]["nodes"][0]["conclusion"] = "SUCCESS"
                    commit["status"] = {"contexts": [{"context": None, "state": "FAILURE"}]}
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_a_clinicians_review_is_matched_whatever_the_login_case(self):
        before = (NOW - timedelta(days=2)).isoformat()
        request = review_node(OWNER.upper(), "CHANGES_REQUESTED", at=before)
        item, state = self.merged_clinical([request])
        self.assertEqual(
            [r["state"] for r in item["task"]["pull_request"]["reviews"]], ["CHANGES_REQUESTED"]
        )
        self.assertEqual(state.state, tasks.State.UNSAFE)

    # ------------------------------------------------ audit of 0585599

    def test_a_review_after_the_merge_is_skipped_before_its_author_is_checked(self):
        before = (NOW - timedelta(days=2)).isoformat()
        later = (NOW - timedelta(hours=1)).isoformat()
        for author in (
            {"__typename": "User", "login": "someone-else"},
            {"__typename": "Bot", "login": OWNER},
            {"__typename": "User"},
        ):
            with self.subTest(author=author):
                late = review_node(state="COMMENTED", at=later)
                late["author"] = author
                request = review_node(state="CHANGES_REQUESTED", at=before)
                item, state = self.merged_clinical([request, late])
                self.assertIsNotNone(item["task"]["pull_request"]["reviews"])
                self.assertEqual(state.state, tasks.State.UNSAFE)

    def test_a_suite_without_a_workflow_run_is_skipped_only_when_provably_harmless(self):
        cases = {
            "cut off": {"totalCount": 5, "nodes": []},
            "odd name": {
                "totalCount": 1,
                "nodes": [{"name": None, "status": "COMPLETED", "conclusion": "FAILURE"}],
            },
            "no runs": None,
            "odd run": {"totalCount": 1, "nodes": [7]},
        }
        for name, runs in list(cases.items()) + [("no key", "drop")]:
            with self.subTest(name):
                node = pr_node(1, issue=issue_node(10))
                commit = node["commits"]["nodes"][0]["commit"]
                extra = {"app": {"slug": "github-actions"}, "workflowRun": None, "checkRuns": runs}
                if runs == "drop":
                    extra = {
                        "app": {"slug": "github-actions"},
                        "checkRuns": {"totalCount": 0, "nodes": []},
                    }
                commit["checkSuites"]["nodes"].append(extra)
                commit["checkSuites"]["totalCount"] = 2
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                self.assertIs(item["task"]["pull_request"].get("checks_complete"), False)
        # Provably whole and holding no required check: skipped, the rest still passes.
        node = pr_node(1, issue=issue_node(10))
        commit = node["commits"]["nodes"][0]["commit"]
        commit["checkSuites"]["nodes"].append(
            {
                "app": {"slug": "github-actions"},
                "workflowRun": None,
                "checkRuns": {
                    "totalCount": 1,
                    "nodes": [{"name": "deploy", "status": "COMPLETED", "conclusion": "FAILURE"}],
                },
            }
        )
        commit["checkSuites"]["totalCount"] = 2
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_a_time_at_the_edge_of_the_calendar_never_discards_a_known_failure(self):
        # Audit of ea9b32a: astimezone raised OverflowError, which nulled every check.
        for edge in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(edge):
                node, commit = self.failing_lint()
                commit["checkSuites"]["nodes"][0]["checkRuns"]["nodes"][1]["completedAt"] = edge
                self.assert_failing(node)

    def test_a_clinical_path_of_any_length_is_clinical(self):
        # Finding 6.
        item, state = self.merged_clinical(
            [],
            files={
                "totalCount": 1,
                "nodes": [{"path": "evidence/" + "x" * 4100, "changeType": "MODIFIED"}],
            },
        )
        self.assertIs(item["task"]["pull_request"]["clinical_known"], True)
        self.assertEqual(state.state, tasks.State.UNSAFE)

    def test_a_dismissed_review_on_a_merged_pr_is_not_known(self):
        # Codex's review of 9fb21c8 (blocking): GitHub gives a review's current state with its
        # submission time, so a dismissal after the merge looked like one before it.
        recent = (NOW - timedelta(days=1)).isoformat()
        reviews = [review_node("someone"), review_node(state="DISMISSED")]
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [
            pr_node(
                1,
                state="MERGED",
                merged=True,
                closed_at=recent,
                issue=issue_node(10),
                files=("evidence/a.json",),
                reviews=reviews,
            )
        ]
        item = self.run_refresh()["items"][0]
        # Since 42a3721 the reviews are kept, and the model says "not known" because the
        # verdict depends on the dismissed one.
        self.assertIsNotNone(item["task"]["pull_request"]["reviews"])
        state = tasks.derive(self.task_of(item))
        self.assertIn(tasks.Flag.DISMISSAL_UNPLACED, state.flags)
        self.assertNotIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)
        # On an open PR the current state is what counts: it is kept.
        self.fake.prs[REPO_A]["closed"] = []
        self.fake.prs[REPO_A]["open"] = [
            pr_node(1, issue=issue_node(10), reviews=[review_node(state="DISMISSED")])
        ]
        kept = self.run_refresh()["items"][0]["task"]["pull_request"]["reviews"]
        self.assertEqual([r["state"] for r in kept], ["DISMISSED"])

    def test_unlinked_and_unauthorised_open_prs_still_show_their_gates(self):
        # Codex's review of 9fb21c8: early returns skipped checks and clinician approval.
        unlinked = pr_node(1, files=("evidence/a.json",))  # no linked issue
        suite = unlinked["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["checkRuns"]["nodes"][0]["conclusion"] = "FAILURE"
        unauthorised = pr_node(
            2, issue=issue_node(11, actor="someone-else"), files=("evidence/b.json",)
        )
        self.fake.prs[REPO_A]["open"] = [unlinked, unauthorised]
        first, second = self.run_refresh()["items"][:2]
        s1 = tasks.derive(self.task_of(first))
        self.assertEqual(s1.state, tasks.State.NOT_LINKED)
        self.assertIn(tasks.Flag.CHECKS_FAILING, s1.flags)
        self.assertIn(tasks.Flag.CLINICAL_APPROVAL_MISSING, s1.flags)
        s2 = tasks.derive(self.task_of(second))
        self.assertEqual(s2.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.CHECKS_PASSED, s2.flags)
        self.assertIn(tasks.Flag.CLINICAL_APPROVAL_MISSING, s2.flags)

    def test_valid_data_never_freezes_the_snapshot(self):
        # Codex's review of dc1eb14 (blocking): long issue timelines repeated in every item, and
        # many check runs, could push valid data over the limit, failing every refresh.
        issue = issue_node(10)
        noise = [
            {
                "__typename": "LabeledEvent",
                "createdAt": "2026-11-20T08:00:00Z",
                "actor": {"__typename": "User", "login": OWNER},
                "label": {"name": f"{i:03}" + "x" * 197},  # each its own: no repeat
            }
            for i in range(90)
        ]
        issue["timelineItems"]["nodes"] = noise + issue["timelineItems"]["nodes"]
        issue["timelineItems"]["totalCount"] = len(issue["timelineItems"]["nodes"])
        checks = tuple(f"job-{i}-" + "y" * 100 for i in range(25)) + ("lint", "test")
        self.fake.prs[REPO_A]["open"] = [
            pr_node(n, issue=issue, files=("evidence/a.json",), checks=checks) for n in range(1, 31)
        ]
        snap = self.run_refresh()
        task = snap["items"][0]["task"]
        self.assertEqual([e["label"] for e in task["issue"]["timeline"]], ["agent:ready"])
        self.assertEqual(
            sorted(c["name"] for c in task["pull_request"]["checks"]), ["lint", "test"]
        )
        # And when even that is too much, items are left out and the repository marked
        # truncated, rather than every refresh failing.
        small = len(snapshot.encode(snap)) // 3
        saved = snapshot.MAX_SNAPSHOT
        snapshot.MAX_SNAPSHOT = small
        try:
            cut = self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        self.assertLessEqual(len(snapshot.encode(cut)), small)
        self.assertIn(REPO_A, cut["truncated"])
        self.assertTrue(cut["items"])

    def test_a_known_missing_approval_waits_for_you(self):
        # Codex's review of dc1eb14: with Billy's records unread, an open clinical PR with no
        # clinician approval sat under "Running / queued", its card silent.
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("evidence/a.json",)
        )
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertIn(tasks.Flag.CLINICAL_APPROVAL_MISSING, state.flags)
        self.assertTrue(state.needs_attention)

    def test_details_too_large_for_one_answer_are_read_in_smaller_batches(self):
        # Codex's review of 877fd21 (blocking): one answer held every pull request's details,
        # and a large but valid one exceeded the transport's limit before anything could be
        # cut, failing every refresh.
        self.fake.prs[REPO_A]["open"] = [pr_node(n, issue=issue_node(10)) for n in range(1, 8)]
        self.fake.max_batch_ok[REPO_A] = 2
        snap = self.run_refresh()
        items = [i for i in snap["items"] if i["repo"] == REPO_A]
        self.assertEqual([i["number"] for i in items], list(range(1, 8)))
        for item in items:
            self.assertEqual(item["task"]["pull_request"]["files"], ["site/a.html"])  # whole
        self.assertNotIn(REPO_A, snap["truncated"])

    def test_a_query_github_stops_for_its_cost_is_split_too(self):
        # Codex's review of 28546f5 (blocking): GitHub can stop a costly query by time or
        # resources, before the answer reaches the size cap.
        heavy = json.dumps(
            {"data": None, "errors": [{"type": "RESOURCE_LIMITS_EXCEEDED", "message": "x"}]}
        ).encode()
        for failure in ((200, {}, heavy), (502, {}, b""), (504, {}, b""), TimeoutError()):
            with self.subTest(failure=repr(failure)[:40]):
                self.fake.prs[REPO_A]["open"] = [
                    pr_node(n, issue=issue_node(10)) for n in range(1, 8)
                ]
                self.fake.max_batch_ok[REPO_A] = 2
                if isinstance(failure, Exception):
                    real = self.fake.__call__

                    def call(method, path, headers, body, real=real):
                        if path == "/graphql" and body.count(b"pullRequest(number:") > 2:
                            raise TimeoutError()
                        return real(method, path, headers, body)

                    fake = call
                else:
                    self.fake.batch_failure = failure
                    fake = self.fake
                github = gh.GitHub(APP_ID, KEY, transport=fake, clock=lambda: NOW.timestamp())
                snap = snapshot.refresh(self.cfg, github, NOW)
                numbers = [i["number"] for i in snap["items"] if i["repo"] == REPO_A]
                self.assertEqual(numbers, list(range(1, 8)))

    def test_when_github_is_down_the_refresh_fails_after_a_bounded_number_of_requests(self):
        self.fake.prs[REPO_A]["open"] = [pr_node(n, issue=issue_node(10)) for n in range(1, 21)]
        self.fake.down = True
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, "http-502")
        detail_calls = sum("pullRequest(number:" in q for q in self.fake.queries)
        self.assertLessEqual(detail_calls, 3 * 20 + 2)

    def test_a_merged_prs_current_issue_link_is_no_evidence_of_authorisation(self):
        # Codex's review of 28546f5 (blocking): GitHub shows a PR's closing issue as it is
        # now, not as it was at the merge.
        recent = (NOW - timedelta(days=1)).isoformat()
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [
            pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        ]
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["issue"])
        self.assertEqual(item["issue"]["number"], 10)  # still shown
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.MERGED)
        self.assertIn(tasks.Flag.AUTHORIZATION_UNVERIFIED, state.flags)
        self.assertNotIn(tasks.Flag.ISSUE_NOT_LINKED, state.flags)
        self.assertFalse(state.needs_attention)

    def test_one_pull_request_too_large_is_read_without_its_heavy_parts(self):
        self.fake.prs[REPO_A]["open"] = [
            pr_node(1, issue=issue_node(10), files=("evidence/a.json",)),
            pr_node(2, issue=issue_node(10)),
        ]
        self.fake.too_large = {1}
        snap = self.run_refresh()
        heavy, fine = snap["items"][:2]
        pull = heavy["task"]["pull_request"]
        # Read lite: files and checks not known; reviews, which are small, are kept (4945de9).
        self.assertEqual((pull["files"], pull["checks"]), (None, None))
        self.assertEqual(pull["reviews"], [])
        state = tasks.derive(self.task_of(heavy))
        for flag in (
            tasks.Flag.FILES_UNVERIFIED,
            tasks.Flag.CHECKS_UNVERIFIED,
            tasks.Flag.CLINICAL_APPROVAL_MISSING,  # files may be clinical; reviews read: none
        ):
            self.assertIn(flag, state.flags)  # "not known", never clean
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, state.flags)
        self.assertEqual(fine["task"]["pull_request"]["files"], ["site/a.html"])

    def test_an_approved_open_clinical_pr_shows_the_approval(self):
        # Codex's review of 877fd21: with Billy's records unread, the view showed approval as
        # still needed, guessing from the state.
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=[review_node()])
        self.fake.prs[REPO_A]["open"][0] = node
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertIn(tasks.Flag.CLINICIAN_APPROVED, state.flags)
        self.assertNotIn(tasks.Flag.CLINICAL_APPROVAL_MISSING, state.flags)
        self.assertTrue(views.clinician_approved(state))

    def test_a_renamed_file_makes_the_file_list_incomplete(self):
        # Codex's review of f37d0c7 (blocking): a rename lists only the new path, so a move out
        # of a clinical folder would hide where it came from.
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("site/moved.md",), renamed=("site/moved.md",)
        )
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["task"]["pull_request"]["files"], ["site/moved.md"])
        self.assertIs(item["task"]["pull_request"]["files_complete"], False)
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, tasks.derive(self.task_of(item)).flags)

    def test_a_merged_pr_with_unknown_files_keeps_its_known_warnings(self):
        # Codex's review of 198a66e (blocking): a rename made a merged PR unreadable, hiding
        # that someone other than the owner merged it.
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=recent,
            issue=issue_node(10),
            files=("site/moved.md",),
            renamed=("site/moved.md",),
        )
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        node["review_totals"] = {OWNER: 500}  # the clinician's reviews incomplete too
        self.fake.prs[REPO_A]["open"], self.fake.prs[REPO_A]["closed"] = [], [node]
        item = self.run_refresh()["items"][0]
        pull = item["task"]["pull_request"]
        self.assertIs(pull["files_complete"], False)
        self.assertIsNone(pull["reviews"])
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, state.flags)
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, state.flags)
        self.assertIn(tasks.Flag.REVIEWS_UNVERIFIED, state.flags)
        # Nothing unknown is claimed either way.
        self.assertNotIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_a_merged_pr_with_no_issue_and_an_unknown_merger_is_still_judged(self):
        # Codex's review of 3f7d3c2 (blocking): a missing issue, or a merger GitHub can't name
        # (a deleted account), made the merged PR unreadable and hid its warnings.
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=recent)  # no linked issue
        node["mergedBy"] = None
        self.fake.prs[REPO_A]["open"], self.fake.prs[REPO_A]["closed"] = [], [node]
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["issue"])
        self.assertIsNone(item["task"]["pull_request"]["merged_by"])
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGER_UNKNOWN, state.flags)
        self.assertIn(tasks.Flag.AUTHORIZATION_UNVERIFIED, state.flags)

    def test_a_known_clinical_path_in_a_renamed_list_still_counts(self):
        # Codex's review of 3f7d3c2: a rename threw away paths that showed clinical content.
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=recent,
            issue=issue_node(10),
            files=("evidence/study.md", "site/moved.md"),
            renamed=("site/moved.md",),
        )
        self.fake.prs[REPO_A]["open"], self.fake.prs[REPO_A]["closed"] = [], [node]
        item = self.run_refresh()["items"][0]
        task = self.reviewed(item)
        state = tasks.derive(task)
        self.assertIn(tasks.Flag.CLINICAL, state.flags)
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, state.flags)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_unknown_reviews_give_no_clinical_approval(self):
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("evidence/study.md",)
        )
        self.fake.prs[REPO_A]["open"][0]["review_totals"] = {OWNER: 500}
        item = self.run_refresh()["items"][0]
        state = tasks.derive(self.reviewed(item))
        self.assertEqual(state.state, tasks.State.CLINICAL_REVIEW)
        self.assertIn(tasks.Flag.REVIEWS_UNVERIFIED, state.flags)

    def test_a_manually_dispatched_run_never_counts(self):
        # Codex's review of f37d0c7 (blocking): GitHub leaves runs from workflow_dispatch out of
        # a PR's required checks.
        for event, flag in (
            ("pull_request", tasks.Flag.CHECKS_PASSED),
            ("push", tasks.Flag.CHECKS_PASSED),
            ("workflow_dispatch", tasks.Flag.CHECKS_MISSING),
            ("schedule", tasks.Flag.CHECKS_MISSING),
        ):
            with self.subTest(event=event):
                self.fake.prs[REPO_A]["closed"] = []
                self.fake.prs[REPO_A]["open"] = [
                    pr_node(
                        1,
                        issue=issue_node(10),
                        check_event=event,
                    )
                ]
                item = self.run_refresh()["items"][0]
                self.assertIn(flag, tasks.derive(self.reviewed(item)).flags)

    def test_closed_pages_are_read_while_they_reach_into_the_window(self):
        # Codex's review of f37d0c7: more closed pull requests could lie past the first page.
        # Fable's pre-review of 8152df0: so pages are read while the last one is in the window,
        # and only past CLOSED_PAGES is the repository marked truncated.
        recent = (NOW - timedelta(days=2)).isoformat()
        total = snapshot.CLOSED_PAGES * self.fake.closed_page + 1
        self.fake.prs[REPO_B]["closed"] = [
            pr_node(100 + i, state="CLOSED", closed_at=recent) for i in range(total)
        ]
        self.assertIn(REPO_B, self.run_refresh()["truncated"])
        self.fake.prs[REPO_B]["closed"].pop()  # exactly CLOSED_PAGES full pages: no more
        self.assertNotIn(REPO_B, self.run_refresh()["truncated"])

    def test_bumped_old_prs_never_push_a_recent_unsafe_merge_off_the_list(self):
        # Fable's pre-review of 8152df0: a comment on 30 old closed pull requests put a recent
        # merge by someone else 31st, past the only page read.
        old = (NOW - timedelta(days=60)).isoformat()
        bumped = (NOW - timedelta(hours=1)).isoformat()
        recent = (NOW - timedelta(days=4)).isoformat()
        merge = pr_node(500, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        merge["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["closed"] = [
            pr_node(400 + i, state="CLOSED", closed_at=old, updated_at=bumped) for i in range(30)
        ] + [merge]
        snap = self.run_refresh()
        item = next(i for i in snap["items"] if i["number"] == 500)
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertNotIn(REPO_A, snap["truncated"])

    def test_a_failed_refresh_says_when_the_token_outlived_it(self):
        # Codex's review of bf76866: a failed revoke was reported only on success.
        self.fake.fail["/graphql"] = (502, {}, b"")
        self.fake.fail["/installation/token"] = (500, {}, b"")
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, "http-502+token-not-revoked")

    def test_the_size_limit_is_measured_as_written(self):
        # Codex's review of 1cc6cf8: it measured compact JSON, but the file is indented.
        written = len(snapshot.encode(self.run_refresh()))
        compact = len(json.dumps(self.run_refresh()))
        self.assertGreater(written, compact)
        saved = snapshot.MAX_SNAPSHOT
        limit = (written + compact) // 2  # compact fits, written doesn't
        snapshot.MAX_SNAPSHOT = limit
        try:
            snap = self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        # It was cut to fit, measured as written (dc1eb14: cutting, not failing).
        self.assertLessEqual(len(snapshot.encode(snap)), limit)

    def test_a_removal_by_a_deleted_account_still_withdraws(self):
        # Codex's review of f772122 (blocking): skipping it left the authorisation in force.
        issue = issue_node(10)
        issue["timelineItems"]["totalCount"] = 2
        issue["timelineItems"]["nodes"].append(
            {
                "__typename": "UnlabeledEvent",
                "createdAt": "2026-11-21T09:00:00Z",
                "actor": None,
                "label": {"name": "agent:ready"},
            }
        )
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue)
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["task"]["issue"]["timeline"][1]["actor"], "ghost")
        authorised = dict(self.task_of(item))
        authorised["issue"] = dict(
            authorised["issue"], timeline=authorised["issue"]["timeline"][:1]
        )
        self.assertNotEqual(tasks.derive(self.task_of(item)).state, tasks.derive(authorised).state)

    def test_an_issue_in_another_repository_gives_no_issue(self):
        # Codex's review of f772122: its number would point at the wrong issue here.
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10, repo=REPO_B))
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["linked_issues"], 1)
        self.assertIsNone(item["issue"])
        self.assertIsNone(item["task"]["issue"])

    def test_authorisation_comes_only_from_label_events(self):
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10, actor="someone"))
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["task"]["issue"]["timeline"][0]["actor"], "someone")
        self.assertEqual(tasks.derive(self.task_of(item)).state, tasks.State.UNSAFE)

    def failing(self, failure, code, prefix="/graphql"):
        self.fake.fail[prefix] = failure
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, code)

    def test_each_failure_has_a_reason_and_the_token_is_still_revoked(self):
        cases = (
            ((403, {"x-ratelimit-remaining": "0"}, b"{}"), "rate-limited"),
            ((429, {}, b"{}"), "rate-limited"),
            ((502, {}, b"<html>"), "http-502"),
            ((200, {}, b"not json"), "bad-response"),
            ((200, {}, b"{" + b" " * gh.MAX_RESPONSE + b"}"), "too-large"),
            (
                (200, {}, json.dumps({"errors": [{"type": "RATE_LIMITED"}]}).encode()),
                "rate-limited",
            ),
            ((200, {}, json.dumps({"errors": [{"type": "OTHER"}]}).encode()), "graphql-error"),
            ((200, {}, json.dumps({"data": {"repository": {"open": 1}}}).encode()), "bad-response"),
            (TimeoutError(), "timeout"),
            (ConnectionResetError(), "network"),
        )
        for failure, code in cases:
            with self.subTest(code=code, failure=repr(failure)[:40]):
                self.fake = FakeGitHub()
                self.failing(failure, code)
                self.assertEqual(self.fake.revoked, 1)

    def test_a_bad_installation_answer_fails_before_any_token(self):
        self.failing((200, {}, b"[]"), "bad-response", prefix="/repos/")
        self.assertNotIn(("POST", "/app/installations/77/access_tokens"), self.fake.calls)


# ---------------------------------------------------------------- the refresher


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
        # Pre-review of 9537b08: accept() errors escaped serve().
        class Broken:
            def accept(self):
                raise OSError(24, "Too many open files")

        lines = []
        with mock.patch.object(server.time, "sleep"):
            server.serve(Broken(), object(), os.getuid(), log=lines.append, once=True)
        self.assertEqual(lines, ["fetcher: error: accept"])

    def test_a_wall_clock_change_never_moves_the_floor_within_a_boot(self):
        # Codex's reviews of a1e05e5 and b24ac2d: a recorded future time held refreshes until
        # the clock caught up, and then a clock moved back let a refresh skip the floor. Within
        # one boot the floor follows time since boot, which a wall-clock change can't move.
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
        # Codex's review of 198a66e: without a boot id it fell back to the wall clock.
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
        # Codex's review of 3f7d3c2 suggested a quick reboot could skip the floor when the boot
        # ids are missing. It can't: a new boot starts after the last attempt, so the real time
        # since it is at least the new time since boot, and taking that boot for the old one
        # (since_boot - last) only ever measures less, never more. Here: an attempt at 5 s of
        # the old boot, then a new boot now at 40 s, at least 40 s later in fact, is held.
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
        # Pre-review of 9537b08: after a reboot the wall clock may be wrong (before it syncs),
        # so a refresh 35 s after the last one, with the clock a few minutes off, got through.
        # A new boot began after the last attempt, so time since boot is a lower bound on the
        # real time since it: under a minute since boot always waits.
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

    def test_an_unreadable_status_file_is_not_no_earlier_attempt(self):
        # Pre-review of 9537b08: any failure to read the status file skipped the floor.
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
        # Codex's review of 9aeff19: a malformed status file was read as "no earlier attempt".
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
        # Codex's review of 69ed8e3: a status object with missing or non-finite times let a
        # refresh skip the floor.
        wall = [NOW.timestamp()]
        self.assertEqual(self.make(lambda: wall[0]).run(), server.OK)
        for bad in (
            b"{}",
            b'{"attempt_epoch": 1}',
            b'{"attempt_epoch": Infinity, "attempt_since_boot": 5}',
            b'{"attempt_epoch": 1, "attempt_since_boot": NaN}',
            b'{"attempt_epoch": 1, "attempt_since_boot": -5}',
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
        # Fable's pre-review of 8152df0, finding 9: in the same boot, a recorded time since
        # boot later than now made every request "too-soon" until the uptime caught up.
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
        # Pre-review of 9537b08: a failed revoke was lost when the snapshot write then failed.
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
        # Pre-review of 9537b08: a process killed mid-write left a temp file a later process
        # with the same pid couldn't get past.
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
        # Codex's review of 23bfb61: an unexpected exception escaped and stopped the fetcher.
        def broken(cfg):
            raise TypeError("a surprise")

        refresher = self.make(lambda: NOW.timestamp())
        refresher.github = broken
        self.assertEqual(refresher.run(), b"failed:internal\n")
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual((status["result"], status["reason"]), ("failed", "internal"))

    def test_a_short_write_never_leaves_a_truncated_file(self):
        # Codex's review of bf76866: os.write may write less than asked.
        real_write = os.write

        def dribble(fd, data):
            return real_write(fd, bytes(data[:7]))  # a few bytes at a time

        with mock.patch.object(snapshot.os, "write", side_effect=dribble):
            self.assertEqual(self.make(lambda: NOW.timestamp()).run(), server.OK)
        written = snapshot.read_json(self.cfg.snapshot_dir, snapshot.SNAPSHOT)
        self.assertEqual(len(written["items"]), 3)

    def test_a_failed_folder_sync_after_the_rename_is_not_a_failed_write(self):
        # Codex's review of 198a66e: the new snapshot was in place, but the refresh said it
        # failed and the status kept the old time.
        # (The attempt recorded before any network work is synced first; only later syncs
        # fail here.)
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
        # Codex's review of c5ccf49 (blocking): a failed folder sync of the attempt record was
        # ignored, so after a power cut the attempt could vanish and a refresh repeat within
        # the minute.
        real = os.fsync

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(5, "sync failed")
            return real(fd)

        with mock.patch.object(snapshot.os, "fsync", side_effect=fsync):
            self.assertEqual(self.make(lambda: NOW.timestamp()).run(), b"failed:write\n")
        self.assertEqual(self.fake.calls, [])  # nothing sent to GitHub

    def test_a_token_that_could_not_be_revoked_is_reported(self):
        # Codex's review of 1cc6cf8: a good refresh said "ok" while the token stayed valid.
        self.fake.fail["/installation/token"] = (500, {}, b"")
        self.assertEqual(self.make(lambda: NOW.timestamp()).run(), b"ok:token-not-revoked\n")
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual((status["result"], status["reason"]), ("ok", "token-not-revoked"))
        self.assertTrue((self.cfg.snapshot_dir / snapshot.SNAPSHOT).exists())

    def test_a_file_that_misses_the_folders_group_is_refused(self):
        # Codex's review of f772122 (blocking): without setgid, files took the fetcher's own
        # group and the web app couldn't read them. Needs root to give the folder another group.
        if os.getuid() != 0:
            self.skipTest("needs root to set the folder's group")
        os.chown(self.cfg.snapshot_dir, -1, 1)  # another group, no setgid
        os.chmod(self.cfg.snapshot_dir, 0o750)
        self.assertEqual(self.make(lambda: NOW.timestamp()).run(), b"failed:write\n")
        self.assertFalse((self.cfg.snapshot_dir / snapshot.SNAPSHOT).exists())

    def test_one_refresh_at_a_time_across_processes(self):
        # Codex's review of f772122: the floor was per process and recorded after the network
        # work, so fetch-now and the service could both start.
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


# ---------------------------------------------------------------- the socket


class Socket(Base):
    def serve_once(self, client_uid, request):
        path = self.base / "fetch.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        self.addCleanup(listener.close)
        lines = []

        class Fixed:
            def run(self):
                return server.OK

        thread = threading.Thread(
            target=server.serve,
            args=(listener, Fixed(), client_uid),
            kwargs={"log": lines.append, "once": True},
            daemon=True,
        )
        thread.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5)
            conn.connect(str(path))
            conn.sendall(request)
            reply = conn.recv(64)
        thread.join(5)
        return reply, lines

    def test_the_web_apps_account_gets_a_refresh(self):
        reply, lines = self.serve_once(os.getuid(), server.REQUEST)
        self.assertEqual(reply, server.OK)
        self.assertEqual(lines, ["fetcher: refresh: ok"])

    def test_any_other_account_is_refused(self):
        reply, lines = self.serve_once(os.getuid() + 1, server.REQUEST)
        self.assertEqual(reply, server.REFUSED)
        self.assertEqual(lines, ["fetcher: refused: wrong account"])

    def test_anything_but_the_request_is_refused(self):
        reply, _ = self.serve_once(os.getuid(), b"STOP\n")
        self.assertEqual(reply, server.REFUSED)


# ---------------------------------------------------------------- start-up checks


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
                self.assertNotEqual(code, 0)
                refresher.assert_not_called()
        code, github_checks, refresher, _ = self.main_with(
            ["selfcheck", "--github", "--config", "x"], failing
        )
        self.assertNotEqual(code, 0)
        github_checks.assert_not_called()
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


class AuditOf80e8fb3(Base):
    """Round 9: code that was right but that no test held in place, and one real gap."""

    def run_refresh(self):
        return snapshot.refresh(self.cfg, client(self.fake), NOW)

    def task_of(self, item):
        return dict(item["task"], paused=False)

    def reviewed(self, item):
        return Refresh.reviewed(self, item)

    def test_a_failing_required_run_from_another_event_is_never_dropped(self):
        node = pr_node(1, issue=issue_node(10))
        commit = node["commits"]["nodes"][0]["commit"]
        commit["checkSuites"]["nodes"].append(
            {
                "app": {"slug": "github-actions"},
                "workflowRun": {"event": "workflow_dispatch"},
                "checkRuns": {
                    "totalCount": 1,
                    "nodes": [{"name": "test", "status": "COMPLETED", "conclusion": "FAILURE"}],
                },
            }
        )
        commit["checkSuites"]["totalCount"] = 2
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)
        # Its successes still never count, and a harmless one changes nothing.
        commit["checkSuites"]["nodes"][1]["checkRuns"]["nodes"][0]["conclusion"] = "SUCCESS"
        item = self.run_refresh()["items"][0]
        self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_more_open_prs_than_one_page_marks_the_repository_truncated(self):
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number:" not in body and b"open:" in body:
                answer = json.loads(data)
                answer["data"]["repository"]["open"]["totalCount"] += 5
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        self.assertIn(REPO_A, snapshot.refresh(self.cfg, github, NOW)["truncated"])

    def test_more_suites_than_returned_never_pass(self):
        node = pr_node(1, issue=issue_node(10))
        node["commits"]["nodes"][0]["commit"]["checkSuites"]["totalCount"] = 5
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_only_success_skipped_and_neutral_pass(self):
        for conclusion in ("CANCELLED", "TIMED_OUT", "ACTION_REQUIRED", "STALE", "FAILURE", None):
            with self.subTest(conclusion):
                node = pr_node(1, issue=issue_node(10))
                run = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
                run["checkRuns"]["nodes"][0]["conclusion"] = conclusion
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_an_odd_review_in_a_clinicians_list_makes_the_reviews_not_known(self):
        no_time = review_node(state="CHANGES_REQUESTED")
        no_time["submittedAt"] = None
        bot = review_node(state="APPROVED", bot=True)
        other = review_node("someone-else", "APPROVED")
        for odd in (no_time, bot, other):
            with self.subTest(odd=odd["author"]):
                node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",))
                self.fake.prs[REPO_A]["open"][0] = node
                real = self.fake.__call__

                def call(method, path, headers, body, odd=odd, real=real):
                    status, h, data = real(method, path, headers, body)
                    if path == "/graphql" and b"rv0:" in body:
                        answer = json.loads(data)
                        for p in answer["data"]["repository"].values():
                            if p and "rv0" in p:
                                p["rv0"] = {"totalCount": 1, "nodes": [odd]}
                        data = json.dumps(answer).encode()
                    return status, h, data

                github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
                item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
                self.assertIsNone(item["task"]["pull_request"]["reviews"])

    def test_more_runs_than_returned_never_pass(self):
        # Audit of 8c62413: a matrix of more than the runs GitHub returned.
        node = pr_node(1, issue=issue_node(10))
        suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["checkRuns"]["totalCount"] = len(suite["checkRuns"]["nodes"]) + 1
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertFalse(item["task"]["pull_request"]["checks_complete"])
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, tasks.derive(self.reviewed(item)).flags)

    def test_results_for_another_commit_are_never_read(self):
        # Audit of 8c62413: every required name passed, but on a commit that isn't the head.
        node = pr_node(1, issue=issue_node(10))
        node["commits"]["nodes"][0]["commit"]["oid"] = "c" * 40
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["pull_request"]["checks"])
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_a_symlinked_key_or_folder_is_never_followed(self):
        real_key = self.base / "real.pem"
        real_key.write_text("synthetic")
        link = self.base / "link.pem"
        link.symlink_to(real_key)
        with self.assertRaises(gh.FetchError):
            server.read_key(link)
        target = self.base / "elsewhere"
        target.mkdir()
        folder = self.base / "linked-folder"
        folder.symlink_to(target)
        with self.assertRaises(OSError):
            snapshot.write_json(folder, snapshot.STATUS, {"a": 1})
        self.assertEqual(list(target.iterdir()), [])


class CodexReviewOfB1fef32(Base):
    def run_refresh(self, github=None):
        return snapshot.refresh(self.cfg, github or client(self.fake), NOW)

    def task_of(self, item):
        return dict(item["task"], paused=False)

    def reviewed(self, item):
        return Refresh.reviewed(self, item)

    def test_a_success_in_another_case_never_passes(self):
        # Blocking: "success" skipped the freshness check and still read as passed.
        for odd in ("success", "Success", "SUCCEEDED", ""):
            with self.subTest(odd=odd):
                node = pr_node(1, issue=issue_node(10))
                runs = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
                for r in runs["checkRuns"]["nodes"]:
                    r["conclusion"] = odd
                    r["completedAt"] = "2020-01-01T00:00:00Z"  # stale too
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                pull = item["task"]["pull_request"]
                self.assertFalse(pull["checks_complete"])
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)
                self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, flags)

    def test_a_deep_error_that_nulls_the_pr_is_retried_not_given_up(self):
        # Blocking: GitHub nulled the whole PR for an error deep in its commits, and the
        # fetcher marked it unreadable, losing a known unsafe merge a retry could read.
        merged_at = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=merged_at, issue=issue_node(10))
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        real = self.fake.__call__
        for field, path in (
            ("commits(", ["repository", "p0", "commits", "nodes", 0, "commit", "status"]),
            ("files(", ["repository", "p0", "files", "nodes", 0, "path"]),
        ):
            with self.subTest(field=field):

                def call(method, url, headers, body, field=field, path=path):
                    status, h, data = real(method, url, headers, body)
                    if url == "/graphql" and b"p0:" in body and field.encode() in body:
                        answer = json.loads(data)
                        answer["data"]["repository"]["p0"] = None
                        answer["errors"] = [{"type": "X", "path": path}]
                        data = json.dumps(answer).encode()
                    return status, h, data

                github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
                item = self.run_refresh(github)["items"][0]
                self.assertIsNotNone(item["task"])
                s = tasks.derive(self.task_of(item))
                self.assertEqual(s.state, tasks.State.UNSAFE)
                self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, s.flags)


class CodexReviewOf099ef9b(Base):
    def run_refresh(self, github=None):
        return snapshot.refresh(self.cfg, github or client(self.fake), NOW)

    def task_of(self, item):
        return dict(item["task"], paused=False)

    def reviewed(self, item):
        return Refresh.reviewed(self, item)

    def with_status(self, created):
        node = pr_node(1, issue=issue_node(10), statuses=[("test", "SUCCESS")])
        context = node["commits"]["nodes"][0]["commit"]["status"]["contexts"][0]
        if created is None:
            del context["createdAt"]
        else:
            context["createdAt"] = created
        self.fake.prs[REPO_A]["open"][0] = node
        return self.run_refresh()["items"][0]

    def test_an_old_successful_status_never_passes_a_required_check(self):
        # Blocking: a fresh check run beside an old successful status of the same name passed.
        for created in ("2020-01-01T00:00:00Z", None, "not a time"):
            with self.subTest(created=created):
                item = self.with_status(created)
                self.assertFalse(item["task"]["pull_request"]["checks_complete"])
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)
        item = self.with_status((NOW - timedelta(days=1)).isoformat())  # fresh: fine
        self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def heavy_unless_core(self):
        """GitHub stops any query that asks for more than the core fields of PR 1."""
        real = self.fake.__call__
        heavy = json.dumps(
            {"data": None, "errors": [{"type": "RESOURCE_LIMITS_EXCEEDED", "message": "x"}]}
        ).encode()
        asked = []

        def call(method, path, headers, body):
            if path == "/graphql" and b"pullRequest(number: 1)" in body:
                asked.append(body)
                if b"closingIssuesReferences" in body:
                    return 200, {}, heavy
            return real(method, path, headers, body)

        return gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp()), asked

    def merged_by_stranger(self):
        merged_at = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=merged_at, issue=issue_node(10))
        node["mergedBy"] = {"__typename": "User", "login": "someone-else"}
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]

    def test_a_lite_read_still_too_heavy_falls_back_to_the_core(self):
        # Blocking: the heavy error escaped and failed the whole refresh.
        self.merged_by_stranger()
        github, asked = self.heavy_unless_core()
        item = self.run_refresh(github)["items"][0]
        self.assertIsNotNone(item["task"])
        s = tasks.derive(self.task_of(item))
        self.assertEqual(s.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, s.flags)
        self.assertNotIn(b"closingIssuesReferences", asked[-1])  # the core only, last

    def test_a_retry_still_too_heavy_falls_back_to_the_core(self):
        self.merged_by_stranger()
        heavy_github, asked = self.heavy_unless_core()
        first = []

        def call(method, path, headers, body):
            # The full read answers with an error on the title, so a retry is asked for; the
            # retry, without the title, is still too heavy.
            if path == "/graphql" and b"pullRequest(number: 1)" in body and not first:
                first.append(1)
                status, h, data = self.fake(method, path, headers, body)
                answer = json.loads(data)
                # GitHub nulls the whole pull request, so only a retry can read it (Codex's
                # review of 0f79663: nulling the title alone never asked for one).
                answer["data"]["repository"]["p0"] = None
                answer["errors"] = [{"type": "X", "path": ["repository", "p0", "title"]}]
                return status, h, json.dumps(answer).encode()
            return heavy_github.transport(method, path, headers, body)

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = self.run_refresh(github)["items"][0]
        self.assertIsNotNone(item["task"])
        self.assertEqual(tasks.derive(self.task_of(item)).state, tasks.State.UNSAFE)
        # After the full read: the retry (too heavy), then the core (Codex's review of 05062fc:
        # a retry's failure never starts the reads over).
        self.assertEqual(len(asked), 2)
        self.assertNotIn(b"closingIssuesReferences", asked[-1])

    def test_running_out_of_requests_has_its_own_reason(self):
        # Never taken for a heavy query: the budget's own code is not HEAVY.
        self.assertNotIn("over-budget", snapshot.HEAVY)
        self.assertRegex("over-budget", server.REASON)


class CodexReviewOf0f79663(CodexReviewOf099ef9b):
    def test_errors_on_every_piece_never_spend_the_budget_before_the_core(self):
        # Blocking: each optional piece in error used a retry, and the budget ran out before
        # the core read that would show the unsafe merge.
        self.merged_by_stranger()
        real = self.fake.__call__
        pieces = [p for p in snapshot.PIECES if p != "reviews"]
        markers = {
            "files": b"files(",
            "commits": b"commits(",
            "potentialMergeCommit": b"potentialMergeCommit",
            "closingIssuesReferences": b"closingIssuesReferences",
        }

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number: 1)" in body:
                # The body is JSON, so a newline in the query is "\\n" there (Codex's review of
                # 9650d02: a literal newline never matched, so those pieces were never in error).
                asked = [p for p in pieces if markers.get(p, f"\\n  {p}".encode()) in body]
                requests.append(asked)
                if asked:
                    answer = json.loads(data)
                    answer["data"]["repository"]["p0"] = None
                    answer["errors"] = [{"type": "X", "path": ["repository", "p0", asked[0]]}]
                    data = json.dumps(answer).encode()
            return status, h, data

        requests = []
        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = self.run_refresh(github)["items"][0]
        # Every optional piece was asked for, and in error, until the core read (no piece).
        self.assertIn("title", requests[0])
        self.assertEqual(requests[-1], [])
        self.assertIsNotNone(item["task"])
        s = tasks.derive(self.task_of(item))
        self.assertEqual(s.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, s.flags)

    def with_lint(self, kind, name, outcome):
        node = pr_node(1, issue=issue_node(10))
        commit = node["commits"]["nodes"][0]["commit"]
        if kind == "status":
            commit["status"] = {
                "contexts": [
                    {"context": name, "state": outcome, "createdAt": "2026-11-23T00:00:00Z"}
                ]
            }
        else:
            commit["checkSuites"]["nodes"][0]["checkRuns"]["nodes"].append(
                {
                    "name": name,
                    "status": "COMPLETED",
                    "conclusion": outcome,
                    "completedAt": "2026-11-23T00:00:00Z",
                }
            )
            commit["checkSuites"]["nodes"][0]["checkRuns"]["totalCount"] += 1
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        return tasks.derive(self.reviewed(item)).flags

    def test_a_failure_under_another_case_of_a_required_name_counts(self):
        # Blocking: a failing status "LINT" was ignored beside a passing run "lint".
        for kind in ("status", "run"):
            with self.subTest(kind=kind):
                flags = self.with_lint(kind, "LINT", "FAILURE")
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)
                self.assertIn(tasks.Flag.CHECKS_FAILING, flags)
        # A pass under another case adds nothing, and never stands in for the exact name.
        self.assertIn(tasks.Flag.CHECKS_PASSED, self.with_lint("run", "LINT", "SUCCESS"))
        node = pr_node(1, issue=issue_node(10), checks=("LINT", "test"))
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_another_case_counts_in_suites_whose_event_cant_count(self):
        # A failing run under another case, in a suite started by hand or with no workflow
        # run, still keeps the checks from passing.
        for workflow_run in ({"event": "workflow_dispatch"}, None):
            with self.subTest(workflow_run=workflow_run):
                node = pr_node(1, issue=issue_node(10))
                commit = node["commits"]["nodes"][0]["commit"]
                commit["checkSuites"]["nodes"].append(
                    {
                        "app": {"slug": "github-actions"},
                        "workflowRun": workflow_run,
                        "checkRuns": {
                            "totalCount": 1,
                            "nodes": [
                                {"name": "LINT", "status": "COMPLETED", "conclusion": "FAILURE"}
                            ],
                        },
                    }
                )
                commit["checkSuites"]["totalCount"] = 2
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)


class CodexReviewOf05062fc(unittest.TestCase):
    """Codex's review of 05062fc (blocking): a split batch could spend the request budget
    before every pull request's core read."""

    class Adversary:
        """GitHub failing every read but the core one, each a different way."""

        deadline = None

        def __init__(self):
            self.requests = 0

        def graphql(self, token, query, variables, placeable=None):
            self.requests += 1
            numbers = [int(n) for n in re.findall(r"pullRequest\(number: (\d+)\)", query)]
            if "files(" in query:
                raise gh.FetchError("http-502")  # every full read: transient
            if "closingIssuesReferences" in query:
                raise gh.FetchError("too-heavy")  # every lite read and retry: too heavy
            return {"repository": {f"p{i}": {"number": n} for i, n in enumerate(numbers)}}

    def test_every_pull_request_reaches_its_core_read_within_the_budget(self):
        github = self.Adversary()
        numbers = list(range(1, 11))
        got = snapshot._details(github, "token", "o", "r", numbers)
        self.assertEqual([n for n, _, _ in got], numbers)
        self.assertTrue(all(isinstance(node, dict) for _, node, _ in got))
        self.assertLessEqual(github.requests, 7 * len(numbers) + 2)

    def test_a_retrys_failure_never_starts_the_reads_over(self):
        # Ten pull requests, each answered with a Retry, each retry too heavy: one batch read,
        # then a retry and a core read each, never a split.
        class Partial(self.Adversary):
            def graphql(self, token, query, variables, placeable=None):
                self.requests += 1
                numbers = [int(n) for n in re.findall(r"pullRequest\(number: (\d+)\)", query)]
                if len(numbers) > 1:
                    data = {"repository": {f"p{i}": None for i in range(len(numbers))}}
                    paths = tuple(("repository", f"p{i}", "title") for i in range(len(numbers)))
                    raise gh.FetchError("graphql-error", paths, data)
                if "closingIssuesReferences" in query:
                    raise gh.FetchError("too-heavy")
                return {"repository": {"p0": {"number": numbers[0]}}}

        github = Partial()
        got = snapshot._details(github, "token", "o", "r", list(range(1, 11)))
        self.assertTrue(all(isinstance(node, dict) for _, node, _ in got))
        self.assertEqual(github.requests, 1 + 10 * 2)


class PreReviewOfE995f6a(CodexReviewOf099ef9b):
    def deep_error(self, field):
        """A passing PR whose answer has an error deep in its checks, nulled there."""
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10))
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"commits(" in body and b"pullRequest(number: 1)" in body:
                answer = json.loads(data)
                commit = answer["data"]["repository"]["p0"]["commits"]["nodes"][0]["commit"]
                at = ["repository", "p0", "commits", "nodes", 0, "commit"]
                if field == "status":
                    commit["status"] = None
                    at.append("status")
                else:
                    commit["checkSuites"]["nodes"][0]["app"] = None
                    at += ["checkSuites", "nodes", 0, "app"]
                answer["errors"] = [{"type": "X", "path": at}]
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        return self.run_refresh(github)["items"][0]

    def test_a_deep_error_in_the_checks_never_reads_as_passed(self):
        for field in ("status", "app"):
            with self.subTest(field=field):
                item = self.deep_error(field)
                self.assertFalse(item["task"]["pull_request"]["checks_complete"])
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)

    def another_suite(self, app, conclusion):
        node = pr_node(1, issue=issue_node(10))
        commit = node["commits"]["nodes"][0]["commit"]
        commit["checkSuites"]["nodes"].append(
            {
                "app": app,
                "checkRuns": {
                    "totalCount": 1,
                    "nodes": [{"name": "lint", "status": "COMPLETED", "conclusion": conclusion}],
                },
            }
        )
        commit["checkSuites"]["totalCount"] = 2
        self.fake.prs[REPO_A]["open"][0] = node
        return tasks.derive(self.reviewed(self.run_refresh()["items"][0])).flags

    def test_another_apps_failure_keeps_the_checks_from_passing(self):
        for app in ({"slug": "other-ci"}, None):
            with self.subTest(app=app):
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, self.another_suite(app, "FAILURE"))
                # Its success is harmless: never counted, never in the way.
                self.assertIn(tasks.Flag.CHECKS_PASSED, self.another_suite(app, "SUCCESS"))

    def test_a_required_status_in_an_unknown_state_is_not_known(self):
        node = pr_node(1, issue=issue_node(10), statuses=[("lint", "WHATEVER")])
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertFalse(item["task"]["pull_request"]["checks_complete"])

    def test_more_issue_events_than_returned_leave_the_issue_not_known(self):
        issue = issue_node(10)
        issue["timelineItems"]["totalCount"] = 101
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue)
        self.assertIsNone(self.run_refresh()["items"][0]["task"]["issue"])


class CodexReviewOf2736aee(CodexReviewOf099ef9b):
    def flags_for(self, node):
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        return item, tasks.derive(self.reviewed(item)).flags

    def test_a_status_left_out_is_not_known(self):
        node = pr_node(1, issue=issue_node(10))
        del node["commits"]["nodes"][0]["commit"]["status"]
        item, flags = self.flags_for(node)
        self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)

    def test_an_old_or_untimed_success_is_never_masked_by_a_fresh_one(self):
        for done in ("2020-01-01T00:00:00Z", None):
            with self.subTest(done=done):
                node = pr_node(1, issue=issue_node(10))
                commit = node["commits"]["nodes"][0]["commit"]
                old = {"name": "lint", "status": "COMPLETED", "conclusion": "SUCCESS"}
                if done is not None:
                    old["completedAt"] = done
                commit["checkSuites"]["nodes"].append(
                    {
                        "app": {"slug": "github-actions"},
                        "workflowRun": {"event": "pull_request"},
                        "checkRuns": {"totalCount": 1, "nodes": [old]},
                    }
                )
                commit["checkSuites"]["totalCount"] = 2
                item, flags = self.flags_for(node)
                self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)


class CodexReviewOfA34154f(CodexReviewOf099ef9b):
    def test_a_test_merge_commits_status_left_out_is_not_known(self):
        merge = {"checkSuites": {"totalCount": 0}}  # no status key at all
        node = pr_node(1, issue=issue_node(10), merge_commit=merge)
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)


class ChecksFreshUntil(CodexReviewOf099ef9b):
    """Freshness changes with time, and a snapshot is read long after it is written: each item
    says when its counted passes stop being fresh, and a reader treats its checks as not known
    after that (Codex's reviews of 05062fc to 28d71fe; owner's decision, 2026-11-25)."""

    def item_for(self, node):
        self.fake.prs[REPO_A]["open"][0] = node
        return self.run_refresh()["items"][0]

    def test_the_earliest_pass_to_go_stale_dates_the_checks(self):
        node = pr_node(1, issue=issue_node(10))
        runs = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["checkRuns"]
        runs["nodes"][1]["completedAt"] = "2026-11-21T08:00:00Z"
        item = self.item_for(node)
        self.assertEqual(item["checks_fresh_until"], "2026-11-28T08:00:00+00:00")
        # A required status's pass dates them too.
        node = pr_node(1, issue=issue_node(10), statuses=[("lint", "SUCCESS")])
        status = node["commits"]["nodes"][0]["commit"]["status"]["contexts"][0]
        status["createdAt"] = "2026-11-20T00:00:00Z"
        self.assertEqual(self.item_for(node)["checks_fresh_until"], "2026-11-27T00:00:00+00:00")

    def test_a_pass_about_to_go_stale_counts_but_is_dated(self):
        soon = NOW - snapshot.CHECK_FRESH + timedelta(seconds=30)
        node = pr_node(1, issue=issue_node(10))
        for r in node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["checkRuns"][
            "nodes"
        ]:
            r["completedAt"] = soon.isoformat()
        item = self.item_for(node)
        self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)
        expected = (soon + snapshot.CHECK_FRESH).astimezone(UTC).isoformat()
        self.assertEqual(item["checks_fresh_until"], expected)

    def test_a_time_too_late_to_date_never_discards_a_known_failure(self):
        # Codex's review of 1e0f9b0 (blocking): adding a week overflowed, and the whole check
        # list, a failure GitHub reported among it, became "not known".
        node = pr_node(1, issue=issue_node(10))
        runs = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["checkRuns"]
        runs["nodes"][0]["completedAt"] = "9999-12-31T23:00:00Z"
        runs["nodes"][1]["conclusion"] = "FAILURE"
        item = self.item_for(node)
        pull = item["task"]["pull_request"]
        self.assertIsNotNone(pull["checks"])
        self.assertFalse(pull.get("checks_complete", True))
        self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)
        # A status the same.
        node = pr_node(1, issue=issue_node(10), statuses=[("lint", "SUCCESS")])
        status = node["commits"]["nodes"][0]["commit"]["status"]["contexts"][0]
        status["createdAt"] = "9999-12-31T23:00:00Z"
        self.assertFalse(self.item_for(node)["task"]["pull_request"].get("checks_complete", True))

    def test_no_checks_read_means_no_date(self):
        merged_at = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=merged_at, issue=issue_node(10))
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        self.assertIsNone(self.run_refresh()["items"][0]["checks_fresh_until"])
        node = pr_node(1, issue=issue_node(10), checks=())
        self.fake.prs[REPO_A]["open"] = [node]
        self.fake.prs[REPO_A]["closed"] = []
        self.assertIsNone(self.run_refresh()["items"][0]["checks_fresh_until"])
        self.assertIsNone(snapshot._unreadable(REPO_A, 1)["checks_fresh_until"])


class CodexReviewOf6e22a60(CodexReviewOf099ef9b):
    def test_a_count_that_cant_be_read_never_hides_a_failure(self):
        # Blocking: a missing or malformed totalCount discarded the nodes GitHub did give.
        for level in ("suites", "runs"):
            for bad in (None, "2", -1, True):
                with self.subTest(level=level, bad=bad):
                    node = pr_node(1, issue=issue_node(10))
                    suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
                    runs = suites["nodes"][0]["checkRuns"]
                    runs["nodes"][0]["conclusion"] = "FAILURE"
                    conn = suites if level == "suites" else runs
                    if bad is None:
                        del conn["totalCount"]
                    else:
                        conn["totalCount"] = bad
                    self.fake.prs[REPO_A]["open"][0] = node
                    item = self.run_refresh()["items"][0]
                    self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
                    flags = tasks.derive(self.reviewed(item)).flags
                    self.assertIn(tasks.Flag.CHECKS_FAILING, flags)


class CodexReviewOfB1f5a1a(CodexReviewOf099ef9b):
    def test_a_count_below_the_nodes_given_is_never_whole(self):
        # Blocking: a count smaller than the nodes GitHub gave read as complete.
        for level in ("suites", "runs"):
            with self.subTest(level=level):
                node = pr_node(1, issue=issue_node(10))
                suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
                conn = suites if level == "suites" else suites["nodes"][0]["checkRuns"]
                conn["totalCount"] = 0
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)

    def test_a_costly_error_on_one_part_keeps_the_rest_of_the_answer(self):
        # Blocking: a resource-limit error placed on one optional part threw the whole answer
        # away, a failure GitHub had reported in it included.
        node = pr_node(1, issue=issue_node(10))
        runs = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["checkRuns"]
        runs["nodes"][0]["conclusion"] = "FAILURE"
        self.fake.prs[REPO_A]["open"][0] = node
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"closingIssuesReferences" in body and b"p0:" in body:
                answer = json.loads(data)
                answer["data"]["repository"]["p0"]["closingIssuesReferences"] = None
                place = ["repository", "p0", "closingIssuesReferences"]
                answer["errors"] = [{"type": "RESOURCE_LIMITS_EXCEEDED", "path": place}]
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = self.run_refresh(github)["items"][0]
        self.assertIsNotNone(item["task"])
        self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)

    def test_a_costly_error_with_no_place_is_still_too_heavy(self):
        def call(method, path, headers, body):
            answer = {"data": {"repository": {}}, "errors": [{"type": "TIMEOUT"}]}
            return 200, {}, json.dumps(answer).encode()

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        with self.assertRaises(gh.FetchError) as caught:
            github.graphql(TOKEN, "query", {})
        self.assertEqual(caught.exception.code, "too-heavy")


class CodexReviewOf96a9e17(CodexReviewOf099ef9b):
    def test_an_error_inside_the_file_list_never_reads_as_complete(self):
        # Blocking: the error was dropped, and with the count matching the nodes the list read
        # as complete, weakening the clinical gate.
        node = pr_node(1, issue=issue_node(10), files=("site/a.html", "site/b.html"))
        self.fake.prs[REPO_A]["open"][0] = node
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"files(" in body and b"p0:" in body:
                answer = json.loads(data)
                place = ["repository", "p0", "files", "nodes", 1, "changeType"]
                answer["errors"] = [{"type": "X", "path": place}]
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = self.run_refresh(github)["items"][0]
        pull = item["task"]["pull_request"]
        self.assertFalse(pull.get("files_complete", True))
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, tasks.derive(self.reviewed(item)).flags)

    def test_a_config_error_is_shown_without_control_characters(self):
        # Should fix: the message may quote the file, and went to logs as it was.
        from mission_control.config import ConfigError, shown

        text = shown(ConfigError("unknown key 'a\nFAKE LOG LINE\x1b[31m'" + "x" * 500))
        self.assertNotRegex(text, "[\x00-\x1f\x7f-\x9f]")
        self.assertLessEqual(len(text), 200)
        self.assertEqual(shown(ConfigError("plain")), "plain")

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


class CodexReviewOf9650d02(CodexReviewOf099ef9b):
    def test_a_result_dated_in_the_future_is_never_fresh(self):
        # Blocking: a future-dated success passed, and dated the checks past seven days.
        later = (NOW + timedelta(days=30)).isoformat()
        node = pr_node(1, issue=issue_node(10))
        runs = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["checkRuns"]
        runs["nodes"][0]["completedAt"] = later
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)
        self.assertFalse(
            self.with_status(later)["task"]["pull_request"].get("checks_complete", True)
        )
        # A minute ahead is clock drift: fresh.
        item = self.with_status((NOW + timedelta(minutes=1)).isoformat())
        self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)


class CodexReviewOf9cc8f43(Base):
    def test_a_repository_is_named_by_position_never_by_its_key(self):
        # Blocking: a key that passes owner/name was still quoted in later messages.
        key = "ghp-abcdefghijklmnop/ghp-qrstuvwxyz0123456789"  # credential-shaped, but valid
        data = config_data(self.base)
        data["repos"] = {key: {"required_checks": ["lint"], "clinical_paths": []}}
        with self.assertRaises(fconfig.ConfigError) as caught:
            fconfig.parse_fetcher(json.dumps(data))
        message = str(caught.exception)
        self.assertIn("repos[0]", message)
        self.assertNotIn("ghp-", message)

    def test_an_empty_page_that_says_more_follow_is_never_the_end(self):
        # Should fix: it was taken as the end, and recent closures could be missed unmarked.
        data = {
            "repository": {
                "open": {"totalCount": 0, "nodes": []},
                "closed": {
                    "nodes": [],
                    "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
                },
            }
        }
        numbers, truncated = snapshot._listing(REPO_A, data, NOW)
        self.assertEqual((numbers, truncated), ([], True))


class CodexReviewOf322b659(Base):
    def test_only_a_github_user_can_be_a_clinician(self):
        # Blocking: an author with no kind, or another kind, was emitted as a User.
        for kind in (None, "Mannequin", "Organization", "EnterpriseUserAccount"):
            with self.subTest(kind=kind):
                review = review_node(OWNER, "APPROVED")
                if kind is None:
                    del review["author"]["__typename"]
                else:
                    review["author"]["__typename"] = kind
                node = pr_node(
                    1, issue=issue_node(10), files=("evidence/a.json",), reviews=(review,)
                )
                self.fake.prs[REPO_A]["open"][0] = node
                item = snapshot.refresh(self.cfg, client(self.fake), NOW)["items"][0]
                self.assertIsNone(item["task"]["pull_request"]["reviews"])

    def test_an_app_named_like_the_owner_never_authorises_or_merges(self):
        # The same for label events and the merger: an app can share a person's name.
        issue = issue_node(10)
        issue["timelineItems"]["nodes"][0]["actor"]["__typename"] = "Bot"
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue)
        item = snapshot.refresh(self.cfg, client(self.fake), NOW)["items"][0]
        state = tasks.derive(dict(item["task"], paused=False))
        self.assertIn(tasks.Flag.UNAUTHORIZED_WORK, state.flags)
        merged_at = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=merged_at, issue=issue_node(10))
        node["mergedBy"] = {"__typename": "Bot", "login": OWNER}
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        item = snapshot.refresh(self.cfg, client(self.fake), NOW)["items"][0]
        state = tasks.derive(dict(item["task"], paused=False))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGER_UNKNOWN, state.flags)

    def test_a_repeated_open_row_marks_the_list_cut_off(self):
        # Should fix: duplicates matched the count, then collapsed silently.
        data = {
            "repository": {
                "open": {"totalCount": 2, "nodes": [{"number": 1}, {"number": 1}]},
                "closed": {"nodes": [], "pageInfo": {"hasNextPage": False}},
            }
        }
        self.assertEqual(snapshot._listing(REPO_A, data, NOW), ([1], True))


class CodexReviewOf07c05d4(Base):
    def test_a_review_with_no_author_in_a_clinicians_list_is_not_known(self):
        # Blocking: skipped as "someone else", it could hide a later changes request.
        approved = review_node(OWNER, "APPROVED", at="2026-11-22T00:00:00Z")
        later = review_node(OWNER, "CHANGES_REQUESTED", at="2026-11-23T00:00:00Z")
        later["author"] = None
        node = pr_node(
            1, issue=issue_node(10), files=("evidence/a.json",), reviews=(approved, later)
        )
        self.fake.prs[REPO_A]["open"][0] = node
        real = self.fake.__call__

        def call(method, path, headers, body):
            # GitHub returned it in this clinician's own connection.
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"rv0:" in body:
                answer = json.loads(data)
                for pr in answer["data"]["repository"].values():
                    if pr and "rv0" in pr:
                        pr["rv0"] = {"totalCount": 2, "nodes": [approved, later]}
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
        self.assertIsNone(item["task"]["pull_request"]["reviews"])
        self.assertNotIn(
            tasks.Flag.CLINICIAN_APPROVED, tasks.derive(dict(item["task"], paused=False)).flags
        )

    def test_any_repeated_row_marks_the_list_cut_off(self):
        # Should fix: repeats in the closed list were merged silently.
        recent = (NOW - timedelta(days=1)).isoformat()
        row = {"number": 5, "closedAt": recent, "updatedAt": recent}
        for closed in ([row, row], [row]):
            with self.subTest(rows=len(closed)):
                data = {
                    "repository": {
                        "open": {"totalCount": 1, "nodes": [{"number": 5}]}
                        if len(closed) == 1
                        else {"totalCount": 0, "nodes": []},
                        "closed": {"nodes": closed, "pageInfo": {"hasNextPage": False}},
                    }
                }
                self.assertEqual(snapshot._listing(REPO_A, data, NOW), ([5], True))
        # A list with no repeat is whole.
        data["repository"]["open"] = {"totalCount": 0, "nodes": []}
        self.assertEqual(snapshot._listing(REPO_A, data, NOW), ([5], False))


class CodexReviewOf96cb8a9(Base):
    def test_a_repeated_path_never_makes_the_file_list_whole(self):
        # Blocking: a repeated path could fill the row of an omitted clinical one.
        node = pr_node(1, issue=issue_node(10), files=("site/a.html", "site/a.html"))
        self.fake.prs[REPO_A]["open"][0] = node
        item = snapshot.refresh(self.cfg, client(self.fake), NOW)["items"][0]
        self.assertFalse(item["task"]["pull_request"].get("files_complete", True))
        flags = tasks.derive(dict(item["task"], paused=False)).flags
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, flags)

    def test_a_repeated_older_closed_row_marks_the_list_cut_off(self):
        # Should fix: rows closed before the window were dropped before the repeat check.
        old = (NOW - timedelta(days=60)).isoformat()
        recent = (NOW - timedelta(days=1)).isoformat()
        row = {"number": 9, "closedAt": old, "updatedAt": recent}
        data = {
            "repository": {
                "open": {"totalCount": 0, "nodes": []},
                "closed": {"nodes": [row, row], "pageInfo": {"hasNextPage": False}},
            }
        }
        self.assertEqual(snapshot._listing(REPO_A, data, NOW), ([], True))


class CodexReviewOfCaf31c9(CodexReviewOf099ef9b):
    """A repeated row may stand where GitHub omitted one, so a counted list with a repeat is
    never whole: reviews, issue events, check suites and check runs."""

    def test_a_repeated_review_never_hides_an_omitted_one(self):
        approved = review_node(OWNER, "APPROVED")
        node = pr_node(
            1, issue=issue_node(10), files=("evidence/a.json",), reviews=(approved, approved)
        )
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["pull_request"]["reviews"])

    def test_a_repeated_issue_event_never_hides_an_omitted_one(self):
        issue = issue_node(10)
        events = issue["timelineItems"]
        events["nodes"] = events["nodes"] * 2
        events["totalCount"] = 2
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue)
        self.assertIsNone(self.run_refresh()["items"][0]["task"]["issue"])

    def test_a_repeated_check_never_hides_an_omitted_one(self):
        for level in ("suites", "runs"):
            with self.subTest(level=level):
                node = pr_node(1, issue=issue_node(10))
                suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
                conn = suites if level == "suites" else suites["nodes"][0]["checkRuns"]
                conn["nodes"] = conn["nodes"] + conn["nodes"][-1:]
                conn["totalCount"] = len(conn["nodes"])
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)


class CodexReviewOf0dc0f8b(CodexReviewOf099ef9b):
    def suite_with(self, workflow_run, runs):
        node = pr_node(1, issue=issue_node(10))
        commit = node["commits"]["nodes"][0]["commit"]
        commit["checkSuites"]["nodes"].append(
            {
                "app": {"slug": "github-actions"},
                "workflowRun": workflow_run,
                "checkRuns": {"totalCount": len(runs), "nodes": runs},
            }
        )
        commit["checkSuites"]["totalCount"] = 2
        self.fake.prs[REPO_A]["open"][0] = node
        return self.run_refresh()["items"][0]

    def test_a_repeat_never_makes_a_suite_provably_harmless(self):
        # Blocking: the two filters trusted a matching count with a repeated row.
        lint = {"name": "lint", "status": "COMPLETED", "conclusion": "SUCCESS"}
        other = {"name": "other", "status": "COMPLETED", "conclusion": "SUCCESS"}
        for workflow_run, runs in (
            ({"event": "workflow_dispatch"}, [lint, lint]),
            (None, [other, other]),
        ):
            with self.subTest(workflow_run=workflow_run):
                item = self.suite_with(workflow_run, runs)
                self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))

    def test_rows_are_told_apart_by_githubs_id(self):
        # Should fix: two real reviews that look alike were taken for a repeat.
        first = dict(review_node(OWNER, "APPROVED"), id="R1")
        second = dict(review_node(OWNER, "APPROVED"), id="R2")
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=(first, second))
        self.fake.prs[REPO_A]["open"][0] = node
        self.assertIsNotNone(self.run_refresh()["items"][0]["task"]["pull_request"]["reviews"])
        # The same id twice is a repeat, however the rows differ.
        changed = dict(second, id="R1", state="CHANGES_REQUESTED")
        node = pr_node(
            1, issue=issue_node(10), files=("evidence/a.json",), reviews=(first, changed)
        )
        self.fake.prs[REPO_A]["open"][0] = node
        self.assertIsNone(self.run_refresh()["items"][0]["task"]["pull_request"]["reviews"])

    def test_the_queries_ask_for_each_rows_id(self):
        query = snapshot.detail_query([1], frozenset(), (OWNER,))
        for piece in ("nodes { id state", "id app { slug }", "nodes { id name", "{ id createdAt"):
            self.assertIn(piece, query)


class PreReviewOf07c3480(CodexReviewOf099ef9b):
    """A class-by-class audit of 07c3480: every remaining place for each pattern."""

    FUTURE = "2031-01-01T00:00:00Z"

    def item_for(self, node, github=None):
        self.fake.prs[REPO_A]["open"] = [node]
        self.fake.prs[REPO_A]["closed"] = []
        return self.run_refresh(github)["items"][0]

    def merged(self, **over):
        merged_at = over.pop("merged_at", (NOW - timedelta(days=1)).isoformat())
        node = pr_node(1, state="MERGED", merged=True, closed_at=merged_at, issue=issue_node(10))
        node.update(over)
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        return self.run_refresh()["items"][0]

    # ---- times
    def test_a_review_dated_in_the_future_is_not_known(self):
        review = review_node(OWNER, "APPROVED", at=self.FUTURE)
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=(review,))
        self.assertIsNone(self.item_for(node)["task"]["pull_request"]["reviews"])

    def test_an_issue_event_dated_in_the_future_is_not_known(self):
        issue = issue_node(10)
        late = dict(issue["timelineItems"]["nodes"][0], createdAt=self.FUTURE)
        issue["timelineItems"]["nodes"].append(late)
        issue["timelineItems"]["totalCount"] = 2
        self.assertIsNone(self.item_for(pr_node(1, issue=issue))["task"]["issue"])

    def test_a_merge_dated_in_the_future_or_unlike_its_closing_is_unreadable(self):
        self.assertIsNone(self.merged(merged_at=self.FUTURE)["task"])
        self.assertIsNone(self.merged(mergedAt="2026-11-01T00:00:00Z")["task"])

    def test_times_are_whole_seconds_as_the_model_reads_them(self):
        # A changes request half a second into the merge's second is in that second: the model
        # holds it in doubt, never "after the merge".
        merged_at = "2026-11-23T00:00:00Z"
        approved = review_node(OWNER, "APPROVED", at="2026-11-22T00:00:00Z")
        changes = review_node(OWNER, "CHANGES_REQUESTED", at="2026-11-23T00:00:00.500Z")
        item = self.merged(
            merged_at=merged_at,
            files={"totalCount": 1, "nodes": [{"path": "evidence/a.json", "changeType": "ADDED"}]},
            reviews={"totalCount": 2, "nodes": [approved, changes]},
        )
        flags = tasks.derive(dict(item["task"], paused=False)).flags
        self.assertNotIn(tasks.Flag.CLINICIAN_APPROVED, flags)
        for odd in ("20261123T000000Z", "2026-W48-1T00:00:00+00:00", "2026-11-23T00:00:00"):
            with self.subTest(odd=odd), self.assertRaises(gh.FetchError):
                snapshot._time(odd)

    # ---- repeats
    def test_a_repeated_status_or_a_run_in_two_suites_is_never_whole(self):
        node = pr_node(1, issue=issue_node(10), statuses=[("lint", "SUCCESS"), ("LINT", "SUCCESS")])
        self.assertFalse(self.item_for(node)["task"]["pull_request"].get("checks_complete", True))
        node = pr_node(1, issue=issue_node(10))
        suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
        for i, r in enumerate(suites["nodes"][0]["checkRuns"]["nodes"]):
            r["id"] = f"CR_{i}"
        suites["nodes"].append(json.loads(json.dumps(suites["nodes"][0])))
        suites["nodes"][1]["id"] = "S2"
        suites["totalCount"] = 2
        item = self.item_for(node)
        self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    # ---- contradictions, and states read as calmer
    def test_a_merger_on_an_unmerged_pr_makes_it_unreadable(self):
        node = pr_node(1, state="CLOSED", closed_at=(NOW - timedelta(days=1)).isoformat())
        node["mergedBy"] = {"__typename": "User", "login": "stranger"}
        self.assertIsNone(self.item_for(node)["task"])

    def test_a_run_in_an_odd_state_is_not_known_never_pending(self):
        for status, conclusion in (
            ("IN_PROGRESS", "FAILURE"),
            ("completed", "FAILURE"),
            ("X", None),
        ):
            with self.subTest(status=status):
                node = pr_node(1, issue=issue_node(10))
                run = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
                run["checkRuns"]["nodes"][0].update(status=status, conclusion=conclusion)
                pull = self.item_for(node)["task"]["pull_request"]
                self.assertFalse(pull.get("checks_complete", True))

    def test_the_head_must_be_the_one_commit_given(self):
        for count in (0, 2):
            with self.subTest(count=count):
                node = pr_node(1, issue=issue_node(10))
                commits = node["commits"]["nodes"]
                node["commits"]["nodes"] = commits * count
                item = self.item_for(node)
                self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    # ---- counts
    def test_a_linked_issue_count_unlike_its_rows_is_not_known(self):
        for total, rows in ((0, 1), (1, 2), (3, 0)):
            with self.subTest(total=total, rows=rows):
                node = pr_node(1, issue=issue_node(10))
                refs = node["closingIssuesReferences"]
                refs["nodes"] = (refs["nodes"] * 2)[:rows]
                refs["totalCount"] = total
                self.assertIsNone(self.item_for(node)["linked_issues"])

    def test_counts_unlike_their_rows_either_way_are_never_whole(self):
        for delta in (-1, 1):
            with self.subTest(delta=delta):
                review = review_node(OWNER, "APPROVED")
                node = pr_node(
                    1, issue=issue_node(10), files=("a.html", "b.html"), reviews=(review,)
                )
                node["reviews"]["totalCount"] = 1 + delta
                node["files"]["totalCount"] = 2 + delta
                pull = self.item_for(node)["task"]["pull_request"]
                self.assertFalse(pull.get("files_complete", True))
        data = {
            "repository": {
                "open": {"totalCount": 1, "nodes": [{"number": 1}, {"number": 2}]},
                "closed": {"nodes": [], "pageInfo": {"hasNextPage": False}},
            }
        }
        self.assertEqual(snapshot._listing(REPO_A, data, NOW)[1], True)

    # ---- the list and the details
    def test_a_pr_the_details_place_outside_the_window_is_kept_and_marked(self):
        node = pr_node(1, state="MERGED", merged=True, closed_at="2020-01-01T00:00:00Z")
        node["mergedBy"] = {"__typename": "User", "login": "stranger"}
        self.fake.prs[REPO_A]["open"] = [node]  # the list still says it is open
        snap = self.run_refresh()
        self.assertEqual([i["number"] for i in snap["items"] if i["repo"] == REPO_A], [1])
        self.assertIn(REPO_A, snap["truncated"])

    def test_details_for_another_number_are_unreadable(self):
        node = pr_node(1, issue=issue_node(10))
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number: 1)" in body:
                answer = json.loads(data)
                answer["data"]["repository"]["p0"]["number"] = 7
                data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        self.assertIsNone(self.item_for(node, github)["task"])

    def test_a_closed_page_out_of_order_is_never_the_end(self):
        old = (NOW - timedelta(days=60)).isoformat()
        recent = (NOW - timedelta(days=1)).isoformat()
        rows = [
            {"number": 2, "closedAt": recent, "updatedAt": old},
            {"number": 3, "closedAt": recent, "updatedAt": recent},
            {"number": 4, "closedAt": old, "updatedAt": old},
        ]
        data = {
            "repository": {
                "open": {"totalCount": 0, "nodes": []},
                "closed": {"nodes": rows, "pageInfo": {"hasNextPage": True, "endCursor": "c"}},
            }
        }
        self.assertTrue(snapshot._listing(REPO_A, data, NOW)[1])

    # ---- actors
    def test_a_merger_who_is_not_a_user_is_unknown(self):
        for actor in ({"__typename": "Organization", "login": OWNER}, {"login": OWNER}):
            with self.subTest(actor=actor):
                item = self.merged(mergedBy=actor)
                state = tasks.derive(dict(item["task"], paused=False))
                self.assertIn(tasks.Flag.MERGER_UNKNOWN, state.flags)

    # ---- text from the config
    def test_a_path_with_control_characters_is_refused(self):
        for odd in ("a\x1b[31m", "a\nFAKE", "\x85"):
            path = f"{self.base}/{odd}/key.pem"
            with self.subTest(path=path), self.assertRaises(fconfig.ConfigError):
                fconfig.parse_fetcher(json.dumps(config_data(self.base, key=path)))


class CodexReviewOfCc29d6e(PreReviewOf07c3480):
    def test_a_run_in_a_skipped_suite_and_a_counted_one_is_a_repeat(self):
        node = pr_node(1, issue=issue_node(10))
        suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
        for i, r in enumerate(suites["nodes"][0]["checkRuns"]["nodes"]):
            r["id"] = f"CR_{i}"
        other = json.loads(json.dumps(suites["nodes"][0]))
        other["app"] = {"slug": "another-ci"}  # passed over before its runs are read
        suites["nodes"].insert(0, other)
        suites["totalCount"] = 2
        item = self.item_for(node)
        self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_the_heads_row_is_read_wherever_it_is(self):
        node = pr_node(1, issue=issue_node(10))
        head_row = node["commits"]["nodes"][0]
        head_row["commit"]["checkSuites"]["nodes"][0]["checkRuns"]["nodes"][0]["conclusion"] = (
            "FAILURE"
        )
        other_row = json.loads(json.dumps(head_row))
        other_row["commit"]["oid"] = "c" * 40
        node["commits"]["nodes"] = [other_row, head_row]
        item = self.item_for(node)
        self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)

    def test_an_update_before_its_closing_is_never_the_end(self):
        recent = (NOW - timedelta(days=1)).isoformat()
        old = (NOW - timedelta(days=60)).isoformat()
        rows = [{"number": 2, "closedAt": recent, "updatedAt": old}]
        data = {
            "repository": {
                "open": {"totalCount": 0, "nodes": []},
                "closed": {"nodes": rows, "pageInfo": {"hasNextPage": True, "endCursor": "c"}},
            }
        }
        self.assertTrue(snapshot._listing(REPO_A, data, NOW)[1])


class CodexReviewOf2084eb4(PreReviewOf07c3480):
    def test_a_row_without_an_id_is_never_told_apart_by_its_content(self):
        # Blocking: an approval with an id and the same approval without one were two reviews.
        review = review_node(OWNER, "APPROVED")
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=(review,))
        real = self.fake.__call__

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"rv0:" in body:
                answer = json.loads(data)
                for pr in answer["data"]["repository"].values():
                    if pr and "rv0" in pr and pr["rv0"]["nodes"]:
                        row = pr["rv0"]["nodes"][0]
                        copy = {k: v for k, v in row.items() if k != "id"}
                        pr["rv0"] = {"totalCount": 2, "nodes": [row, copy]}
                        seen.append(1)
                data = json.dumps(answer).encode()
            return status, h, data

        seen = []
        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        self.assertIsNone(self.item_for(node, github)["task"]["pull_request"]["reviews"])
        self.assertTrue(seen)

    def test_every_head_row_is_read_and_a_bad_sibling_never_stops_it(self):
        # Blocking: a malformed row before the head's stopped the reading; of two head rows,
        # only the first was read. Either could discard a reported failure.
        node = pr_node(1, issue=issue_node(10))
        head_row = node["commits"]["nodes"][0]
        failing = json.loads(json.dumps(head_row))
        failing["commit"]["checkSuites"]["nodes"][0]["checkRuns"]["nodes"][0]["conclusion"] = (
            "FAILURE"
        )
        broken = {"commit": {"oid": "not a sha"}}
        for rows in ([broken, failing], [head_row, failing]):
            with self.subTest(first=rows[0]["commit"]["oid"][:5]):
                node["commits"]["nodes"] = rows
                item = self.item_for(node)
                pull = item["task"]["pull_request"]
                self.assertFalse(pull.get("checks_complete", True))
                self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)


class CodexReviewOfB03ad71(PreReviewOf07c3480):
    def test_a_pending_review_with_a_submission_time_is_not_known(self):
        pending = review_node(OWNER, "PENDING")  # with a submittedAt: contradictory
        approved = review_node(OWNER, "APPROVED", at="2026-11-21T00:00:00Z")
        node = pr_node(
            1, issue=issue_node(10), files=("evidence/a.json",), reviews=(approved, pending)
        )
        self.assertIsNone(self.item_for(node)["task"]["pull_request"]["reviews"])
        # Nor any other pending row: an App never sees another user's draft (pre-review of
        # 6b7da87).
        pending["submittedAt"] = None
        self.assertIsNone(self.item_for(node)["task"]["pull_request"]["reviews"])

    def test_the_order_is_checked_across_pages(self):
        recent = NOW - timedelta(days=1)

        def row(n, updated):
            at = updated.isoformat()
            return {"number": n, "closedAt": at, "updatedAt": at}

        full = [row(100 + i, recent - timedelta(minutes=i)) for i in range(snapshot.MAX_CLOSED)]
        first = {"nodes": full, "pageInfo": {"hasNextPage": True, "endCursor": "c1"}}
        second = {  # starts later than the first page ended: out of order
            "nodes": [row(4, recent + timedelta(hours=2))],
            "pageInfo": {"hasNextPage": False},
        }
        data = {"repository": {"open": {"totalCount": 0, "nodes": []}, "closed": first}}
        pages = {"c1": {"repository": {"closed": second}}}
        expected = [r["number"] for r in full] + [4]
        self.assertEqual(snapshot._listing(REPO_A, data, NOW, pages.get), (expected, True))
        second["nodes"] = [row(4, recent - timedelta(hours=2))]  # in order: whole
        self.assertEqual(snapshot._listing(REPO_A, data, NOW, pages.get), (expected, False))


class PreReviewOf6b7da87(PreReviewOf07c3480):
    """An exhaustive audit of 6b7da87: answers GitHub wouldn't give, each read as not known."""

    def checks_partial(self, node):
        item = self.item_for(node)
        self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
        return item

    def run0(self, node):
        return node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["checkRuns"][
            "nodes"
        ][0]

    def test_the_vanished_sentinel_is_never_a_head_or_an_oid(self):
        self.assertIsNone(self.item_for(pr_node(1, head="0" * 40))["task"])
        review = review_node(OWNER, "APPROVED", commit="0" * 40)
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=(review,))
        self.assertIsNone(self.item_for(node)["task"]["pull_request"]["reviews"])

    def test_runs_and_suites_that_contradict_themselves_are_not_known(self):
        node = pr_node(1, issue=issue_node(10))
        self.run0(node).update(status="IN_PROGRESS", conclusion=None)  # completedAt still set
        self.checks_partial(node)
        node = pr_node(1, issue=issue_node(10))
        node["potentialMergeCommit"] = {
            "oid": SHA1,
            "status": None,
            "checkSuites": {"totalCount": 0},
        }
        self.checks_partial(node)  # the test merge commit can't be the head
        node = pr_node(1, issue=issue_node(10))
        suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
        other = json.loads(json.dumps(suites["nodes"][0]))
        other["app"] = {"slug": "other-ci"}  # with a workflow run: only Actions has one
        suites["nodes"].append(other)
        suites["totalCount"] = 2
        self.checks_partial(node)

    def test_a_failure_with_keys_left_out_is_still_a_failure(self):
        node = pr_node(1, issue=issue_node(10))
        run = self.run0(node)
        run["conclusion"] = "FAILURE"
        del run["completedAt"]
        item = self.checks_partial(node)
        self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)
        node = pr_node(1, issue=issue_node(10), statuses=[("lint", "FAILURE")])
        del node["commits"]["nodes"][0]["commit"]["status"]["contexts"][0]["createdAt"]
        item = self.checks_partial(node)
        self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)

    def test_a_label_event_in_another_case_is_not_known(self):
        issue = issue_node(10)
        removal = dict(issue["timelineItems"]["nodes"][0], __typename="UnlabeledEvent")
        removal.update(label={"name": "Agent:Ready"}, createdAt="2026-11-21T00:00:00Z")
        issue["timelineItems"]["nodes"].append(removal)
        issue["timelineItems"]["totalCount"] = 2
        self.assertIsNone(self.item_for(pr_node(1, issue=issue))["task"]["issue"])

    def test_a_closed_prs_commit_row_must_name_its_head(self):
        review = review_node(OWNER, "APPROVED")
        merged_at = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=merged_at,
            issue=issue_node(10),
            files=("evidence/a.json",),
            reviews=(review,),
        )
        node["commits"]["nodes"][0]["commit"]["oid"] = SHA2
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["pull_request"]["reviews"])

    def test_one_review_in_two_clinicians_lists_is_not_known(self):
        row = review_node("a", "APPROVED")
        row["id"] = "R1"
        twin = dict(review_node("b", "APPROVED"), id="R1")
        pr = {"rv0": {"totalCount": 1, "nodes": [row]}, "rv1": {"totalCount": 1, "nodes": [twin]}}
        with self.assertRaises(snapshot._Incomplete):
            snapshot._reviews(pr, ("a", "b"), None, NOW)

    def test_paths_git_cant_have_leave_the_files_not_known(self):
        for path in ("/evidence/x.md", "./evidence/x.md", "site/../evidence/x.md", "site//a.html"):
            with self.subTest(path=path):
                node = pr_node(1, issue=issue_node(10), files=(path,))
                self.assertIsNone(self.item_for(node)["task"]["pull_request"]["files"])

    def test_an_impossible_issue_number_is_no_issue(self):
        for number in (0, 1):  # none, or the pull request's own
            with self.subTest(number=number):
                issue = issue_node(10)
                issue["number"] = number
                self.assertIsNone(self.item_for(pr_node(1, issue=issue))["task"]["issue"])

    def test_more_rows_than_asked_for_are_never_whole(self):
        files = tuple(f"site/{i}.html" for i in range(snapshot.MAX_FILES + 1))
        node = pr_node(1, issue=issue_node(10), files=files)
        self.assertFalse(snapshot._files(node, ())[1])
        open_rows = [{"number": n} for n in range(1, snapshot.MAX_OPEN + 2)]
        data = {
            "repository": {
                "open": {"totalCount": len(open_rows), "nodes": open_rows},
                "closed": {"nodes": [], "pageInfo": {"hasNextPage": False}},
            }
        }
        self.assertTrue(snapshot._listing(REPO_A, data, NOW)[1])

    def test_a_core_key_left_out_makes_the_pr_unreadable(self):
        for key in ("closedAt", "mergedAt", "mergedBy"):
            with self.subTest(key=key):
                node = pr_node(1, issue=issue_node(10))
                del node[key]
                self.assertIsNone(self.item_for(node)["task"])

    def test_doubt_on_one_page_is_never_cleared_by_the_next(self):
        now = NOW

        def row(n, days):
            at = (now - timedelta(days=days)).isoformat()
            return {"number": n, "closedAt": at, "updatedAt": at}

        # Full pages, as GitHub gives while more follow.
        disordered = [row(2, 1), row(3, 20), row(4, 2)] + [
            row(100 + i, 20 + i / 100) for i in range(snapshot.MAX_CLOSED - 3)
        ]
        first = {"nodes": disordered, "pageInfo": {"hasNextPage": True, "endCursor": "c1"}}
        orderly = [row(200 + i, 21 + i / 100) for i in range(snapshot.MAX_CLOSED)]
        second = {"nodes": orderly, "pageInfo": {"hasNextPage": True, "endCursor": "c2"}}
        data = {"repository": {"open": {"totalCount": 0, "nodes": []}, "closed": first}}
        pages = {"c1": {"repository": {"closed": second}}}
        self.assertTrue(snapshot._listing(REPO_A, data, NOW, pages.get)[1])

    def test_the_detail_query_asks_for_no_field_it_never_reads(self):
        self.assertNotIn("updatedAt", snapshot.detail_query([1], frozenset(), (OWNER,)))


class PreReviewOf8c4bfec(PreReviewOf07c3480):
    def merged_node(self, closed_gap=0, **over):
        merged_at = NOW - timedelta(days=1)
        node = pr_node(
            1,
            state="MERGED",
            merged=True,
            closed_at=(merged_at + timedelta(seconds=closed_gap)).isoformat(),
            issue=issue_node(10),
            **over,
        )
        node["mergedAt"] = merged_at.isoformat()
        node["mergedBy"] = {"__typename": "User", "login": "stranger"}
        self.fake.prs[REPO_A]["open"] = []
        self.fake.prs[REPO_A]["closed"] = [node]
        return node

    def test_a_merge_closed_a_second_later_is_read(self):
        # Blocking: real merges close a second after they merge (6 of 85 recent ones).
        for gap, readable in ((1, True), (5, True), (-1, False), (60, False)):
            with self.subTest(gap=gap):
                self.merged_node(closed_gap=gap)
                task = self.run_refresh()["items"][0]["task"]
                self.assertEqual(task is not None, readable)
                if readable:
                    state = tasks.derive(dict(task, paused=False))
                    self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, state.flags)

    def test_a_commit_row_that_cant_be_read_never_hides_the_reviews(self):
        # Should fix: an unreadable row discarded a merge's reviews, losing its unsafe verdict.
        node = self.merged_node(files=("evidence/a.json",))
        node["mergedBy"] = {"__typename": "User", "login": OWNER}
        node["commits"]["nodes"] = [None]
        task = self.run_refresh()["items"][0]["task"]
        self.assertEqual(task["pull_request"]["reviews"], [])
        state = tasks.derive(dict(task, paused=False))
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_an_open_prs_head_contradicted_by_its_row_reads_no_approval(self):
        review = review_node(OWNER, "APPROVED")
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=(review,))
        node["commits"]["nodes"][0]["commit"]["oid"] = SHA2
        self.assertIsNone(self.item_for(node)["task"]["pull_request"]["reviews"])

    def test_the_configured_apps_failure_is_read_whatever_its_suite_says(self):
        self.cfg = make_cfg(
            self.base,
            repos={
                REPO_A: {"required_checks": ["lint"], "clinical_paths": [], "checks_app": "my-ci"}
            },
        )
        node = pr_node(1, issue=issue_node(10), checks_app="my-ci")
        suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["workflowRun"] = {"event": "pull_request"}  # only Actions has one
        suite["checkRuns"]["nodes"][0]["conclusion"] = "FAILURE"
        self.fake.installed = [REPO_A]
        item = self.item_for(node)
        self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)

    def test_a_short_page_that_says_more_follow_is_never_the_end(self):
        old = (NOW - timedelta(days=20)).isoformat()
        data = {
            "repository": {
                "open": {"totalCount": 0, "nodes": []},
                "closed": {
                    "nodes": [{"number": 2, "closedAt": old, "updatedAt": old}],
                    "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
                },
            }
        }
        self.assertTrue(snapshot._listing(REPO_A, data, NOW)[1])

    def test_an_empty_check_name_is_not_known(self):
        node = pr_node(1, issue=issue_node(10))
        node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["checkRuns"]["nodes"][0][
            "name"
        ] = ""
        pull = self.item_for(node)["task"]["pull_request"]
        self.assertFalse(pull.get("checks_complete", True))

    def test_one_login_twice_is_never_two_clinicians(self):
        with self.assertRaises(fconfig.ConfigError):
            make_cfg(self.base, clinicians=[OWNER, OWNER.upper()])

    def test_an_oversized_open_list_is_never_all_read(self):
        rows = [{"number": n} for n in range(1, snapshot.MAX_OPEN * 3)]
        data = {
            "repository": {
                "open": {"totalCount": len(rows), "nodes": rows},
                "closed": {"nodes": [], "pageInfo": {"hasNextPage": False}},
            }
        }
        numbers, cut_off = snapshot._listing(REPO_A, data, NOW)
        self.assertEqual((len(numbers), cut_off), (snapshot.MAX_OPEN, True))

    def test_a_cost_error_on_a_pr_not_asked_for_is_never_partial(self):
        self.assertTrue(snapshot._optional_place(("repository", "p1", "files"), 2))
        self.assertFalse(snapshot._optional_place(("repository", "p9", "files"), 2))


class NoFifoAnywhere(Base):
    """Codex's review of b1fef32 (should fix): the config was opened and read before it was
    checked, so a FIFO in its place could hang start-up. Every file the fetcher reads is now
    opened without blocking and refused unless it is a regular file."""

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


class ClosingsAndReopenings(Base):
    """Part 1's rule (audit of ca7faa9): closing the issue withdraws the authorisation, and
    reopening restores nothing, so the fetcher reads closings and reopenings too."""

    def run_refresh(self):
        return snapshot.refresh(self.cfg, client(self.fake), NOW)

    def task_of(self, item):
        return dict(item["task"], paused=False)

    def reviewed(self, item):
        return Refresh.reviewed(self, item)

    def with_events(self, *events, state="OPEN"):
        issue = issue_node(10)
        issue["state"] = state
        issue["timelineItems"]["nodes"] += list(events)
        issue["timelineItems"]["totalCount"] = len(issue["timelineItems"]["nodes"])
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue)
        return self.run_refresh()["items"][0]

    def closed(self, at, closer=None):
        return {
            "__typename": "ClosedEvent",
            "createdAt": at,
            "actor": {"__typename": "User", "login": OWNER},
            "closer": closer,
        }

    def reopened(self, at):
        return {
            "__typename": "ReopenedEvent",
            "createdAt": at,
            "actor": {"__typename": "User", "login": OWNER},
        }

    def test_the_query_asks_for_closings_and_reopenings(self):
        query = snapshot.detail_query([1], frozenset(), (OWNER,))
        self.assertIn("CLOSED_EVENT, REOPENED_EVENT", query)
        self.assertIn("... on ClosedEvent", query)

    def test_closed_and_reopened_is_never_still_authorised(self):
        item = self.with_events(
            self.closed("2026-11-20T10:00:00Z"), self.reopened("2026-11-20T11:00:00Z")
        )
        timeline = item["task"]["issue"]["timeline"]
        self.assertEqual([e["event"] for e in timeline], ["labeled", "closed", "reopened"])
        s = tasks.derive(self.reviewed(item))
        self.assertEqual(s.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.AUTHORIZATION_WITHDRAWN, s.flags)

    def test_the_closer_is_kept_only_for_a_pr_in_this_repository(self):
        pr_here = {
            "__typename": "PullRequest",
            "number": 1,
            "repository": {"nameWithOwner": REPO_A},
        }
        pr_there = dict(pr_here, repository={"nameWithOwner": REPO_B})
        commit = {"__typename": "Commit"}
        for closer, expected in ((pr_here, 1), (pr_there, None), (commit, None), (None, None)):
            with self.subTest(closer=closer):
                item = self.with_events(self.closed("2026-11-20T10:00:00Z", closer), state="CLOSED")
                closing = item["task"]["issue"]["timeline"][-1]
                self.assertEqual(closing["event"], "closed")
                self.assertEqual(closing["closer_pr"], expected)

    def test_a_wrongly_shaped_closer_is_never_read(self):
        # The issue isn't known (null), as with a wrongly shaped label event: never guessed.
        item = self.with_events(self.closed("2026-11-20T10:00:00Z", "a commit"), state="CLOSED")
        self.assertIsNone(item["task"]["issue"])

    def test_a_closed_issue_with_its_closing_reads_as_withdrawn_not_unknown(self):
        item = self.with_events(self.closed("2026-11-20T10:00:00Z"), state="CLOSED")
        s = tasks.derive(self.reviewed(item))
        self.assertEqual(s.state, tasks.State.UNSAFE)
        self.assertNotIn(tasks.Flag.CLOSURE_UNPLACED, s.flags)


class AuditOf7712dec(Base):
    """Round 11: guards that were right but that no test held in place."""

    def run_refresh(self):
        return snapshot.refresh(self.cfg, client(self.fake), NOW)

    def task_of(self, item):
        return dict(item["task"], paused=False)

    def reviewed(self, item):
        return Refresh.reviewed(self, item)

    def test_an_approval_of_a_vanished_commit_never_approves_the_head(self):
        for commit, approved in ((SHA1, True), (None, False)):
            with self.subTest(commit=commit):
                review = review_node(OWNER, "APPROVED")
                review["commit"] = None if commit is None else {"oid": commit}
                node = pr_node(
                    1, issue=issue_node(10), files=("evidence/a.json",), reviews=(review,)
                )
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertEqual(tasks.Flag.CLINICIAN_APPROVED in flags, approved)
                if not approved:
                    self.assertIn(tasks.Flag.CLINICAL_APPROVAL_MISSING, flags)

    def test_only_the_latest_attempt_of_each_check_is_asked_for(self):
        # A re-run that passed must not leave an earlier failed attempt showing (audit of
        # 7712dec): GitHub is asked for the latest run of each check only.
        query = snapshot.detail_query([1], frozenset(), [OWNER])
        self.assertIn("checkRuns(first: 30, filterBy: {checkType: LATEST})", query)


class AuditOf8c62413(unittest.TestCase):
    def test_the_floor_is_measured_on_the_boot_clock(self):
        # Audit of 8c62413: every test injects its own clock, so the real one wasn't held.
        asked = []

        def clock_gettime(which):
            asked.append(which)
            return 42.0

        with mock.patch.object(server.time, "clock_gettime", clock_gettime):
            self.assertEqual(server.boot_clock()[1], 42.0)
        self.assertEqual(asked, [time.CLOCK_BOOTTIME])


if __name__ == "__main__":
    unittest.main()
