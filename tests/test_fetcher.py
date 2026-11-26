"""Phase A5a (issue #16): the fetcher, against a fake GitHub. No network: every response is
synthetic, and the App's key is generated at run time, never committed."""

from __future__ import annotations

import json
import os
import re
import unittest
from datetime import UTC, timedelta
from unittest import mock

from mission_control import tasks, views
from mission_fetcher import config as fconfig
from mission_fetcher import github as gh
from mission_fetcher import snapshot
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
    answer_for,
    client,
    config_data,
    issue_node,
    make_cfg,
    pr_node,
    review_node,
    with_ids,
)

# ---------------------------------------------------------------- config


# ---------------------------------------------------------------- the App on GitHub


# ---------------------------------------------------------------- one refresh


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
        paths = ("evidence/a  b.md", "evidence/a b.md", "evidence/\u202ex.md", "site/x\ty.html")
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10), files=paths)
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["task"]["pull_request"]["files"], list(paths))
        state = tasks.derive(self.task_of(item))
        self.assertIn(tasks.Flag.CLINICAL, state.flags)

    def test_a_label_name_is_never_cleaned_into_the_authorisation_label(self):
        for name in ("agent:ready ", "agent:ready\u200b", "agent:\x01ready", " agent:ready"):
            with self.subTest(name=repr(name)):
                self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10, label=name))
                item = self.run_refresh()["items"][0]
                labels = [e["label"] for e in item["task"].get("issue", {}).get("timeline", [])]
                self.assertNotIn("agent:ready", labels)
                self.assertEqual(tasks.derive(self.task_of(item)).state, tasks.State.UNSAFE)

    def test_check_names_are_matched_exactly(self):
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
        clean = {"oid": SHA2, "status": None, "checkSuites": {"totalCount": 0, "nodes": []}}
        with_status = dict(clean, status={"contexts": [{"context": "ci/other"}]})
        with_suite = dict(clean, checkSuites={"totalCount": 1})
        for merge, mergeable, has_checks in (
            # None: still being generated, its results not known yet (Codex's review of
            # 521361b); or the pull request has conflicts, and is never ready either.
            (None, "MERGEABLE", False),
            (None, "UNKNOWN", False),
            (None, "CONFLICTING", False),  # can't be merged: never ready (Codex, 2676a4d)
            (clean, "MERGEABLE", True),
            (clean, "CONFLICTING", False),  # GitHub gives none then: odd, so not known
            (with_status, "MERGEABLE", False),
            (with_suite, "MERGEABLE", False),
        ):
            with self.subTest(merge=merge, mergeable=mergeable):
                node = pr_node(1, issue=issue_node(10), merge_commit=merge)
                node["mergeable"] = mergeable
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                pull = item["task"]["pull_request"]
                # Results on the test merge commit make the head's partial: never passed.
                self.assertEqual(pull.get("checks_complete", True), has_checks)
                passed = tasks.Flag.CHECKS_PASSED in tasks.derive(self.reviewed(item)).flags
                self.assertEqual(passed, has_checks)

    def test_the_test_merge_commits_failure_fails_and_its_pass_never_passes(self):
        # Read like the head's (Codex's review of 521361b): a failure counts, a pass doesn't.
        for conclusion, flag in (("FAILURE", "CHECKS_FAILING"), ("SUCCESS", "CHECKS_UNVERIFIED")):
            with self.subTest(conclusion=conclusion):
                node = pr_node(1, issue=issue_node(10))
                merge = node["commits"]["nodes"][0]["commit"]
                merge = json.loads(json.dumps(dict(merge, oid=SHA2)))
                merge["checkSuites"]["nodes"][0]["checkRuns"]["nodes"][0]["conclusion"] = conclusion
                node["potentialMergeCommit"] = merge
                self.fake.prs[REPO_A]["open"][0] = node
                item = self.run_refresh()["items"][0]
                flags = tasks.derive(self.reviewed(item)).flags
                self.assertIn(getattr(tasks.Flag, flag), flags)
                self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)

    def test_a_test_merge_commit_that_contradicts_itself_never_hides_its_failure(self):
        # Fable's pre-review of 7f24519: a zero count over a failing suite passed, and any odd
        # field dropped the failure. Whatever it says, its runs are read.
        def odd(merge):
            merge["checkSuites"]["totalCount"] = 0  # yet a failing suite below

        for i, spoil in enumerate((odd, lambda m: m.update(status=5), lambda m: m.update(oid="z"))):
            with self.subTest(spoil=i):
                self.spoiled_merge_commit_fails(spoil)
        # Present, but GitHub not yet sure it is mergeable: not known either.
        for mergeable in ("UNKNOWN", None):
            node = pr_node(1, issue=issue_node(10))
            node["mergeable"] = mergeable
            self.fake.prs[REPO_A]["open"][0] = node
            pull = self.run_refresh()["items"][0]["task"]["pull_request"]
            self.assertFalse(pull.get("checks_complete", True))
        # An error on `mergeable` leaves out its piece, never the whole pull request.
        self.assertEqual(snapshot._piece("mergeable"), "potentialMergeCommit")

    def test_one_suite_under_the_head_and_the_test_merge_commit_is_never_whole(self):
        # Codex's review of 2ee1f93: its empty copy passed for "no results".
        node = pr_node(1, issue=issue_node(10))
        node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["id"] = "S1"
        runs = {"totalCount": 0, "nodes": []}
        suite = {"id": "S1", "app": {"slug": "github-actions"}, "workflowRun": None}
        merge = {"oid": SHA2, "status": None}
        merge["checkSuites"] = {"totalCount": 1, "nodes": [dict(suite, checkRuns=runs)]}
        node["potentialMergeCommit"] = merge
        self.fake.prs[REPO_A]["open"][0] = node
        pull = self.run_refresh()["items"][0]["task"]["pull_request"]
        self.assertFalse(pull.get("checks_complete", True))

    def test_a_file_that_opens_but_cant_be_read_is_unreadable(self):
        # Codex's review of 2ee1f93: an error after the open escaped the None fallback.
        snapshot.write_json(self.cfg.snapshot_dir, snapshot.STATUS, {"a": 1})

        class Broken:
            def __init__(self, fd, mode):
                os.close(fd)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, size):
                raise OSError("I/O error")

        with mock.patch.object(snapshot.os, "fdopen", Broken):
            self.assertIsNone(snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS))
            with self.assertRaises(OSError):
                snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS, strict=True)

    def test_an_empty_suite_on_the_test_merge_commit_is_no_result(self):
        # Codex's review of a214c08: a suite with no runs gives GitHub nothing to judge.
        empty = {"totalCount": 0, "nodes": []}
        for app, runs, passes in (
            ("github-actions", empty, True),
            ("other-ci", empty, True),
            ("other-ci", {"totalCount": 1, "nodes": []}, False),  # a run left out
        ):
            with self.subTest(app=app, runs=runs):
                suite = {"app": {"slug": app}, "workflowRun": None, "checkRuns": runs}
                merge = {"oid": SHA2, "status": None, "checkSuites": {"totalCount": 1}}
                merge["checkSuites"]["nodes"] = [suite]
                self.fake.prs[REPO_A]["open"][0] = pr_node(
                    1, issue=issue_node(10), merge_commit=merge
                )
                flags = tasks.derive(self.reviewed(self.run_refresh()["items"][0])).flags
                self.assertEqual(tasks.Flag.CHECKS_PASSED in flags, passes)

    def failing_merge_commit(self):
        node = pr_node(1, issue=issue_node(10))
        merge = json.loads(json.dumps(dict(node["commits"]["nodes"][0]["commit"], oid=SHA2)))
        merge["checkSuites"]["nodes"][0]["checkRuns"]["nodes"][0]["conclusion"] = "FAILURE"
        node["potentialMergeCommit"] = merge
        return node, merge

    def spoiled_merge_commit_fails(self, spoil=lambda merge: None, github=None):
        node, merge = self.failing_merge_commit()
        self.fake.prs[REPO_A]["open"][0] = node
        spoil(merge)
        item = snapshot.refresh(self.cfg, github or client(self.fake), NOW)["items"][0]
        self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
        self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)

    def test_the_test_merge_commits_failure_counts_when_the_heads_row_cant(self):
        # Fable's pre-review of 619b757: it was lost when the head's row couldn't be used.
        other = {"commit": {"oid": SHA2, "status": None, "checkSuites": {"totalCount": 0}}}
        for rows in ([None], [], [other]):
            with self.subTest(rows=rows):

                def spoil(merge, rows=rows):
                    self.fake.prs[REPO_A]["open"][0]["commits"]["nodes"] = rows

                self.spoiled_merge_commit_fails(spoil)
        with self.subTest(rows="errored"):
            self.spoiled_merge_commit_fails(github=self.with_field_errors({1: ["commits"]}))
        with self.subTest(rows="left out"):  # Codex's review of b2e12a7

            def leave_out(merge):
                del self.fake.prs[REPO_A]["open"][0]["commits"]

            self.spoiled_merge_commit_fails(leave_out)

    def test_an_error_inside_the_test_merge_commit_keeps_what_github_gave(self):
        real = self.fake.__call__
        where = ["potentialMergeCommit", "checkSuites", "nodes", 0, "app"]

        def call(method, path, headers, body):
            status, h, data = real(method, path, headers, body)
            if path == "/graphql" and b"pullRequest(number:" in body:
                answer = json.loads(data)
                node = answer["data"]["repository"]["p0"]
                suites = (node or {}).get("potentialMergeCommit", {}).get("checkSuites", {})
                if suites.get("nodes"):  # only the pull request whose merge commit has a suite
                    suites["nodes"][0]["app"] = None
                    answer["errors"] = [{"type": "X", "path": ["repository", "p0", *where]}]
                    data = json.dumps(answer).encode()
            return status, h, data

        github = gh.GitHub(APP_ID, KEY, transport=call, clock=lambda: NOW.timestamp())
        self.spoiled_merge_commit_fails(github=github)

    def test_an_error_on_mergeable_leaves_the_pull_request_readable(self):
        for github in (
            self.with_field_errors({1: ["mergeable"]}),
            self.nulled_once({1}, [["mergeable"]]),
        ):
            self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10))
            item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
            self.assertIsNotNone(item["task"])
            self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))

    def test_a_commit_status_can_only_add_caution(self):
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
        self.fake.fail["/graphql"] = ValueError("a surprise")
        self.fake.fail["/installation/token"] = (500, {}, b"")
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, "internal+token-not-revoked")

    def test_a_malformed_check_status_makes_that_pr_unreadable(self):
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
        bad_review = review_node()
        bad_review["state"] = ["APPROVED"]
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10), reviews=[bad_review])
        items = self.run_refresh()["items"]
        self.assertEqual([i["number"] for i in items], [1, 2, 3])
        self.assertIsNone(items[0]["task"]["pull_request"]["reviews"])  # that part: not known
        self.assertIsNotNone(items[1]["task"]["pull_request"]["reviews"])

    def test_a_query_wide_graphql_error_fails_the_refresh(self):
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
        times = iter([0.0] + [10_000.0] * 1000)  # the start, then everything is too late
        with mock.patch.object(snapshot.time, "monotonic", side_effect=lambda: next(times)):
            with self.assertRaises(gh.FetchError) as caught:
                self.run_refresh()
        self.assertEqual(caught.exception.code, "too-slow")

    def test_item_ids_are_unique_across_owners(self):
        self.assertNotEqual(
            snapshot._unreadable("one/site", 1)["id"], snapshot._unreadable("two/site", 1)["id"]
        )
        self.assertEqual(self.run_refresh()["items"][0]["id"], f"{REPO_A}#1")

    def test_a_slow_drip_answer_is_cut_off_by_the_request_limit(self):
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
        node = pr_node(3, issue=issue_node(11, repo=REPO_B))
        node["isDraft"] = "no"  # wrongly shaped: this PR's own data
        self.fake.prs[REPO_B]["open"] = [node]
        snap = self.run_refresh()  # no bad-response
        lone = next(i for i in snap["items"] if i["repo"] == REPO_B)
        self.assertIsNone(lone["task"])  # shown, as unreadable
        self.assertTrue(any(i["task"] for i in snap["items"] if i["repo"] == REPO_A))

    def test_an_open_pr_with_a_closing_time_is_never_dropped(self):
        node = pr_node(1, issue=issue_node(10))
        node["closedAt"] = (NOW - timedelta(days=60)).isoformat()
        self.fake.prs[REPO_A]["open"][0] = node
        items = self.run_refresh()["items"]
        bad = next(i for i in items if i["number"] == 1)
        self.assertIsNone(bad["task"])  # unreadable: UNKNOWN

    def test_fitting_measures_the_snapshot_a_handful_of_times(self):
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
        recent = (NOW - timedelta(days=1)).isoformat()
        node = pr_node(1, state="MERGED", merged=True, closed_at=recent, issue=issue_node(10))
        node["merged"] = False
        self.fake.prs[REPO_A]["closed"] = [node]
        item = next(i for i in self.run_refresh()["items"] if i["number"] == 1)
        self.assertIsNone(item["task"])  # unreadable: UNKNOWN, an alert
        self.assertIsNone(item["linked_issues"])  # finding 5: not known, never 0

    def test_a_pr_from_a_fork_always_needs_attention(self):
        node = pr_node(1, issue=issue_node(10))
        node["isCrossRepository"] = True
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertIs(item["task"]["pull_request"]["from_fork"], True)
        state = tasks.derive(self.task_of(item))
        self.assertIn(tasks.Flag.FROM_FORK, state.flags)
        self.assertTrue(state.needs_attention)

    def test_every_pr_read_only_lite_is_shown_never_clean(self):
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
        self.fake.prs[REPO_A]["open"] = [pr_node(1, issue=issue_node(10)), pr_node(2)]
        github = self.with_field_errors({1: ["closingIssuesReferences"]})
        item = snapshot.refresh(self.cfg, github, NOW)["items"][0]
        self.assertIsNone(item["task"]["issue"])
        self.assertIsNone(item["issue"])
        self.assertEqual(item["task"]["pull_request"]["files"], ["site/a.html"])
        self.assertEqual(tasks.derive(self.task_of(item)).state, tasks.State.NOT_LINKED)

    def test_an_error_on_a_core_field_makes_only_that_pr_unreadable(self):
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
        for path in (None, ["repository"], ["repository", "p9", "files"], ["rateLimit"], "p0"):
            with self.subTest(path=path):
                error = {"type": "FORBIDDEN"} if path is None else {"type": "X", "path": path}
                github = self.with_field_errors({1: ["files"]}, extra=[error])
                with self.assertRaises(gh.FetchError) as caught:
                    snapshot.refresh(self.cfg, github, NOW)
                self.assertEqual(caught.exception.code, "graphql-error")

    def test_prs_that_all_fail_validation_never_replace_the_snapshot(self):
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
        github = self.with_field_errors({1: ["state"], 2: ["merged"]})
        with self.assertRaises(gh.FetchError) as caught:
            snapshot.refresh(self.cfg, github, NOW)
        self.assertEqual(caught.exception.code, "bad-response")

    def test_a_bad_issue_never_hides_a_known_unsafe_merge(self):
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
        # Beside it, an Actions suite whose workflow run can't be read: not known (Fable, ba87dc7).
        suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
        suites["nodes"].append({"app": {"slug": "github-actions"}, "workflowRun": {"event": 7}})
        suites["nodes"][1]["checkRuns"] = {"totalCount": 0, "nodes": []}
        suites["totalCount"] = 2
        item = self.run_refresh()["items"][0]
        self.assertFalse(item["task"]["pull_request"]["checks_complete"])
        suites["nodes"].pop()
        suites["totalCount"] = 1
        # Left out, the workflow run is not known, never taken as null (Codex's review of
        # d99b49a): the suite never passes on it.
        del node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]["workflowRun"]
        item = self.run_refresh()["items"][0]
        self.assertFalse(item["task"]["pull_request"]["checks_complete"])
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_too_large_also_says_when_the_token_outlived_it(self):
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
        state = tasks.derive(self.task_of(merged))
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, state.flags)  # never judged after a merge
        self.assertEqual(tasks.derive(self.task_of(closed)).state, tasks.State.CLOSED)

    def test_an_owner_merge_is_never_called_unreviewed_for_lack_of_run_records(self):
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
        for event in ("pull_request_review", "deployment", "deployment_status"):
            with self.subTest(event=event):
                self.fake.prs[REPO_A]["open"] = [
                    pr_node(1, issue=issue_node(10), check_event=event)
                ]
                item = self.run_refresh()["items"][0]
                self.assertIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_an_open_pr_is_never_closed_by_its_issue(self):
        issue = issue_node(10)
        issue["state"] = "CLOSED"
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue)
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertNotEqual(state.state, tasks.State.CLOSED)
        self.assertIn(tasks.Flag.ISSUE_CLOSED_PR_OPEN, state.flags)
        self.assertTrue(state.needs_attention)

    def test_long_paths_in_one_pr_never_stop_the_refresh(self):
        long_files = tuple("d/" + "x" * 3990 + f"{i:03d}" for i in range(100))
        self.fake.prs[REPO_A]["open"] = [
            pr_node(n, issue=issue_node(10), files=long_files) for n in range(1, 7)
        ]
        snap = self.run_refresh()  # no too-large
        for item in snap["items"][:6]:
            self.assertIsNone(item["task"]["pull_request"]["files"])  # "not known"
            self.assertIn(tasks.Flag.FILES_UNVERIFIED, tasks.derive(self.task_of(item)).flags)

    def test_the_path_cap_counts_escaped_bytes(self):
        paths = tuple(f"d/{i:02d}" + "é" * 200 for i in range(30))  # 12 KB raw, 36 KB written
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10), files=paths)
        self.assertIsNone(self.run_refresh()["items"][0]["task"]["pull_request"]["files"])

    def test_a_snapshot_over_its_limit_drops_file_lists_rather_than_failing(self):
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
        crowd = [review_node(f"user{i}", "COMMENTED") for i in range(90)]
        crowd += [review_node("helper[bot]", "APPROVED", bot=True), review_node()]
        self.fake.prs[REPO_A]["open"][0] = pr_node(1, issue=issue_node(10), reviews=crowd)
        reviews = self.run_refresh()["items"][0]["task"]["pull_request"]["reviews"]
        self.assertEqual([r["user"] for r in reviews], [OWNER])  # OWNER is the clinician here

    def test_fitting_cuts_reviews_and_checks_to_what_the_verdict_reads(self):
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
        later = (NOW - timedelta(hours=1)).isoformat()
        crowd = [review_node(f"user{i}", "COMMENTED", at=later) for i in range(101)]
        crowd.append(review_node("odd_login", "WEIRD"))  # a stranger's odd review
        item, state = self.merged_clinical(crowd)
        self.assertEqual(item["task"]["pull_request"]["reviews"], [])
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_a_stale_dismissed_approval_never_hides_a_merge_without_approval(self):
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
        for edge in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(edge):
                node, commit = self.failing_lint()
                commit["checkSuites"]["nodes"][0]["checkRuns"]["nodes"][1]["completedAt"] = edge
                self.assert_failing(node)

    def test_a_clinical_path_of_any_length_is_clinical(self):
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
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("evidence/a.json",)
        )
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertIn(tasks.Flag.CLINICAL_APPROVAL_MISSING, state.flags)
        self.assertTrue(state.needs_attention)

    def test_details_too_large_for_one_answer_are_read_in_smaller_batches(self):
        self.fake.prs[REPO_A]["open"] = [pr_node(n, issue=issue_node(10)) for n in range(1, 8)]
        self.fake.max_batch_ok[REPO_A] = 2
        snap = self.run_refresh()
        items = [i for i in snap["items"] if i["repo"] == REPO_A]
        self.assertEqual([i["number"] for i in items], list(range(1, 8)))
        for item in items:
            self.assertEqual(item["task"]["pull_request"]["files"], ["site/a.html"])  # whole
        self.assertNotIn(REPO_A, snap["truncated"])

    def test_a_query_github_stops_for_its_cost_is_split_too(self):
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
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=[review_node()])
        self.fake.prs[REPO_A]["open"][0] = node
        state = tasks.derive(self.task_of(self.run_refresh()["items"][0]))
        self.assertIn(tasks.Flag.CLINICIAN_APPROVED, state.flags)
        self.assertNotIn(tasks.Flag.CLINICAL_APPROVAL_MISSING, state.flags)
        self.assertTrue(views.clinician_approved(state))

    def test_a_renamed_file_makes_the_file_list_incomplete(self):
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("site/moved.md",), renamed=("site/moved.md",)
        )
        item = self.run_refresh()["items"][0]
        self.assertEqual(item["task"]["pull_request"]["files"], ["site/moved.md"])
        self.assertIs(item["task"]["pull_request"]["files_complete"], False)
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, tasks.derive(self.task_of(item)).flags)

    def test_a_merged_pr_with_unknown_files_keeps_its_known_warnings(self):
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
        recent = (NOW - timedelta(days=2)).isoformat()
        total = snapshot.CLOSED_PAGES * self.fake.closed_page + 1
        self.fake.prs[REPO_B]["closed"] = [
            pr_node(100 + i, state="CLOSED", closed_at=recent) for i in range(total)
        ]
        self.assertIn(REPO_B, self.run_refresh()["truncated"])
        self.fake.prs[REPO_B]["closed"].pop()  # exactly CLOSED_PAGES full pages: no more
        self.assertNotIn(REPO_B, self.run_refresh()["truncated"])

    def test_bumped_old_prs_never_push_a_recent_unsafe_merge_off_the_list(self):
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
        self.fake.fail["/graphql"] = (502, {}, b"")
        self.fake.fail["/installation/token"] = (500, {}, b"")
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, "http-502+token-not-revoked")

    def test_the_size_limit_is_measured_as_written(self):
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


# ---------------------------------------------------------------- the socket


# ---------------------------------------------------------------- start-up checks


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
        node = pr_node(1, issue=issue_node(10))
        suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["checkRuns"]["totalCount"] = len(suite["checkRuns"]["nodes"]) + 1
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertFalse(item["task"]["pull_request"]["checks_complete"])
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, tasks.derive(self.reviewed(item)).flags)

    def test_results_for_another_commit_are_never_read(self):
        node = pr_node(1, issue=issue_node(10))
        node["commits"]["nodes"][0]["commit"]["oid"] = "c" * 40
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["pull_request"]["checks"])
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)

    def test_a_symlinked_folder_is_never_followed(self):
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
                "workflowRun": None,
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
        app = {"slug": "other-ci"}
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, self.another_suite(app, "FAILURE"))
        # Its success is harmless: never counted, never in the way.
        self.assertIn(tasks.Flag.CHECKS_PASSED, self.another_suite(app, "SUCCESS"))
        # No app at all (a GraphQL error can null it), with a required name: not known, read on
        # so its failure still fails (Codex's review of d99b49a).
        self.assertIn(tasks.Flag.CHECKS_FAILING, self.another_suite(None, "FAILURE"))
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, self.another_suite(None, "SUCCESS"))

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
        merge = {"oid": SHA2, "checkSuites": {"totalCount": 0}}  # no status key at all
        node = pr_node(1, issue=issue_node(10), merge_commit=merge)
        self.fake.prs[REPO_A]["open"][0] = node
        item = self.run_refresh()["items"][0]
        self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
        self.assertNotIn(tasks.Flag.CHECKS_PASSED, tasks.derive(self.reviewed(item)).flags)


class ChecksFreshUntil(CodexReviewOf099ef9b):
    """Each item says when its counted passes stop being fresh (owner's decision)."""

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
                        # With ids, so only the missing author can refuse it (Codex, a78c3cb).
                        pr.update(with_ids({"rv0": {"totalCount": 2, "nodes": [approved, later]}}))
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
                        "closed": {
                            "totalCount": len(closed),
                            "nodes": closed,
                            "pageInfo": {"hasNextPage": False},
                        },
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
    """A counted list with a repeated row is never whole."""

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
        # Both read, so the answer is the model's, never reviews dropped (Codex, 34ad21c).
        states = sorted(r["state"] for r in item["task"]["pull_request"]["reviews"])
        self.assertEqual(states, ["APPROVED", "CHANGES_REQUESTED"])
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
        # Even as the last page, as is one with a time that can't be (Codex, 34ad21c).
        data["repository"]["closed"]["pageInfo"]["hasNextPage"] = False
        self.assertTrue(snapshot._listing(REPO_A, data, NOW)[1])
        rows[:] = [{"number": 2, "closedAt": recent, "updatedAt": old}]
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
        first = {
            "totalCount": snapshot.MAX_CLOSED + 1,
            "nodes": full,
            "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
        }
        second = {  # starts later than the first page ended: out of order
            "totalCount": snapshot.MAX_CLOSED + 1,
            "nodes": [row(4, recent + timedelta(hours=2))],
            "pageInfo": {"hasNextPage": False},
        }
        data = {"repository": {"open": {"totalCount": 0, "nodes": []}, "closed": first}}
        pages = {"c1": {"repository": {"closed": second}}}
        expected = [r["number"] for r in full] + [4]
        self.assertEqual(snapshot._listing(REPO_A, data, NOW, pages.get), (expected, True))
        second["nodes"] = [row(4, recent - timedelta(hours=2))]  # in order: whole
        self.assertEqual(snapshot._listing(REPO_A, data, NOW, pages.get), (expected, False))
        # The last page, but the count says more: rows are missing (Codex, a78c3cb).
        for total in (snapshot.MAX_CLOSED + 2, None):
            second["totalCount"] = total
            self.assertEqual(snapshot._listing(REPO_A, data, NOW, pages.get), (expected, True))
        # Stopped early, the count must still exceed what was read, alike on every page
        # (Codex's review of a214c08).
        second["totalCount"] = snapshot.MAX_CLOSED + 1
        old_rows = [row(200 + i, recent - timedelta(days=30 + i)) for i in range(2)]
        first["nodes"] = full[:-2] + old_rows  # the last row is old: no need to read further
        data["repository"]["closed"] = first
        listed = snapshot._listing(REPO_A, data, NOW, pages.get)[1]
        self.assertFalse(listed)
        for total in (snapshot.MAX_CLOSED, 3, None):
            first["totalCount"] = total
            self.assertTrue(snapshot._listing(REPO_A, data, NOW, pages.get)[1])


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
            "checkSuites": {"totalCount": 0, "nodes": []},
        }
        self.checks_partial(node)  # the test merge commit can't be the head
        node["potentialMergeCommit"]["oid"] = snapshot.VANISHED  # nor "gone" (Codex, 34ad21c)
        self.checks_partial(node)
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
        for odd in ("agent:ready ", " Agent:Ready "):  # nor its removal padded (Codex, a78c3cb)
            removal["label"] = {"name": odd}
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

    def test_an_empty_page_after_a_promise_of_more_is_never_the_end(self):
        rows = [
            {"number": n, "closedAt": t, "updatedAt": t}
            for n in range(1, snapshot.MAX_CLOSED + 1)
            for t in [(NOW - timedelta(hours=n)).isoformat()]
        ]
        first = {"nodes": rows, "pageInfo": {"hasNextPage": True, "endCursor": "c1"}}
        data = {"repository": {"open": {"totalCount": 0, "nodes": []}, "closed": first}}
        last = {"repository": {"closed": {"nodes": [], "pageInfo": {"hasNextPage": False}}}}
        self.assertTrue(snapshot._listing(REPO_A, data, NOW, lambda c: last)[1])
        # Nor is a later page with a time that can't be (160cc5a's sweep).
        odd = {"number": 99, "closedAt": rows[0]["closedAt"], "updatedAt": "2026-01-01T00:00:00Z"}
        fine = dict(odd, number=98, closedAt=odd["updatedAt"])
        last["repository"]["closed"]["nodes"] = [odd, fine]
        self.assertTrue(snapshot._listing(REPO_A, data, NOW, lambda c: last)[1])
        del first["pageInfo"]["hasNextPage"]  # left out: a bad answer, never "no more"
        with self.assertRaises(gh.FetchError):
            snapshot._listing(REPO_A, data, NOW)

    def test_a_review_whose_commit_is_left_out_is_not_known(self):
        review = review_node(OWNER, "APPROVED")
        del review["commit"]
        node = pr_node(1, issue=issue_node(10), files=("evidence/a.json",), reviews=(review,))
        self.assertIsNone(self.item_for(node)["task"]["pull_request"]["reviews"])

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


class PreReviewOfB8b1ca7(PreReviewOf07c3480):
    def test_an_oversized_closed_page_is_never_all_read(self):
        recent = (NOW - timedelta(days=1)).isoformat()
        rows = [{"number": n, "closedAt": recent, "updatedAt": recent} for n in range(1, 2001)]
        data = {
            "repository": {
                "open": {"totalCount": 0, "nodes": []},
                "closed": {"nodes": rows, "pageInfo": {"hasNextPage": False}},
            }
        }
        numbers, cut_off = snapshot._listing(REPO_A, data, NOW)
        self.assertEqual((len(numbers), cut_off), (snapshot.MAX_CLOSED, True))

    def test_an_actions_suites_failure_is_read_whatever_its_workflow_run(self):
        for workflow_run in ("left out", None, {"event": 7}, {"event": ""}, {"event": "Push"}):
            with self.subTest(workflow_run=workflow_run):
                node = pr_node(1, issue=issue_node(10))
                suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
                suite["checkRuns"]["nodes"][0]["conclusion"] = "FAILURE"
                if workflow_run == "left out":
                    del suite["workflowRun"]
                else:
                    suite["workflowRun"] = workflow_run
                item = self.item_for(node)
                self.assertFalse(item["task"]["pull_request"].get("checks_complete", True))
                self.assertIn(tasks.Flag.CHECKS_FAILING, tasks.derive(self.reviewed(item)).flags)

    def test_a_suite_whose_app_is_left_out_is_never_one_with_no_app(self):
        # Runs naming no required check: null is passed over, left out is not known.
        for left_out in (False, True):
            node = pr_node(1, issue=issue_node(10))
            suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
            runs = {"totalCount": 0, "nodes": []}
            suites["nodes"].append({"app": None, "workflowRun": None, "checkRuns": runs})
            suites["totalCount"] = 2
            if left_out:
                del suites["nodes"][1]["app"]
            pull = self.item_for(node)["task"]["pull_request"]
            self.assertEqual(pull.get("checks_complete", True), not left_out)

    def test_a_failure_in_a_suite_of_unknown_app_still_fails(self):
        odd = ({"slug": ""}, {"slug": "GitHub-Actions"}, {"slug": " github-actions"})
        for suite_app in ("left out", 7, {"slug": 7}, *odd):
            for conclusion in ("FAILURE", "SUCCESS"):
                with self.subTest(app=suite_app, conclusion=conclusion):
                    node = pr_node(1, issue=issue_node(10))
                    suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
                    suite["checkRuns"]["nodes"][0]["conclusion"] = conclusion
                    if suite_app == "left out":
                        del suite["app"]
                    else:
                        suite["app"] = suite_app
                    item = self.item_for(node)
                    pull = item["task"]["pull_request"]
                    self.assertFalse(pull.get("checks_complete", True))
                    flags = tasks.derive(self.reviewed(item)).flags
                    self.assertNotIn(tasks.Flag.CHECKS_PASSED, flags)
                    if conclusion == "FAILURE":
                        self.assertIn(tasks.Flag.CHECKS_FAILING, flags)

    def test_an_empty_name_in_another_suite_is_never_harmless(self):
        # Both guards: another app's suite, and an Actions suite with no workflow run
        # (pre-review of e4a8096: the second had no test).
        for app in ("other-ci", "github-actions"):
            with self.subTest(app=app):
                node = pr_node(1, issue=issue_node(10))
                suites = node["commits"]["nodes"][0]["commit"]["checkSuites"]
                suites["nodes"].append(
                    {
                        "app": {"slug": app},
                        "workflowRun": None,
                        "checkRuns": {
                            "totalCount": 1,
                            "nodes": [{"name": "", "status": "COMPLETED", "conclusion": "FAILURE"}],
                        },
                    }
                )
                suites["totalCount"] = 2
                pull = self.item_for(node)["task"]["pull_request"]
                self.assertFalse(pull.get("checks_complete", True))


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


class SweepOf160cc5a(Base):
    """A mutation sweep of 160cc5a: guards that could be deleted with every test passing."""

    def test_each_guard_alone_keeps_a_pull_request_from_reading_calmer(self):
        node = pr_node(
            1,
            issue=issue_node(10),
            files=("evidence/a.json",),
            checks=("lint", "test", "docs"),
            reviews=(review_node(),),
            statuses=(("lint", "SUCCESS"),),
            merge_commit={
                "oid": SHA2,
                "status": None,
                "checkSuites": {"totalCount": 0, "nodes": []},
            },
        )
        mine = node["commits"]["nodes"][0]["commit"]["checkSuites"]
        failed = dict(mine["nodes"][0]["checkRuns"]["nodes"][2], conclusion="FAILURE")
        mine["nodes"][0]["checkRuns"]["nodes"][2] = failed  # not a required check
        runs = {"totalCount": 1, "nodes": [dict(failed, name="d")]}
        mine["nodes"].append({"app": {"slug": "other-ci"}, "workflowRun": None, "checkRuns": runs})
        mine["totalCount"] = 2
        base = answer_for(node, snapshot.detail_query([1], frozenset(), self.cfg.clinicians))

        def flags(path="", value=None):
            answer = at = json.loads(json.dumps(base))
            *keys, last = (int(k) if k.isdigit() else k for k in path.split("."))
            for key in keys:
                at = at[key]
            at[last] = value
            item = snapshot._item(REPO_A, self.cfg, answer, NOW)
            return {f.value for f in tasks.derive(dict(item["task"], paused=False)).flags}

        # Failures that aren't required checks, its own app's and another's: still calm.
        self.assertLessEqual({"checks_passed", "clinician_approved"}, flags())
        events = "closingIssuesReferences.nodes.0.timelineItems"
        commit = "commits.nodes.0.commit"
        run = {"id": "R", "name": "lint", "status": "QUEUED", "completedAt": None}
        rows = [*base["commits"]["nodes"], {"commit": {"oid": SHA2}}]  # the head's, and another
        for path, value, expected in (
            ("rv0.nodes.0.author.login", "someone", "reviews_unverified"),
            ("rv0.nodes.0.submittedAt", "2026-02-30T00:00:00Z", "reviews_unverified"),
            ("rv0.totalCount", 2, "reviews_unverified"),
            (events + ".totalCount", 2, "issue_not_linked"),
            (events + ".nodes.0.__typename", "labeledEvent", "issue_not_linked"),
            ("potentialMergeCommit.status", {}, "checks_unverified"),
            ("commits.nodes", rows, "checks_unverified"),
            (commit + ".checkSuites.nodes.1.checkRuns.nodes.0.id", None, "checks_unverified"),
            (commit + ".checkSuites.nodes.1.checkRuns.totalCount", 2, "checks_unverified"),
            (commit + ".status", {}, "checks_unverified"),
            (commit + ".status.contexts.0", 5, "checks_unverified"),
            (commit + ".status.contexts.0", {}, "checks_unverified"),
            (commit + ".checkSuites", None, "checks_unverified"),
            (commit + ".checkSuites.nodes.0.checkRuns.nodes.0", run, "checks_unverified"),
            # And what is known stays known: a run not done is pending, no suite is no result.
            (
                commit + ".checkSuites.nodes.0.checkRuns.nodes.0",
                {**run, "conclusion": None},
                "checks_pending",
            ),
            (commit + ".checkSuites", {"totalCount": 0, "nodes": []}, "checks_missing"),
        ):
            self.assertIn(expected, flags(path, value), path)
        with self.assertRaises(gh.FetchError):  # open, with a merge time: a contradiction
            flags("mergedAt", "2026-11-23T00:00:00Z")

    def test_a_snapshot_over_its_limit_is_cut_step_by_step(self):
        reviews = (review_node(), review_node(state="COMMENTED"))
        node = pr_node(1, files=("evidence/a.json",), reviews=reviews, statuses=[("lint", "ERROR")])
        self.fake.prs[REPO_A]["open"] = [node]
        snap = snapshot.refresh(self.cfg, client(self.fake), NOW)
        snap["items"].insert(0, snapshot._unreadable(REPO_A, 9))
        nulled = json.loads(json.dumps(snap))
        for item in nulled["items"][1:]:
            snapshot._cut(item["task"]["pull_request"], ("evidence/*",), False)

        def fit(under):
            limit = len(snapshot.encode(dict(snap, token_revoked=False))) - under
            with mock.patch.object(snapshot, "MAX_SNAPSHOT", limit):
                snapshot._fit(snap)
            return snap["items"][-2]["task"]["pull_request"]

        fit(len(snapshot.encode(snap)) - len(snapshot.encode(nulled)))
        self.assertEqual(snap, nulled)  # every file list null, a known clinical one known: enough
        pull = fit(1)  # then reviews and checks, down to what the verdict reads
        self.assertEqual((len(pull["reviews"]), len(pull["checks"]), len(snap["items"])), (1, 2, 3))
        fit(1)  # then whole items, an unreadable one first
        self.assertEqual(
            ([i["number"] for i in snap["items"]], snap["truncated"]), ([1, 3], [REPO_A])
        )

    def test_small_guards_no_test_held(self):
        for numbers, logins in (([], ()), ([True], ()), ([0], ()), ([2**31], ()), ([1], ('a"b',))):
            with self.assertRaises(gh.FetchError):  # nothing odd is written into a query
                snapshot.detail_query(numbers, frozenset(), logins)
        # An error on the pull request itself, or on a core field and then an optional one.
        core = [("repository", "p0", "state"), ("repository", "p0", "files")]
        for places in ([("repository", "p0")], core):
            error = gh.FetchError("graphql-error", tuple(places), {"repository": {"p0": {}}})
            self.assertEqual(
                snapshot._partial(error, [1], False), [(1, snapshot.UNREADABLE, False)]
            )
        with self.assertRaises(fconfig.ConfigError):
            make_cfg(self.base, clinicians=[5])


if __name__ == "__main__":
    unittest.main()
