"""Phase A5a (issue #16): the fetcher, against a fake GitHub. No network: every response is
synthetic, and the App's key is generated at run time, never committed."""

from __future__ import annotations

import base64
import json
import os
import socket
import stat
import tempfile
import threading
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mission_control import tasks
from mission_fetcher import config as fconfig
from mission_fetcher import github as gh
from mission_fetcher import server, snapshot
from mission_fetcher.__main__ import github_checks
from mission_fetcher.checks import fetcher_checks, shared_with_web_app

APP_ID = 424242
OWNER = "example-owner"
REPO_A = "example-owner/site"
REPO_B = "example-owner/tools"
TOKEN = "ghs_" + "T" * 36  # a synthetic token shape, never a real one
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
SHA1 = "a" * 40
SHA2 = "b" * 40
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def config_data(base: Path, **over) -> dict:
    data = {
        "account": "fetcher-account",
        "client_account": "web-account",
        "app_id": APP_ID,
        "key": str(base / "key.pem"),
        "snapshot_dir": str(base / "snapshot"),
        "owner": OWNER,
        "clinicians": [OWNER],
        "repos": {
            REPO_A: {
                "required_checks": ["lint", "test"],
                "clinical_paths": ["evidence/*"],
                "checks_app": "github-actions",
            },
            REPO_B: {
                "required_checks": ["lint"],
                "clinical_paths": [],
                "checks_app": "github-actions",
            },
        },
        "forbidden_paths": [str(base / "publisher.pem")],
    }
    data.update(over)
    return data


def make_cfg(base: Path, **over) -> fconfig.FetcherConfig:
    return fconfig.parse_fetcher(json.dumps(config_data(base, **over)))


def pr_node(
    number,
    *,
    state="OPEN",
    head=SHA1,
    files=("site/a.html",),
    checks=("lint", "test"),
    reviews=(),
    issue=None,
    title="A synthetic title",
    closed_at=None,
    merged=False,
    files_total=None,
    checks_app="github-actions",
    check_event="pull_request",
    renamed=(),
    updated_at=None,
    merge_commit=None,
    statuses=None,
):
    node = {
        "number": number,
        "title": title,
        "state": state,
        "isDraft": False,
        "merged": merged,
        "closedAt": closed_at,
        "updatedAt": updated_at or closed_at or "2026-11-23T00:00:00Z",
        "mergedBy": {"login": OWNER} if merged else None,
        "headRefName": f"claude/task-{number}",
        "headRefOid": head,
        "potentialMergeCommit": merge_commit,
        "files": {
            "totalCount": len(files) if files_total is None else files_total,
            "nodes": [
                {"path": p, "changeType": "RENAMED" if p in renamed else "MODIFIED"} for p in files
            ],
        },
        "reviews": {"totalCount": len(reviews), "nodes": list(reviews)},
        "commits": {
            "nodes": [
                {
                    "commit": {
                        "oid": head,
                        "status": None
                        if statuses is None
                        else {"contexts": [{"context": c, "state": st} for c, st in statuses]},
                        "checkSuites": {
                            "totalCount": 1,
                            "nodes": [
                                {
                                    "app": {"slug": checks_app},
                                    "workflowRun": {"event": check_event},
                                    "checkRuns": {
                                        "totalCount": len(checks),
                                        "nodes": [
                                            {
                                                "name": c,
                                                "status": "COMPLETED",
                                                "conclusion": "SUCCESS",
                                            }
                                            for c in checks
                                        ],
                                    },
                                }
                            ],
                        },
                    }
                }
            ]
        },
        "closingIssuesReferences": {"totalCount": 0, "nodes": []},
    }
    if issue is not None:
        node["closingIssuesReferences"] = {"totalCount": 1, "nodes": [issue]}
    return node


def issue_node(number, actor=OWNER, label="agent:ready", repo=REPO_A):
    return {
        "number": number,
        "title": "A synthetic issue",
        "state": "OPEN",
        "repository": {"nameWithOwner": repo},
        "timelineItems": {
            "totalCount": 1,
            "nodes": [
                {
                    "__typename": "LabeledEvent",
                    "createdAt": "2026-11-20T09:00:00Z",
                    "actor": {"login": actor},
                    "label": {"name": label},
                }
            ],
        },
    }


class FakeGitHub:
    """api.github.com, as far as the fetcher uses it. Each attribute can be changed to make it
    misbehave; every JWT it receives is verified with the App's public key."""

    def __init__(self):
        self.permissions = dict(gh.EXPECTED_PERMISSIONS)
        self.token_permissions = dict(gh.EXPECTED_PERMISSIONS)
        self.selection = "selected"
        self.app_id = APP_ID
        self.account = OWNER
        self.suspended = None
        self.installed = [REPO_A, REPO_B]
        self.prs = {
            REPO_A: {
                "open": [pr_node(1, issue=issue_node(10)), pr_node(2)],
                "closed": [],
            },
            REPO_B: {"open": [pr_node(3, issue=issue_node(11, repo=REPO_B))], "closed": []},
        }
        self.fail = {}  # path -> (status, headers, body) or an exception
        self.calls = []
        self.revoked = 0
        self.jwts = []

    def _jwt_ok(self, bearer: str) -> bool:
        try:
            header, payload, sig = bearer.split(".")
            KEY.public_key().verify(
                b64decode(sig),
                f"{header}.{payload}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except Exception:  # noqa: BLE001 - any failure is a bad JWT
            return False
        claims = json.loads(b64decode(payload))
        self.jwts.append(claims)
        return claims["iss"] == str(APP_ID) and claims["exp"] - claims["iat"] == 600

    def __call__(self, method, path, headers, body):
        self.calls.append((method, path))
        for prefix, failure in self.fail.items():
            if path.startswith(prefix):
                if isinstance(failure, Exception):
                    raise failure
                return failure
        bearer = headers["Authorization"].removeprefix("Bearer ")
        if path.endswith("/installation") and path.startswith("/repos/"):
            if not self._jwt_ok(bearer):
                return 401, {}, b"{}"
            return (
                200,
                {},
                json.dumps(
                    {
                        "id": 77,
                        "app_id": self.app_id,
                        "account": {"login": self.account},
                        "suspended_at": self.suspended,
                        "repository_selection": self.selection,
                        "permissions": self.permissions,
                    }
                ).encode(),
            )
        if path == "/app/installations/77/access_tokens":
            if not self._jwt_ok(bearer):
                return 401, {}, b"{}"
            if json.loads(body) != {"permissions": gh.EXPECTED_PERMISSIONS}:
                return 400, {}, b"{}"  # the fetcher must ask for read-only permissions only
            return (
                201,
                {},
                json.dumps(
                    {
                        "token": TOKEN,
                        "permissions": self.token_permissions,
                        "expires_at": "2026-11-24T13:00:00Z",
                    }
                ).encode(),
            )
        if bearer != TOKEN:
            return 401, {}, b"{}"
        if path == "/installation/repositories?per_page=100":
            return (
                200,
                {},
                json.dumps(
                    {
                        "total_count": len(self.installed),
                        "repositories": [{"full_name": r} for r in self.installed],
                    }
                ).encode(),
            )
        if path == "/graphql":
            variables = json.loads(body)["variables"]
            repo = f"{variables['owner']}/{variables['name']}"
            data = self.prs[repo]
            return (
                200,
                {},
                json.dumps(
                    {
                        "data": {
                            "repository": {
                                "open": {"totalCount": len(data["open"]), "nodes": data["open"]},
                                "closed": {"nodes": data["closed"]},
                            }
                        }
                    }
                ).encode(),
            )
        if path == "/installation/token" and method == "DELETE":
            self.revoked += 1
            return 204, {}, b""
        return 404, {}, b"{}"


def client(fake: FakeGitHub) -> gh.GitHub:
    return gh.GitHub(APP_ID, KEY, transport=fake, clock=lambda: NOW.timestamp())


class Base(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.base, ignore_errors=True))
        (self.base / "snapshot").mkdir(mode=0o750)
        self.cfg = make_cfg(self.base)
        self.fake = FakeGitHub()


# ---------------------------------------------------------------- config


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
            {"repos": {REPO_A: {"required_checks": [], "clinical_paths": []}}},
            {"repos": {REPO_A: {"required_checks": ["x"]}}},
            {"owner": "bad login!"},
            {"clinicians": []},
            {"key": "relative/key.pem"},
            {"extra": 1},
        ):
            with self.subTest(over=over), self.assertRaises(fconfig.ConfigError):
                make_cfg(self.base, **over)


# ---------------------------------------------------------------- the App on GitHub


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

    def test_selfcheck_reports_each_step_and_revokes(self):
        results = github_checks(self.cfg_for_repos(), client(self.fake))
        self.assertTrue(all(c.ok for c in results), results)
        self.assertEqual(self.fake.revoked, 1)
        self.fake.permissions["checks"] = "write"
        results = github_checks(self.cfg_for_repos(), client(self.fake))
        self.assertEqual([(c.ok, c.detail) for c in results], [(False, "not-read-only")])

    def cfg_for_repos(self):
        return self.cfg


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
        self.assertEqual([i["id"] for i in snap["items"]], ["site-1", "site-2", "tools-3"])
        linked = [i for i in snap["items"] if i["linked_issues"] == 1]
        self.assertEqual(len(linked), 2)
        for item in linked:
            tasks.parse(self.task_of(item))  # passes the model's input checks
            self.assertNotEqual(tasks.derive(self.task_of(item)).state, tasks.State.UNKNOWN)
            self.assertEqual(item["task"]["runs"], [])
        unlinked = next(i for i in snap["items"] if i["id"] == "site-2")
        self.assertNotIn("issue", unlinked["task"])  # A5b shows "Not linked"
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
        self.assertIn("tools-4", ids)
        self.assertNotIn("tools-5", ids)

    def test_an_incomplete_part_is_left_out_so_the_model_says_unknown(self):
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("a",), files_total=500
        )
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["pull_request"]["files"])  # "not known"
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
        self.assertNotIn("issue", item["task"])

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
                self.assertEqual(item["task"]["pull_request"]["checks"][0]["name"], ran)
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
                checks = item["task"]["pull_request"]["checks"]
                self.assertEqual(checks is not None, has_checks)

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

    def test_a_malformed_check_status_is_a_bad_response(self):
        # Codex's review of 23bfb61: an unhashable status raised TypeError and stopped the
        # fetcher.
        node = pr_node(1, issue=issue_node(10))
        suite = node["commits"]["nodes"][0]["commit"]["checkSuites"]["nodes"][0]
        suite["checkRuns"]["nodes"][0]["status"] = ["COMPLETED"]
        self.fake.prs[REPO_A]["open"][0] = node
        with self.assertRaises(gh.FetchError) as caught:
            self.run_refresh()
        self.assertEqual(caught.exception.code, "bad-response")

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
        # unreadable. With "not known", the model still judges everything else: here, a merge
        # of a commit that never passed review (there are no run records yet).
        state = tasks.derive(self.task_of(merged))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.MERGED_UNREVIEWED, state.flags)
        self.assertIn(tasks.Flag.CHECKS_UNVERIFIED, state.flags)
        self.assertNotIn(tasks.Flag.MERGED_WITH_CHECKS_NOT_PASSED, state.flags)
        self.assertEqual(tasks.derive(self.task_of(closed)).state, tasks.State.CLOSED)

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
        node["mergedBy"] = {"login": "someone-else"}
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

    def test_a_renamed_file_makes_the_file_list_incomplete(self):
        # Codex's review of f37d0c7 (blocking): a rename lists only the new path, so a move out
        # of a clinical folder would hide where it came from.
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("site/moved.md",), renamed=("site/moved.md",)
        )
        item = self.run_refresh()["items"][0]
        self.assertIsNone(item["task"]["pull_request"]["files"])
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
        node["mergedBy"] = {"login": "someone-else"}
        node["reviews"] = {"totalCount": 500, "nodes": []}  # reviews incomplete too
        self.fake.prs[REPO_A]["open"], self.fake.prs[REPO_A]["closed"] = [], [node]
        item = self.run_refresh()["items"][0]
        pull = item["task"]["pull_request"]
        self.assertIsNone(pull["files"])
        self.assertIsNone(pull["reviews"])
        state = tasks.derive(self.task_of(item))
        self.assertEqual(state.state, tasks.State.UNSAFE)
        self.assertIn(tasks.Flag.UNAUTHORIZED_MERGE, state.flags)
        self.assertIn(tasks.Flag.FILES_UNVERIFIED, state.flags)
        self.assertIn(tasks.Flag.REVIEWS_UNVERIFIED, state.flags)
        # Nothing unknown is claimed either way.
        self.assertNotIn(tasks.Flag.MERGED_WITHOUT_CLINICIAN, state.flags)

    def test_unknown_reviews_give_no_clinical_approval(self):
        self.fake.prs[REPO_A]["open"][0] = pr_node(
            1, issue=issue_node(10), files=("evidence/study.md",)
        )
        self.fake.prs[REPO_A]["open"][0]["reviews"] = {"totalCount": 500, "nodes": []}
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

    def test_a_full_page_of_recently_updated_closed_prs_is_flagged(self):
        # Codex's review of f37d0c7: more closed pull requests could lie past the first page.
        recent = (NOW - timedelta(days=2)).isoformat()
        self.fake.prs[REPO_B]["closed"] = [
            pr_node(100 + i, state="CLOSED", closed_at=recent) for i in range(snapshot.MAX_CLOSED)
        ]
        self.assertIn(REPO_B, self.run_refresh()["truncated"])
        old = (NOW - timedelta(days=30)).isoformat()
        self.fake.prs[REPO_B]["closed"][-1] = pr_node(199, state="CLOSED", closed_at=old)
        self.assertNotIn(REPO_B, self.run_refresh()["truncated"])

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
        snapshot.MAX_SNAPSHOT = (written + compact) // 2  # compact fits, written doesn't
        try:
            with self.assertRaises(gh.FetchError) as caught:
                self.run_refresh()
        finally:
            snapshot.MAX_SNAPSHOT = saved
        self.assertEqual(caught.exception.code, "too-large")

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
        self.assertNotIn("issue", item["task"])

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

    def test_after_a_restart_of_the_machine_the_wall_clock_decides(self):
        wall = [NOW.timestamp()]
        self.assertEqual(
            self.make(lambda: wall[0], boot=lambda: ("boot-1", 1000.0)).run(), server.OK
        )
        wall[0] += 10  # a new boot ten seconds later: the floor holds on the wall clock
        self.assertEqual(
            self.make(lambda: wall[0], boot=lambda: ("boot-2", 20.0)).run(), server.TOO_SOON
        )
        wall[0] -= 3 * 3600  # the clock went back hours: no waiting for it to catch up
        self.assertEqual(self.make(lambda: wall[0], boot=lambda: ("boot-2", 30.0)).run(), server.OK)

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
        real = os.fsync

        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(5, "sync failed")
            return real(fd)

        with mock.patch.object(snapshot.os, "fsync", side_effect=fsync):
            self.assertEqual(self.make(lambda: NOW.timestamp()).run(), server.OK)
        status = snapshot.read_json(self.cfg.snapshot_dir, snapshot.STATUS)
        self.assertEqual(status["snapshot_at"], NOW.isoformat())

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


if __name__ == "__main__":
    unittest.main()
