"""Shared by the fetcher's tests: a synthetic App key, config, pull requests and a fake GitHub.
No network: every response is synthetic, and the App's key is generated at run time."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from mission_fetcher import config as fconfig
from mission_fetcher import github as gh

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
        "isCrossRepository": False,
        "merged": merged,
        "closedAt": closed_at,
        "updatedAt": updated_at or closed_at or "2026-11-23T00:00:00Z",
        "mergedBy": {"__typename": "User", "login": OWNER} if merged else None,
        "mergedAt": (closed_at or "2026-11-23T00:00:00Z") if merged else None,
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
                        else {
                            "contexts": [
                                {"context": c, "state": st, "createdAt": "2026-11-23T00:00:00Z"}
                                for c, st in statuses
                            ]
                        },
                        "checkSuites": {
                            "totalCount": 1,
                            "nodes": [
                                {
                                    "app": {"slug": checks_app},
                                    # Only GitHub Actions suites have a workflow run.
                                    "workflowRun": {"event": check_event}
                                    if checks_app == "github-actions"
                                    else None,
                                    "checkRuns": {
                                        "totalCount": len(checks),
                                        "nodes": [
                                            {
                                                "name": c,
                                                "status": "COMPLETED",
                                                "conclusion": "SUCCESS",
                                                "completedAt": "2026-11-23T00:00:00Z",
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


def review_node(user=OWNER, state="APPROVED", at="2026-11-22T00:00:00Z", commit=SHA1, bot=False):
    return {
        "state": state,
        "author": {"login": user, "__typename": "Bot" if bot else "User"},
        "commit": {"oid": commit},
        "submittedAt": at,
    }


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
                    "actor": {"__typename": "User", "login": actor},
                    "label": {"name": label},
                }
            ],
        },
    }


def answer_for(node, query: str):
    """A pull request node as GitHub would answer this query: only the pieces it asks for, and
    each clinician's reviews (`rv<i>: reviews(author: ...)`) filtered by author."""
    if node is None:
        return None
    node = dict(node)
    pieces = {
        "files": "files(",
        "commits": "commits(",
        "potentialMergeCommit": "potentialMergeCommit",
        "closingIssuesReferences": "closingIssuesReferences",
        "headRefName": "\n  headRefName",
        "title": "\n  title",
    }
    for key, marker in pieces.items():
        if marker not in query:
            node.pop(key, None)
    reviews = (node.pop("reviews", None) or {}).get("nodes", [])
    totals = node.pop("review_totals", {})  # a clinician with more reviews than returned
    for alias, login in re.findall(r'(rv\d+): reviews\(author: "([^"]+)"', query):
        mine = [
            r
            for r in reviews
            if isinstance(r.get("author"), dict)
            and str(r["author"].get("login")).lower() == login.lower()  # as GitHub matches
        ]
        node[alias] = {"totalCount": totals.get(login, len(mine)), "nodes": mine}
    return with_ids(node)


COUNTED = re.compile(r"checkSuites|checkRuns|timelineItems|rv\d+")


def with_ids(value):
    """A copy where every row of a counted list has a node id, as GitHub always gives one: a
    row's own id if it has one, else one made from its content, so identical rows (a repeat)
    share an id, as GitHub's would."""
    if isinstance(value, list):
        return [with_ids(v) for v in value]
    if not isinstance(value, dict):
        return value
    out = {k: with_ids(v) for k, v in value.items()}
    for key, conn in out.items():
        if (
            COUNTED.fullmatch(key)
            and isinstance(conn, dict)
            and isinstance(conn.get("nodes"), list)
        ):
            for row in conn["nodes"]:
                if isinstance(row, dict) and "id" not in row:
                    content = json.dumps(row, sort_keys=True).encode()
                    row["id"] = "N_" + hashlib.sha256(content).hexdigest()[:16]
    return out


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
        self.queries = []
        self.too_large = set()  # PR numbers whose details are too large to read whole
        self.max_batch_ok = {}  # repo -> the largest batch that can be read
        self.batch_failure = (200, {}, b"x" * (gh.MAX_RESPONSE + 1))  # too large to read
        self.down = False  # every detail query fails, as when GitHub is down
        self.closed_page = 30  # closed pull requests per list page

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
                        "repository_selection": "selected",
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
                        "repository_selection": "selected",
                        "repositories": [
                            {"full_name": r, "permissions": {"admin": False, "push": False}}
                            for r in self.installed
                        ],
                    }
                ).encode(),
            )
        if path == "/graphql":
            request = json.loads(body)
            variables, query = request["variables"], request["query"]
            repo = f"{variables['owner']}/{variables['name']}"
            data = self.prs[repo]
            self.queries.append(query)
            if "pullRequest(number:" not in query:  # the list, or a further closed page
                start = int(variables.get("after", "0"))
                page = data["closed"][start : start + self.closed_page]
                more = start + self.closed_page < len(data["closed"])
                closed = {
                    "totalCount": len(data["closed"]),
                    "nodes": [{k: n[k] for k in ("number", "closedAt", "updatedAt")} for n in page],
                    "pageInfo": {
                        "hasNextPage": more,
                        "endCursor": str(start + self.closed_page) if more else None,
                    },
                }
                listing = {"closed": closed}
                if "after" not in variables:
                    listing["open"] = {
                        "totalCount": len(data["open"]),
                        "nodes": [{"number": n["number"]} for n in data["open"]],
                    }
                return 200, {}, json.dumps({"data": {"repository": listing}}).encode()
            wanted = [int(n) for n in re.findall(r"pullRequest\(number: (\d+)\)", query)]
            lite = "files(" not in query
            if self.down:
                return 502, {}, b""
            if not lite and len(wanted) > self.max_batch_ok.get(repo, 10**6):
                return self.batch_failure
            if not lite and set(wanted) & self.too_large:
                return 200, {}, b"x" * (gh.MAX_RESPONSE + 1)
            by_number = {n["number"]: n for n in data["open"] + data["closed"]}
            nodes = {f"p{i}": answer_for(by_number.get(n), query) for i, n in enumerate(wanted)}
            return 200, {}, json.dumps({"data": {"repository": nodes}}).encode()
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
