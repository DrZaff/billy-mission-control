"""From GitHub's answers to the snapshot the web app reads (phase A5a, issue #16).

Each item carries the task model's input (`mission_control.tasks`), built only from fields this
module checks, plus the title and links the screens show. Everything from GitHub is untrusted:
- only the expected shapes are accepted; anything else fails the refresh ("bad-response");
- text is cleaned (no control characters) and capped; links are built here from the repository
  and number, never taken from GitHub's answer;
- where GitHub's answer is incomplete (more files, reviews, checks or label events than one
  request returns), that part is left out, so the model shows UNKNOWN rather than a state built
  on part of the data. Nothing here decides a state: `tasks.derive` does, in the web app.

Two keys the model needs are left for the web app (phase A5b): `paused`, which it reads from
the stop marker itself, and the state for a pull request with no linked issue. `runs` is null,
"not read": phase A5 starts with GitHub data only (issue #15, 2026-11-24), and an empty list
would claim no review ever happened.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from string import Template
from typing import Any

from mission_control.tasks import READY_LABEL

from .config import FetcherConfig
from .github import FetchError, GitHub

SNAPSHOT = "snapshot.json"
STATUS = "status.json"
VERSION = 1
RECENT_DAYS = 14
MAX_OPEN = 50
MAX_CLOSED = 30
MAX_FILES = 100
MAX_REVIEWS = 100
MAX_SUITES = 20
MAX_RUNS = 30
MAX_ISSUES = 5
MAX_EVENTS = 100
MAX_TITLE = 200
MAX_TEXT = 255
MAX_SNAPSHOT = 2 * 1024 * 1024
# Bytes of file paths kept per pull request, measured as written (JSON escapes, Codex's review
# of 72607b3); past it the list is cut to one known clinical path, or else "not known" (see
# `_compact`). If the whole snapshot is still over its limit, the largest lists are cut the
# same way until it fits (see `_fit`), so pull requests anyone can open never stop every
# refresh (pre-review of 9537b08).
MAX_PATH_BYTES = 16 * 1024
SHA = re.compile(r"[0-9a-f]{40}")
CONTROL = re.compile(r"[\x00-\x1f\x7f  ‪-‮⁦-⁩]")
REVIEW_STATES = {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"}
STATUS_STATES = ("ERROR", "EXPECTED", "FAILURE", "PENDING", "SUCCESS")
# Events GitHub documents as able to supply a pull request's required checks (Codex's review
# of a1e05e5 added the review and deployment ones).
CHECK_EVENTS = (
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "push",
    "merge_group",
    "deployment",
    "deployment_status",
)
CHECK_STATUS = {"QUEUED": "queued", "IN_PROGRESS": "in_progress", "COMPLETED": "completed"}

# One small request lists each repository's pull requests; their details come in batches, so no
# answer, however large the pull requests, can exceed the transport's limit and stop every
# refresh (Codex's review of 877fd21). A batch that is too large is split in half, down to one
# pull request, and one still too large is read without its files, reviews and checks, which
# are then "not known".
LIST_QUERY = Template("""
query($$owner: String!, $$name: String!) {
  repository(owner: $$owner, name: $$name) {
    open: pullRequests(states: OPEN, first: $open,
                       orderBy: {field: UPDATED_AT, direction: DESC}) {
      totalCount
      nodes { number }
    }
    closed: pullRequests(states: [CLOSED, MERGED], first: $closed,
                         orderBy: {field: UPDATED_AT, direction: DESC}) {
      nodes { number closedAt updatedAt }
    }
  }
}
""").substitute(open=MAX_OPEN, closed=MAX_CLOSED)

BATCH = 10
# Failures that may mean the query was too heavy, not that GitHub is down: the batch is split
# (Codex's review of 28546f5: GitHub can stop a costly query by time or resources, before the
# answer reaches the size cap). If a lone pull request read without its heavy parts still
# fails, or the request budget runs out, the refresh fails with GitHub's own error.
HEAVY = {"too-large", "too-heavy", "timeout", "http-502", "http-503", "http-504"}
# Failures of one pull request's own data: GitHub's error on a field, or an answer of the wrong
# shape. The batch is split down to that pull request, which is then shown as unreadable
# (UNKNOWN, an alert) instead of failing the refresh for every repository (Codex's review of
# de9a6fb).
ITS_OWN = {"graphql-error", "bad-response"}


def _its_own(error: FetchError, size: int) -> bool:
    """Whether an error can be blamed on the pull requests asked for. A GraphQL error counts
    only if every error GitHub gave points inside one of them (repository > pN > ...): one
    with no place, or anywhere else, is about the whole query, such as a permission or a
    validation error, and fails the refresh (Codex's review of 7faf35a: it made every pull
    request unreadable while the refresh reported success)."""
    if error.code == "bad-response":
        return True
    if error.code != "graphql-error" or not error.paths:
        return False
    aliases = {f"p{i}" for i in range(size)}
    return all(
        path is not None and len(path) >= 2 and path[0] == "repository" and path[1] in aliases
        for path in error.paths
    )


# The parts of a pull request the model can do without: each is "not known" (null) when it
# can't be read, and the rest is still judged. Every other field is needed to judge the pull
# request at all. When GitHub's error is on one of these, only that part is not known (Codex's
# review of c3ee86b: the whole pull request became unreadable, hiding a known unsafe merge).
OPTIONAL_FIELDS = {
    "title",
    "updatedAt",
    "headRefName",
    "closingIssuesReferences",
    "potentialMergeCommit",
    "files",
    "reviews",
    "commits",
}


class _Errored:
    """Stands where GitHub reported an error: no shape check accepts it, so that part is "not
    known". GitHub's own value there is null, which would read as none: no files, no result
    on the test merge commit, no linked issue."""


ERRORED = _Errored()


def _partial(error: FetchError, batch: list[int], lite: bool) -> list | None:
    """The answer GitHub gave along with field errors, as [(number, node, lite)], or None when
    it can't be used. Each error must be inside one of the pull requests asked for (_its_own).
    One on an optional part marks that part ERRORED; one on anything else, or on the pull
    request itself, makes that pull request UNREADABLE. GitHub nulls the nearest field that
    may be null, at or above the error's place, so the whole part is distrusted, never only
    the place named (Codex's review of c3ee86b)."""
    if not _its_own(error, len(batch)) or error.code != "graphql-error":
        return None
    data = error.data
    repository = data.get("repository") if isinstance(data, dict) else None
    if not isinstance(repository, dict):
        return None
    marks: dict[str, set | None] = {}
    for path in error.paths:
        alias = path[1]
        field = path[2] if len(path) > 2 else None
        if isinstance(field, str) and field in OPTIONAL_FIELDS and marks.get(alias, ()) is not None:
            marks.setdefault(alias, set()).add(field)
        else:
            marks[alias] = None  # the pull request itself, or a field it can't be judged without
    out = []
    for i, number in enumerate(batch):
        alias = f"p{i}"
        node = repository.get(alias)
        fields = marks.get(alias, set())
        if not isinstance(node, dict) or fields is None:
            node = UNREADABLE
        elif fields:
            node = {**node, **dict.fromkeys(fields, ERRORED)}
        out.append((number, node, lite))
    return out


_BASE_FIELDS = """
  number title state isDraft merged closedAt mergedAt
  mergedBy { login }
  headRefName headRefOid
  updatedAt
  closingIssuesReferences(first: $issues) {
    totalCount
    nodes {
      number title state
      repository { nameWithOwner }
      timelineItems(itemTypes: [LABELED_EVENT, UNLABELED_EVENT], last: $events) {
        totalCount
        nodes {
          __typename
          ... on LabeledEvent { createdAt actor { login } label { name } }
          ... on UnlabeledEvent { createdAt actor { login } label { name } }
        }
      }
    }
  }
"""
_HEAVY_FIELDS = """
  potentialMergeCommit {
    oid
    status { contexts { context } }
    checkSuites(first: 1) { totalCount }
  }
  files(first: $files) { totalCount nodes { path changeType } }
  reviews(last: $reviews) {
    totalCount
    nodes { state submittedAt author { __typename login } commit { oid } }
  }
  commits(last: 1) {
    nodes { commit { oid status { contexts { context state } } checkSuites(first: $suites) {
      totalCount
      nodes {
        app { slug }
        workflowRun { event }
        checkRuns(first: $runs) { totalCount nodes { name status conclusion } }
      }
    } } }
  }
"""
_LIMITS = {
    "files": MAX_FILES,
    "reviews": MAX_REVIEWS,
    "suites": MAX_SUITES,
    "runs": MAX_RUNS,
    "issues": MAX_ISSUES,
    "events": MAX_EVENTS,
}
FRAGMENT = Template("fragment pr on PullRequest {" + _BASE_FIELDS + _HEAVY_FIELDS + "}").substitute(
    _LIMITS
)
LITE_FRAGMENT = Template("fragment pr on PullRequest {" + _BASE_FIELDS + "}").substitute(_LIMITS)


def detail_query(numbers: list[int], lite: bool = False) -> str:
    """The details of these pull requests, by number. Numbers are checked integers, so they
    can be written into the query; everything else is a variable."""
    if not numbers or not all(type(n) is int and 0 < n < 2**31 for n in numbers):
        raise _bad()
    fields = "\n".join(
        f"    p{i}: pullRequest(number: {n}) {{ ...pr }}" for i, n in enumerate(numbers)
    )
    return (
        "query($owner: String!, $name: String!) {\n"
        "  repository(owner: $owner, name: $name) {\n"
        f"{fields}\n"
        "  }\n"
        "}\n" + (LITE_FRAGMENT if lite else FRAGMENT)
    )


class _Incomplete(Exception):
    """This part of GitHub's answer can't be trusted whole: leave it out."""


# Any sign that one optional part of a pull request's data is wrongly shaped: that part is
# then "not known", and the rest of the pull request is still judged (Codex's review of
# 7faf35a: an error in a merged PR's issue data threw away a known unsafe merge).
_SHAPE = (FetchError, TypeError, ValueError, AttributeError, KeyError, OverflowError)


def _bad() -> FetchError:
    return FetchError("bad-response")


def _obj(value: Any) -> dict:
    if not isinstance(value, dict):
        raise _bad()
    return value


def _list(value: Any) -> list:
    if not isinstance(value, list):
        raise _bad()
    return value


def _int(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _bad()
    return value


def _str(value: Any, limit: int = MAX_TEXT) -> str:
    """Untrusted text, cleaned: no control or direction-changing characters, capped."""
    if not isinstance(value, str):
        raise _bad()
    return " ".join(CONTROL.sub(" ", value).split())[:limit]


def _exact(value: Any, limit: int = MAX_TEXT) -> str:
    """A value the model matches (a label, a check, a branch name): kept exactly as GitHub
    gives it, never cleaned, because cleaning can turn one name into another (Codex's reviews of
    f772122 and 1cc6cf8: a cleaned label could become the authorisation label, a cleaned check
    name a required one). Only text that is shown is cleaned (_str). Anything that isn't a
    plain, bounded string leaves its part out, so the model shows UNKNOWN."""
    if not isinstance(value, str) or not 0 < len(value) <= limit or "\x00" in value:
        raise _Incomplete()
    return value


def _sha(value: Any) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise _bad()
    return value


def _time(value: Any) -> str:
    """GitHub's ISO time, re-written as an unambiguous UTC time the model accepts."""
    if not isinstance(value, str):
        raise _bad()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise _bad() from None
    if parsed.tzinfo is None:
        raise _bad()
    return parsed.astimezone(UTC).isoformat()


def _login(value: Any) -> str | None:
    """An actor's login, or None for a deleted account ("ghost")."""
    if value is None:
        return None
    login = _obj(value).get("login")
    if not isinstance(login, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\[\]-]{0,49}", login):
        raise _bad()
    return login


def _connection(value: Any, limit: int, counted: bool = True) -> list:
    """A connection's nodes; _Incomplete if GitHub has more than one request returned."""
    conn = _obj(value)
    nodes = _list(conn.get("nodes"))
    if counted:
        total = _int(conn.get("totalCount"))
        if total > len(nodes) or total > limit:
            raise _Incomplete()
    return nodes


def _files(pr: dict, clinical_paths: tuple[str, ...]) -> tuple[list[str] | None, bool]:
    """(the changed paths exactly as GitHub gives them, whether the list is complete). They are
    only matched against the clinical patterns, never shown, so cleaning them could only make
    two paths look alike and let a clinical one slip past its rule (Codex's review of f772122).
    A renamed or copied file is listed by its new path only, so a move out of a clinical folder
    would hide where it came from (f37d0c7); a list cut off at one request is partial too. Such
    a list is kept, marked incomplete: its known clinical paths still count (3f7d3c2), and the
    rest may be clinical. A path that isn't a plain, bounded string makes the list unknown."""
    conn = _obj(pr.get("files"))
    nodes = _list(conn.get("nodes"))
    complete = _int(conn.get("totalCount")) <= len(nodes)
    paths = []
    size = 0
    for node in nodes:
        n = _obj(node)
        path = n.get("path")
        if not isinstance(path, str) or not 0 < len(path) <= 4096 or "\x00" in path:
            raise _Incomplete()
        size += len(json.dumps(path)) + 3  # as written: escapes, comma, newline, indent
        if n.get("changeType") not in ("ADDED", "MODIFIED", "DELETED", "CHANGED"):
            complete = False
        paths.append(path)
    if size > MAX_PATH_BYTES:
        return _compact(paths, clinical_paths), False
    return paths, complete


def _compact(paths: list[str] | None, clinical_paths: tuple[str, ...]) -> list[str] | None:
    """A file list cut down to fit: one path that matches a clinical rule, kept so the model
    still knows the change is clinical and still warns when a clinician's approval is missing
    (Codex's review of 69ed8e3), or null ("not known") when none matches. The list is then
    partial either way: the rest may be clinical too."""
    for path in paths or ():
        if any(fnmatchcase(path, pattern) for pattern in clinical_paths):
            return [path]
    return None


def _reviews(pr: dict, clinicians: tuple[str, ...], merged: bool) -> list[dict]:
    """The clinicians' reviews: the only ones the model reads. Anyone can review a public
    pull request, so keeping every review let ordinary review volume push the snapshot over
    its limit (Codex's review of 9fb21c8). GitHub gives a review's current state with the time
    it was submitted, so for a merged PR a dismissed review can't be placed before or after the
    merge: the reviews are then "not known" (null) rather than a guess (9fb21c8)."""
    out = []
    for node in _connection(pr.get("reviews"), MAX_REVIEWS):
        n = _obj(node)
        state = n.get("state")
        if state == "PENDING":
            continue  # a draft review nobody else can see
        if state not in REVIEW_STATES:
            raise _bad()
        author = n.get("author")
        is_bot = isinstance(author, dict) and author.get("__typename") == "Bot"
        if is_bot or _login(author) not in clinicians:
            continue
        if merged and state == "DISMISSED":
            raise _Incomplete()
        commit = n.get("commit")
        if commit is None or n.get("submittedAt") is None:
            raise _Incomplete()  # a review whose commit is gone can't be placed: no guess
        out.append(
            {
                "user": _login(author),
                "user_type": "User",
                "state": state,
                "commit_id": _sha(_obj(commit).get("oid")),
                "at": _time(n.get("submittedAt")),
            }
        )
    return out


def _checks(pr: dict, head: str, app: str, required: tuple[str, ...]) -> list[dict]:
    """The head commit's check runs from the configured app only. A same-named run from any
    other app is left out, so it can never satisfy a required check (Codex's review of
    bf76866)."""
    # When GitHub has results for the test merge commit, it judges that commit, not the head.
    # Such results aren't read here, so the checks are left out and the model shows UNKNOWN,
    # rather than look greener than GitHub (Codex's review of 23bfb61).
    merge = pr.get("potentialMergeCommit")
    if merge is not None:
        merge = _obj(merge)
        merge_status = merge.get("status")
        if merge_status is not None and _list(_obj(merge_status).get("contexts")):
            raise _Incomplete()
        if _int(_obj(merge.get("checkSuites")).get("totalCount")) > 0:
            raise _Incomplete()
    commits = _list(_obj(pr.get("commits")).get("nodes"))
    if not commits:
        return []
    commit = _obj(_obj(commits[0]).get("commit"))
    if _sha(commit.get("oid")) != head:
        raise _Incomplete()
    out = []
    for suite in _connection(commit.get("checkSuites"), MAX_SUITES):
        suite = _obj(suite)
        suite_app = suite.get("app")
        if not isinstance(suite_app, dict) or suite_app.get("slug") != app:
            continue
        # Only runs started by a pull request, a push or the merge queue can stand for a PR's
        # required checks; GitHub leaves out a manually dispatched or scheduled run, and so
        # does this (Codex's review of f37d0c7). The aim is never to look greener than GitHub:
        # its ruleset, shown in the merge box, stays the authority on what can merge.
        # Only GitHub Actions suites have a workflow run; another configured app's checks are
        # taken as GitHub gives them (Codex's review of de9a6fb: they showed as missing).
        if app == "github-actions":
            run_event = _obj(suite.get("workflowRun") or {}).get("event")
            if run_event not in CHECK_EVENTS:
                continue
        for run in _connection(suite.get("checkRuns"), MAX_RUNS):
            r = _obj(run)
            raw_status = r.get("status")
            if not isinstance(raw_status, str):
                raise _bad()  # Codex's review of 23bfb61: an unhashable one raised TypeError
            status = CHECK_STATUS.get(raw_status, "queued")  # waiting, pending: not done
            conclusion = r.get("conclusion")
            if conclusion is not None and not isinstance(conclusion, str):
                raise _bad()
            out.append(
                {
                    "name": _exact(r.get("name")),
                    "head_sha": head,
                    "status": status,
                    "conclusion": conclusion.lower() if conclusion else None,
                }
            )
    out += _status_cautions(commit, head)
    # Only the required names: the model reads no others, and a fork's pull request can make
    # check runs with any name (Codex's review of dc1eb14: they could fill the snapshot).
    return [c for c in out if c["name"] in required]


def _status_cautions(commit: dict, head: str) -> list[dict]:
    """The head commit's statuses (GitHub's older kind of result), as cautions only. When a
    status and a check run share a required name, GitHub needs both to pass (Codex's review of
    ab64500). A status that isn't a success counts against that name; a successful one adds
    nothing, because a status can't be tied to an app the way a check run can, so it must never
    make a check look passed. Never greener than GitHub."""
    raw = commit.get("status")
    if raw is None:
        return []
    out = []
    for context in _list(_obj(raw).get("contexts")):
        c = _obj(context)
        state = c.get("state")
        if state not in STATUS_STATES:
            raise _bad()
        if state == "SUCCESS":
            continue
        pending = state in ("PENDING", "EXPECTED")
        out.append(
            {
                "name": _exact(c.get("context")),
                "head_sha": head,
                "status": "in_progress" if pending else "completed",
                "conclusion": None if pending else "failure",
            }
        )
    return out


def _issue(repo: str, pr: dict) -> tuple[int, dict | None, dict | None]:
    """(how many issues the PR closes, the issue's model input or None, its screen fields).
    An issue in another repository gives no issue: its number would point at the wrong one
    here (Codex's review of f772122)."""
    refs = _obj(pr.get("closingIssuesReferences"))
    total = _int(refs.get("totalCount"))
    nodes = _list(refs.get("nodes"))
    if total != 1 or len(nodes) != 1:
        return total, None, None  # none, or several: the model can't pick one, so no guess
    node = _obj(nodes[0])
    if _obj(node.get("repository")).get("nameWithOwner") != repo:
        return total, None, None
    number = _int(node.get("number"))
    state = node.get("state")
    if state not in ("OPEN", "CLOSED"):
        raise _bad()
    screen = {"number": number, "title": _str(node.get("title"), MAX_TITLE)}
    try:
        events = _connection(node.get("timelineItems"), MAX_EVENTS)
    except _Incomplete:
        return total, None, screen
    timeline = []
    try:
        for event in events:
            e = _event(event)
            # Only the agent:ready label's events: the model reads no others, and keeping them
            # all, once per pull request, could fill the snapshot (Codex's review of dc1eb14).
            if e["label"] == READY_LABEL:
                timeline.append(e)
    except _Incomplete:
        return total, None, screen
    issue = {"number": number, "state": state.lower(), "timeline": timeline}
    return total, issue, screen


def _event(event: Any) -> dict:
    """One label event, its label name exact (_exact)."""
    e = _obj(event)
    kind = {"LabeledEvent": "labeled", "UnlabeledEvent": "unlabeled"}.get(e.get("__typename"))
    if kind is None:
        raise _bad()
    # A deleted account is kept as "ghost": it can never authorise, but its removal of the
    # label still withdraws an authorisation (Codex's review of f772122: skipping it could
    # leave an earlier authorisation in force).
    actor = _login(e.get("actor")) or "ghost"
    return {
        "event": kind,
        "label": _exact(_obj(e.get("label")).get("name")),
        "actor": actor,
        "at": _time(e.get("createdAt")),
    }


def _item(repo: str, cfg: FetcherConfig, node: Any, lite: bool = False) -> dict:
    """One pull request as a snapshot item. `lite`: read without its files, reviews and checks
    (it was too large to read whole), which are then "not known"."""
    pr = _obj(node)
    number = _int(pr.get("number"))
    head = _sha(pr.get("headRefOid"))
    state = pr.get("state")
    if state not in ("OPEN", "CLOSED", "MERGED"):
        raise _bad()
    merged = pr.get("merged")
    draft = pr.get("isDraft")
    if not isinstance(merged, bool) or not isinstance(draft, bool):
        raise _bad()
    settings = cfg.repos[repo]
    pull = {
        "number": number,
        "state": "open" if state == "OPEN" else "closed",
        "draft": draft,
        "merged": merged,
        "merged_by": _login(pr.get("mergedBy")) if merged else None,
        # Authorisation counts only up to the merge (Codex's review of 72607b3).
        "merged_at": _time(pr.get("mergedAt")) if merged else None,
        "head_sha": head,
    }
    # Parts that can't be read whole are null ("not known"): the model never reads them as
    # clean, and still judges everything that is known.
    try:
        if lite:
            raise _Incomplete()
        pull["files"], complete = _files(pr, tuple(settings.clinical_paths))
        if not complete:
            pull["files_complete"] = False
    except (_Incomplete, *_SHAPE):
        pull["files"] = None
        pull.pop("files_complete", None)
    parts = [("reviews", lambda: _reviews(pr, cfg.clinicians, merged))]
    # Checks only for an open pull request. Once it is merged or closed, GitHub no longer shows
    # the test merge commit it judged, so no reading of the checks can match its verdict; the
    # merge box enforced them at the time (owner's decision, 2026-11-25, after Codex's review
    # of a1e05e5).
    if lite:
        parts = []
        pull["reviews"] = pull["checks"] = None
    elif state == "OPEN":
        parts.append(
            (
                "checks",
                lambda: _checks(pr, head, settings.checks_app, tuple(settings.required_checks)),
            )
        )
    else:
        # null: "not known", so the model still judges the merger, the authorisation, the
        # review and clinical approval (Codex's review of b24ac2d: leaving the key out made
        # the whole PR unreadable and hid those warnings).
        pull["checks"] = None
    for key, read in parts:
        try:
            pull[key] = read()
        except (_Incomplete, *_SHAPE):
            # null: "not known", so the model still judges what is known (Codex's review of
            # 198a66e: leaving the key out made the whole PR unreadable and hid its warnings).
            pull[key] = None
    try:
        linked, issue, issue_screen = _issue(repo, pr)
    except _SHAPE:
        linked, issue, issue_screen = 0, None, None  # not known: no claim from it
    task = {
        "repo": repo,
        "owner": cfg.owner,
        "clinicians": list(cfg.clinicians),
        "clinical_paths": list(settings.clinical_paths),
        "required_checks": list(settings.required_checks),
        "max_fix_rounds": 1,
        "runs": None,  # not read (A5a); [] would say "never reviewed"
        "pull_request": pull,
    }
    try:
        task["branch"] = {"name": _exact(pr.get("headRefName")), "head": head}
    except (_Incomplete, *_SHAPE):
        task["branch"] = None  # not known; the pull request's head is still known
    # null when no readable, authorised issue is linked: the model shows an open PR as
    # NOT_LINKED and still judges a merged one (Codex's review of 3f7d3c2: leaving the key out
    # made the whole PR unreadable).
    # A merged PR's issue link is GitHub's current one, not the link at the merge: it is no
    # evidence of which issue authorised the merge (Codex's review of 28546f5). The model then
    # makes no authorisation claim either way; the merger is still checked. The link is still
    # shown (issue_screen).
    task["issue"] = None if merged else issue
    short = repo.split("/", 1)[1]
    try:
        title = _str(pr.get("title"), MAX_TITLE)
    except _SHAPE:
        # Only shown, never judged: a title that can't be read must not make the whole pull
        # request unreadable and hide what is known about it (Codex's review of c3ee86b).
        title = NO_TITLE
    return {
        "id": f"{short}-{number}",
        "repo": repo,
        "number": number,
        "title": title,
        "url": f"https://github.com/{repo}/pull/{number}",
        "closed_at": None if pr.get("closedAt") is None else _time(pr.get("closedAt")),
        "linked_issues": linked,
        "issue": None
        if issue_screen is None
        else dict(issue_screen, url=f"https://github.com/{repo}/issues/{issue_screen['number']}"),
        "task": task,
    }


def _listing(repo: str, data: Any, now: datetime) -> tuple[list[int], bool]:
    """(the numbers to read in detail, whether more pull requests may exist than the list
    shows: open ones past the first page, or closed ones in the 14-day window past it)."""
    repository = _obj(_obj(data).get("repository"))
    open_conn = _obj(repository.get("open"))
    open_nodes = _list(open_conn.get("nodes"))
    more_open = _int(open_conn.get("totalCount")) > len(open_nodes)
    since = now - timedelta(days=RECENT_DAYS)
    numbers = [_int(_obj(n).get("number")) for n in open_nodes]
    closed_nodes = _list(_obj(repository.get("closed")).get("nodes"))
    for node in closed_nodes:
        closed_at = _obj(node).get("closedAt")
        if closed_at is not None and datetime.fromisoformat(_time(closed_at)) >= since:
            numbers.append(_int(_obj(node).get("number")))
    # Closed pull requests come newest-updated first: if the last one on a full page was
    # still updated in the window, more may lie past it. Say so rather than drop them
    # silently (Codex's review of f37d0c7).
    more_closed = False
    if len(closed_nodes) >= MAX_CLOSED:
        last = _obj(closed_nodes[-1]).get("updatedAt")
        more_closed = last is None or datetime.fromisoformat(_time(last)) >= since
    return list(dict.fromkeys(numbers)), more_open or more_closed


def _details(github: GitHub, token: str, owner: str, name: str, numbers: list[int]) -> list:
    """[(number, node, lite)] for these pull requests, in order; node UNREADABLE when GitHub's
    answer didn't hold it whole."""

    def fetch(batch: list[int], lite: bool) -> list:
        try:
            data = github.graphql(token, detail_query(batch, lite), {"owner": owner, "name": name})
        except FetchError as error:
            # Errors on some fields, with the rest of the answer: what GitHub did supply is
            # still judged (Codex's review of c3ee86b). With no usable answer, the error
            # stands and the batch is split as before.
            partial = _partial(error, batch, lite)
            if partial is None:
                raise
            return partial
        repository = _obj(_obj(data).get("repository"))
        # Missing or null: never silently dropped (Codex's review of 48929aa). It is shown as
        # unreadable; one deleted since the list is gone from the next refresh's list.
        return [(n, repository.get(f"p{i}") or UNREADABLE, lite) for i, n in enumerate(batch)]

    # At most about three requests per pull request: splitting to one and reading it lite.
    budget = [3 * len(numbers) + 2]

    def fetch_counted(batch: list[int], lite: bool) -> list:
        if budget[0] <= 0:
            raise FetchError("too-heavy")
        budget[0] -= 1
        return fetch(batch, lite)

    def read(batch: list[int]) -> list:
        try:
            return fetch_counted(batch, False)
        except FetchError as error:
            if error.code not in HEAVY and not _its_own(error, len(batch)):
                raise
        if len(batch) > 1:
            half = len(batch) // 2
            return read(batch[:half]) + read(batch[half:])
        try:
            return fetch_counted(batch, True)
        except FetchError as error:
            if not _its_own(error, 1):
                raise
            return [(batch[0], UNREADABLE, True)]

    out = []
    for i in range(0, len(numbers), BATCH):
        out += read(numbers[i : i + BATCH])
    return out


UNREADABLE = object()  # a pull request whose own data GitHub couldn't give whole
NO_TITLE = "(this pull request's title couldn't be read)"


def _unreadable(repo: str, number: int) -> dict:
    """A pull request that couldn't be read: shown, with task null, which the model shows as
    UNKNOWN (an alert). Never left out: that would look calmer than GitHub."""
    short = repo.split("/", 1)[1]
    return {
        "id": f"{short}-{number}",
        "repo": repo,
        "number": number,
        "title": "(this pull request couldn't be read)",
        "url": f"https://github.com/{repo}/pull/{number}",
        "closed_at": None,
        "linked_issues": 0,
        "issue": None,
        "task": None,
    }


def repo_items(repo: str, cfg: FetcherConfig, github: GitHub, token: str, now: datetime):
    """(items, whether more pull requests may exist than were read)."""
    owner, name = repo.split("/", 1)
    listing = github.graphql(token, LIST_QUERY, {"owner": owner, "name": name})
    numbers, more = _listing(repo, listing, now)
    since = now - timedelta(days=RECENT_DAYS)
    items = []
    details = _details(github, token, owner, name, numbers)
    readable = False
    for number, node, lite in details:
        try:
            if node is UNREADABLE:
                raise _bad()
            item = _item(repo, cfg, node, lite)
            if item["number"] != number:
                raise _bad()
        except (FetchError, TypeError, ValueError, AttributeError, KeyError, OverflowError):
            # This pull request's own data is wrongly shaped. Any such error, not only the
            # fetcher's own (Codex's review of 48929aa: an unhashable review state raised
            # TypeError and failed the refresh for every repository).
            item = _unreadable(repo, number)
        readable = readable or item["task"] is not None
        # A pull request closed between the list and its details still belongs here; one
        # closed before the window (possible only if the list was wrong) does not.
        if item["closed_at"] is None or datetime.fromisoformat(item["closed_at"]) >= since:
            items.append(item)
    if details and not readable:
        # Every pull request unreadable is no per-PR problem: fail, keeping the last good
        # snapshot, rather than replace it with nothing but unreadable entries (7faf35a).
        # Judged on the items as built, not on GitHub's answer: pull requests that were all
        # there but all failed their checks here passed the guard (Codex's review of c3ee86b).
        raise _bad()
    return items, more


def refresh(cfg: FetcherConfig, github: GitHub, now: datetime) -> dict:
    """One refresh: check the App is still read-only and limited to the configured
    repositories, read each one, and return the snapshot. The token is revoked whatever
    happens."""
    repos = sorted(cfg.repos)
    installation = github.installation(cfg.owner, repos)
    token = github.token(installation)
    try:
        github.repositories(token, repos)
        items, truncated = [], []
        for repo in repos:
            repo_list, more = repo_items(repo, cfg, github, token, now)
            items += repo_list
            if more:
                truncated.append(repo)
        snapshot = {
            "version": VERSION,
            "fetched_at": now.astimezone(UTC).isoformat(),
            "repos": repos,
            "truncated": truncated,
            "items": items,
        }
        # Measured exactly as it will be written and read (Codex's review of 1cc6cf8), inside
        # the try so a failed revoke is reported with it too (Codex's review of 23bfb61).
        _fit(snapshot)
    except BaseException as error:
        # The refresh failed, whatever the reason: revoke the token, and say too if it
        # outlived the refresh (Codex's review of bf76866).
        revoked = github.revoke(token)
        if not revoked:
            # Whatever went wrong, say the token outlived it (Codex's review of ab64500).
            code = error.code if isinstance(error, FetchError) else "internal"
            raise FetchError(code + "+token-not-revoked") from None
        raise
    snapshot["token_revoked"] = github.revoke(token)
    return snapshot


def _fit(snapshot: dict) -> None:
    """Keep the snapshot under MAX_SNAPSHOT as written. File lists are the one large part
    anyone can make (Codex's review of 72607b3: several repositories of long, escaped paths
    stopped every refresh), so the largest are cut down until it fits: to one known clinical
    path, so a known clinical change stays known (69ed8e3), or else to "not known" (null);
    either way the model treats the rest as possibly clinical. Then reviews (only clinicians'
    are kept) become "not known", which never counts as an approval. What remains is bounded
    and comes from trusted accounts: titles are capped, and labels and statuses need write or
    triage access. Then checks become "not known" (never passed), and last, whole items are
    left out, their repository marked truncated. Only if nothing is left does the refresh fail
    ("too-large")."""

    def size() -> int:
        return len(encode(dict(snapshot, token_revoked=False)))

    if size() <= MAX_SNAPSHOT:
        return
    tasks = [
        i["task"] for i in snapshot["items"] if i["task"] and i["task"]["pull_request"].get("files")
    ]
    tasks.sort(key=lambda t: len(encode({"f": t["pull_request"]["files"]})), reverse=True)
    for task in tasks:
        pull = task["pull_request"]
        pull["files"] = _compact(pull["files"], tuple(task["clinical_paths"]))
        if pull["files"] is None:
            pull.pop("files_complete", None)
        else:
            pull["files_complete"] = False
        if size() <= MAX_SNAPSHOT:
            return
    # Then the clinicians' reviews, largest first: null, "not known", never approved.
    pulls = [i["task"]["pull_request"] for i in snapshot["items"] if i["task"]]
    pulls = [p for p in pulls if p.get("reviews")]
    pulls.sort(key=lambda p: len(encode({"r": p["reviews"]})), reverse=True)
    for pull in pulls:
        pull["reviews"] = None
        if size() <= MAX_SNAPSHOT:
            return
    # Then the checks: null, "not known", never passed (CHECKS_UNVERIFIED).
    pulls = [i["task"]["pull_request"] for i in snapshot["items"] if i["task"]]
    pulls = [p for p in pulls if p.get("checks")]
    pulls.sort(key=lambda p: len(encode({"c": p["checks"]})), reverse=True)
    for pull in pulls:
        pull["checks"] = None
        if size() <= MAX_SNAPSHOT:
            return
    # Last, whole items: the oldest closed first, then the least recently updated open ones,
    # each repository so cut listed in "truncated", as when GitHub's list is cut off. A stale
    # snapshot for every repository would be worse (Codex's review of dc1eb14).
    items = snapshot["items"]
    closed = sorted((i for i in items if i["closed_at"] is not None), key=lambda i: i["closed_at"])
    opened = [i for i in items if i["closed_at"] is None][::-1]
    for item in closed + opened:
        items.remove(item)
        if item["repo"] not in snapshot["truncated"]:
            snapshot["truncated"].append(item["repo"])
        if size() <= MAX_SNAPSHOT:
            return
    raise FetchError("too-large")


def encode(data: dict) -> bytes:
    """The one way a snapshot or status file is written."""
    return json.dumps(data, indent=1, sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------- files


def write_json(folder: Path, name: str, data: dict, durable: bool = False) -> None:
    """Write `name` in `folder` whole, then rename it into place: a reader never sees half a
    file. Never through a symlink (the folder is opened with O_NOFOLLOW and used by its file
    descriptor); private while being written, then readable by the folder's group (the web
    app's account) only."""
    text = encode(data)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    folder_fd = os.open(folder, flags)
    try:
        group = os.fstat(folder_fd).st_gid
        tmp = f".{name}.{os.getpid()}.tmp"
        # A temp file left by a process killed mid-write, with the same pid, would otherwise
        # block every write (pre-review of 9537b08). Callers hold the refresh lock.
        try:
            os.unlink(tmp, dir_fd=folder_fd)
        except FileNotFoundError:
            pass
        create = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(tmp, create, 0o600, dir_fd=folder_fd)
        try:
            try:
                # The web app reads through the folder's group, which a new file inherits only
                # in a setgid folder (checked at start-up); refuse a file that didn't (Codex's
                # review of f772122), rather than write one the web app can't read.
                if os.fstat(fd).st_gid != group:
                    raise OSError("the new file didn't inherit the folder's group")
                view = memoryview(text)
                while view:  # os.write may write less than asked (Codex's review of bf76866)
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
                os.fchmod(fd, 0o640)
            finally:
                os.close(fd)
            os.replace(tmp, name, src_dir_fd=folder_fd, dst_dir_fd=folder_fd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=folder_fd)
            except OSError:
                pass
            raise
        # The new file is already in place and readable: a failed sync of the folder must not
        # report the write as failed (Codex's review of 198a66e). It only makes the rename's
        # survival of a sudden power cut less certain.
        # With `durable`, the write counts only once the folder is synced too: the attempt
        # recorded before any network work must survive a power cut, or a refresh could repeat
        # within the minute after a restart (Codex's review of c5ccf49).
        try:
            os.fsync(folder_fd)
        except OSError:
            if durable:
                raise
    finally:
        os.close(folder_fd)


def read_json(
    folder: Path, name: str, limit: int = MAX_SNAPSHOT, strict: bool = False
) -> dict | None:
    """The file's JSON object, or None when it is missing or unreadable. With `strict`, only a
    missing file gives None: a failure to open it raises OSError (pre-review of 9537b08: an
    unreadable status file was taken for "no earlier refresh"), and a malformed, oversized or
    non-object file raises ValueError (Codex's review of 9aeff19)."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(folder / name, flags)
    except FileNotFoundError:
        return None
    except OSError:
        if strict:
            raise
        return None
    with os.fdopen(fd, "rb") as f:
        data = f.read(limit + 1)
    try:
        if len(data) > limit:
            raise ValueError("too large")
        value = json.loads(data.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("not an object")
    except (ValueError, RecursionError):  # Unicode/JSON errors are ValueErrors; RecursionError:
        # deeply nested JSON (Codex's review of de9a6fb)
        if strict:
            raise ValueError("malformed") from None
        return None
    return value
