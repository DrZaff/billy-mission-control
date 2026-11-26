"""From GitHub's answers to the snapshot the web app reads (phase A5a, issue #16).

Each item carries the task model's input (`mission_control.tasks`), built only from fields this
module checks, plus the title and links the screens show. Everything from GitHub is untrusted:
- only the expected shapes are accepted: a wrongly shaped list or installation answer fails the
  refresh ("bad-response"); a wrongly shaped detail answer, or one pull request's wrongly shaped
  data, makes only those items unreadable (task null, shown as UNKNOWN), never calm;
- text is cleaned (no control characters) and capped; links are built here from the repository
  and number, never taken from GitHub's answer;
- where a part of GitHub's answer is incomplete (more files, reviews, checks or label events than
  one request returns, a partial error, a lite read), that part is written as "not known": null,
  or a list marked partial (files_complete or checks_complete false). The model never reads it
  as clean; it shows the part as not verified. Nothing here decides a state: `tasks.derive`
  does, in the web app.

One key the model needs is left for the web app (phase A5b): `paused`, which it reads from the
stop marker itself. `runs` is null, "not read": phase A5 starts with GitHub data only (issue
#15, 2026-11-24), and an empty list would claim no review ever happened.

Each item's `checks_fresh_until` is when its first counted pass stops being fresh (GitHub needs
one within seven days). After that time the web app must count none of the item's passes: its
checks are then not verified, and a failure still fails (A5b; Codex's review of 1e0f9b0). A
snapshot is read long after it is written, so freshness is judged when it is read.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
import unicodedata
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from string import Template
from typing import Any

from mission_control.tasks import READY_LABEL, InvalidInput, State, derive, parse

from .config import APP_SLUG, FetcherConfig
from .github import STOPPING, FetchError, GitHub

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
MAX_KEPT_PATH = 512  # a clinical path kept in a cut list, as written
SHA = re.compile(r"[0-9a-f]{40}")
HIDDEN = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
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
# GitHub's CheckStatusState values, exactly: the rest (waiting, pending, requested) aren't done.
CHECK_STATUS_STATES = frozenset({*CHECK_STATUS, "PENDING", "REQUESTED", "WAITING"})
# GitHub's CheckConclusionState values, exactly as it writes them.
CHECK_CONCLUSIONS = frozenset(
    {
        "ACTION_REQUIRED",
        "CANCELLED",
        "FAILURE",
        "NEUTRAL",
        "SKIPPED",
        "STALE",
        "STARTUP_FAILURE",
        "SUCCESS",
        "TIMED_OUT",
    }
)

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
      pageInfo { hasNextPage endCursor }
    }
  }
}
""").substitute(open=MAX_OPEN, closed=MAX_CLOSED)
# Further pages of closed pull requests, newest-updated first. Anyone can bump an old pull
# request's update time (a comment), so one page could push a recent merge off the list (Fable's
# pre-review of 8152df0): pages are read while the last one is still in the window, up to
# CLOSED_PAGES; past that the repository is marked truncated.
CLOSED_QUERY = Template("""
query($$owner: String!, $$name: String!, $$after: String!) {
  repository(owner: $$owner, name: $$name) {
    closed: pullRequests(states: [CLOSED, MERGED], first: $closed, after: $$after,
                         orderBy: {field: UPDATED_AT, direction: DESC}) {
      nodes { number closedAt updatedAt }
      pageInfo { hasNextPage endCursor }
    }
  }
}
""").substitute(closed=MAX_CLOSED)
CLOSED_PAGES = 5

BATCH = 10
REFRESH_DEADLINE = 180.0  # seconds


def _on_time(deadline: float | None) -> None:
    """Checked after every request too: one that finishes past the limit fails the refresh
    (Codex's review of 9dbb868: the limit was checked only before detail requests)."""
    if deadline is not None and time.monotonic() > deadline:
        raise FetchError("too-slow")
    if STOPPING.is_set():
        # A stop asked for mid-refresh: what was read since may be failures of its own making,
        # so the refresh fails rather than write it (Codex's review of b7d0915).
        raise FetchError("interrupted")


# Failures that may mean the query was too heavy, not that GitHub is down: the batch is split
# (Codex's review of 28546f5: GitHub can stop a costly query by time or resources, before the
# answer reaches the size cap). A lone pull request whose lite read or retry is still too heavy
# is read with its core only (Codex's review of 099ef9b); if even that fails, or the request
# budget runs out ("over-budget"), the refresh fails with GitHub's own error.
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
REVIEW_ALIAS = re.compile(r"rv\d{1,2}")


def _piece(field) -> str | None:
    """The optional piece a field of a pull request belongs to, or None for a core field."""
    if not isinstance(field, str):
        return None
    if REVIEW_ALIAS.fullmatch(field):
        return "reviews"
    return field if field in PIECES else None


class _Errored:
    """Stands where GitHub reported an error: no shape check accepts it, so that part is "not
    known". GitHub's own value there is null, which would read as none: no files, no result
    on the test merge commit, no linked issue."""


ERRORED = _Errored()


class Retry:
    """A pull request GitHub nulled whole for an error on an optional field (a non-null one,
    such as its title, nulls its parent): asked for again without just those pieces, then with
    the core fields only, so what is known is still judged (Codex's review of 8152df0; Fable's
    pre-review of 4945de9: it went straight to the core)."""

    def __init__(self, pieces: frozenset):
        self.pieces = pieces


def _head_contradicted(pr: dict, head: str) -> bool:
    """Whether the commit rows GitHub gave can be read, and name only commits other than the
    head."""
    try:
        rows = _list(_obj(pr.get("commits")).get("nodes")) if "commits" in pr else []
    except FetchError:
        return False
    oids = []
    for row in rows:
        try:
            oids.append(_sha(_obj(_obj(row).get("commit")).get("oid")))
        except FetchError:
            continue
    return bool(oids) and head not in oids


def _optional_place(path: tuple, size: int) -> bool:
    """Whether a place in a detail answer is inside an optional part of one of the `size` pull
    requests asked for (one a retry can leave out), not the pull request itself, one of its
    core fields, or a pull request not asked for."""
    aliases = {f"p{i}" for i in range(size)}
    return (
        len(path) >= 3
        and path[0] == "repository"
        and path[1] in aliases
        and _piece(path[2]) is not None
    )


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
    deep_commits: set[str] = set()
    deep_files: set[str] = set()
    # The parts with an error deep inside them, by pull request: if GitHub nulled the whole
    # pull request for it, a retry without them may still read it (Codex's review of b1fef32).
    deep: dict[str, set[str]] = {}
    for path in error.paths:
        alias = path[1]
        field = path[2] if len(path) > 2 else None
        if field in ("files", "commits") and len(path) > 3:
            deep.setdefault(alias, set()).add(field)
        if field == "files" and len(path) > 3:
            # An error inside one file's entry: GitHub nulled that entry, and the paths it did
            # give are kept, so a clinical one among them is still found (clinical_known), but
            # the list is marked partial, never complete (Codex's reviews of c5adbba and 96a9e17).
            deep_files.add(alias)
            continue
        if field == "commits" and len(path) > 3:
            # An error inside the checks: what GitHub did give is kept, marked partial, so a
            # failure it reported still counts; nothing in it can pass (Fable's pre-review of
            # 4945de9: a failing check vanished).
            deep_commits.add(alias)
            continue
        piece = _piece(field)
        if piece is not None and marks.get(alias, ()) is not None:
            marks.setdefault(alias, set()).add(field)
        else:
            marks[alias] = None  # the pull request itself, or a field it can't be judged without
    out = []
    for i, number in enumerate(batch):
        alias = f"p{i}"
        node = repository.get(alias)
        fields = marks.get(alias, set())
        if not isinstance(node, dict) and fields is not None and (fields or alias in deep):
            node = Retry(frozenset(_piece(f) for f in fields | deep.get(alias, set())))
        elif not isinstance(node, dict) or fields is None:
            node = UNREADABLE
        else:
            if fields:
                node = {**node, **dict.fromkeys(fields, ERRORED)}
            if alias in deep_commits:
                node = {**node, "__checks_partial__": True}
            if alias in deep_files:
                node = {**node, "__files_partial__": True}
        out.append((number, node, lite))
    return out


# The fields every query asks for: what the merge verdict needs.
CORE_FIELDS = """
  number state isDraft merged closedAt mergedAt isCrossRepository
  mergedBy { __typename login }
  headRefOid
"""
_LIMITS = {
    "files": MAX_FILES,
    "reviews": MAX_REVIEWS,
    "suites": MAX_SUITES,
    "runs": MAX_RUNS,
    "issues": MAX_ISSUES,
    "events": MAX_EVENTS,
}
# The optional parts, each of which can be left out on its own: a retry leaves out only the
# parts GitHub had an error on (Fable's pre-review of 4945de9), and the lite read only the large
# ones. Reviews are asked for per clinician (`reviews`, below).
PIECES = {
    "title": "title",
    "headRefName": "headRefName",
    "closingIssuesReferences": Template("""
  closingIssuesReferences(first: $issues) {
    totalCount
    nodes {
      number title state
      repository { nameWithOwner }
      timelineItems(
        itemTypes: [LABELED_EVENT, UNLABELED_EVENT, CLOSED_EVENT, REOPENED_EVENT], last: $events
      ) {
        totalCount
        nodes {
          __typename
          ... on LabeledEvent { id createdAt actor { __typename login } label { name } }
          ... on UnlabeledEvent { id createdAt actor { __typename login } label { name } }
          ... on ClosedEvent {
            id createdAt actor { __typename login }
            closer { __typename ... on PullRequest { number repository { nameWithOwner } } }
          }
          ... on ReopenedEvent { id createdAt actor { __typename login } }
        }
      }
    }
  }""").substitute(_LIMITS),
    "potentialMergeCommit": """
  potentialMergeCommit {
    oid
    status { contexts { context } }
    checkSuites(first: 1) { totalCount }
  }""",
    "files": Template("""
  files(first: $files) { totalCount nodes { path changeType } }""").substitute(_LIMITS),
    "reviews": None,  # built per clinician
    "commits": Template("""
  commits(last: 1) {
    nodes { commit {
      oid status { contexts { context state createdAt } } checkSuites(first: $suites) {
      totalCount
      nodes {
        id app { slug }
        workflowRun { event }
        checkRuns(first: $runs, filterBy: {checkType: LATEST}) {
          totalCount nodes { id name status conclusion completedAt }
        }
      }
    } } }
  }""").substitute(_LIMITS),
}
LARGE = frozenset({"files", "commits", "potentialMergeCommit"})  # left out of the lite read
ALL_PIECES = frozenset(PIECES)
LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")


def _review_fields(clinicians: tuple[str, ...]) -> str:
    """One reviews connection per clinician, `rv<i>`: GitHub filters by author, so no number
    of other people's reviews can push a clinician's out of the answer (Fable's pre-review of
    4945de9: 100 strangers' comments made every review "not known")."""
    parts = []
    for i, login in enumerate(clinicians):
        if not LOGIN.fullmatch(login):
            raise _bad()
        parts.append(
            f"\n  rv{i}: reviews(author: {json.dumps(login)}, last: {MAX_REVIEWS}) {{"
            "\n    totalCount"
            "\n    nodes { id state submittedAt author { __typename login } commit { oid } }"
            "\n  }"
        )
    return "".join(parts)


def detail_query(
    numbers: list[int], omit: frozenset = frozenset(), clinicians: tuple[str, ...] = ()
) -> str:
    """The details of these pull requests, by number, without the pieces in `omit`. Numbers
    and logins are checked first, so they can be written into the query."""
    if not numbers or not all(type(n) is int and 0 < n < 2**31 for n in numbers):
        raise _bad()
    fields = "\n".join(
        f"    p{i}: pullRequest(number: {n}) {{ ...pr }}" for i, n in enumerate(numbers)
    )
    body = CORE_FIELDS
    for name, text in PIECES.items():
        if name in omit:
            continue
        body += _review_fields(clinicians) if name == "reviews" else "\n  " + text.strip()
    return (
        "query($owner: String!, $name: String!) {\n"
        "  repository(owner: $owner, name: $name) {\n"
        f"{fields}\n"
        "  }\n"
        "}\n"
        "fragment pr on PullRequest {" + body + "\n}\n"
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


def _placed(at: str, now: datetime | None) -> datetime:
    """A time that may be judged against the refresh: one later than `now`, beyond clock drift,
    is wrongly dated, and nothing is placed by it (pre-review of 07c3480: a review, an event or
    a merge dated in the future counted). Raises _Incomplete."""
    when = datetime.fromisoformat(at)
    if now is not None and when > now + FUTURE_SKEW:
        raise _Incomplete()
    return when


def _fresh(stale_at: datetime, now: datetime) -> bool:
    """Whether a result going stale at `stale_at` is fresh now: not yet stale, and not dated in
    the future beyond clock drift."""
    return now <= stale_at <= now + CHECK_FRESH + FUTURE_SKEW


def _distinct(nodes: list) -> bool:
    """Whether no row repeats another. A repeated row may stand where GitHub omitted one (a
    changes request, a label's removal, a failing check), so a counted list with a repeat is
    never whole (Codex's review of caf31c9). Rows are told apart by GitHub's own node id, so
    two real rows that look alike are never taken for a repeat (Codex's review of 0dc0f8b)."""

    # Every row is asked for its id, and GitHub always gives one: a row without one (or with
    # an odd one) is never compared by its content, which a copy of an id'd row would pass
    # (Codex's review of 2084eb4).
    ids = [n.get("id") if isinstance(n, dict) else None for n in nodes]
    if not all(isinstance(i, str) and 0 < len(i) <= 200 for i in ids):
        return False
    return len(set(ids)) == len(ids)


def _whole(conn: dict, nodes: list, cap: int) -> bool:
    """Whether a connection's nodes are all there is: its count readable, no more than the
    nodes given, within the cap, and no row repeated."""
    total = conn.get("totalCount")
    good = isinstance(total, int) and not isinstance(total, bool) and total >= 0
    # Exactly as many: fewer is cut off, more is a contradiction (Codex's review of b1f5a1a).
    return good and total == len(nodes) and len(nodes) <= cap and _distinct(nodes)


def _int(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _bad()
    return value


def _str(value: Any, limit: int = MAX_TEXT) -> str:
    """Untrusted text, cleaned: no control, format (direction-changing, zero-width) or lone
    surrogate characters, capped (Fable's pre-review of 8152df0: U+200E, zero-width and C1
    characters, and lone surrogates, which can't be written as UTF-8, got through)."""
    if not isinstance(value, str):
        raise _bad()
    text = CONTROL.sub(" ", value)
    text = "".join(" " if unicodedata.category(c) in HIDDEN else c for c in text)
    return " ".join(text.split())[:limit]


def _exact(value: Any, limit: int = MAX_TEXT) -> str:
    """A value the model matches (a label, a check, a branch name): kept exactly as GitHub
    gives it, never cleaned, because cleaning can turn one name into another (Codex's reviews of
    f772122 and 1cc6cf8: a cleaned label could become the authorisation label, a cleaned check
    name a required one). Only text that is shown is cleaned (_str). Anything that isn't a
    plain, bounded string leaves its part out, so the model shows UNKNOWN."""
    if not isinstance(value, str) or not 0 < len(value) <= limit or "\x00" in value:
        raise _Incomplete()
    try:
        value.encode("utf-8")  # a lone surrogate can't be written or shown (8152df0)
    except UnicodeEncodeError:
        raise _Incomplete() from None
    return value


def _sha(value: Any) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise _bad()
    return value


ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})")


def _time(value: Any) -> str:
    """GitHub's ISO time, re-written as an unambiguous UTC time the model accepts: GitHub's own
    shape only, and to the whole second, the model's resolution, so the two place every event
    alike (pre-review of 07c3480: a half second let the fetcher drop a review the model would
    have held in doubt)."""
    if not isinstance(value, str) or not ISO_TIME.fullmatch(value):
        raise _bad()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise _bad() from None
    if parsed.tzinfo is None:
        raise _bad()
    try:
        return parsed.astimezone(UTC).replace(microsecond=0).isoformat()
    except OverflowError:
        # A time at the edge of the calendar (year 1 or 9999 with an offset): a bad value like
        # any other, never an error that discards the rest (audit of ea9b32a).
        raise _bad() from None


def _login(value: Any) -> str | None:
    """A GitHub user's login, or None for a deleted account ("ghost") or any other kind of
    actor: a bot or an app can share a person's name, so it never authorises or merges as one
    (Codex's review of 322b659, for reviews; the same for labels and the merger)."""
    if value is None:
        return None
    if _obj(value).get("__typename") != "User":
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
        if total != len(nodes) or total > limit or not _distinct(nodes):
            raise _Incomplete()  # cut off, a count that contradicts the nodes, or a repeat
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
    complete = _int(conn.get("totalCount")) == len(nodes) and not pr.get("__files_partial__")
    complete = complete and len(nodes) <= MAX_FILES  # more than asked for: not whole
    paths = []
    size = 0
    for node in nodes:
        n = _obj(node)
        path = n.get("path")
        if not isinstance(path, str) or not 0 < len(path) <= 4096 or "\x00" in path:
            raise _Incomplete()
        # A path git can't have: never read as an ordinary, non-clinical one (pre-review of
        # 6b7da87).
        if any(part in ("", ".", "..") for part in path.split("/")):
            raise _Incomplete()
        try:
            path.encode("utf-8")
        except UnicodeEncodeError:
            raise _Incomplete() from None
        size += len(json.dumps(path)) + 3  # as written: escapes, comma, newline, indent
        if n.get("changeType") not in ("ADDED", "MODIFIED", "DELETED", "CHANGED"):
            complete = False
        paths.append(path)
    if len(set(paths)) != len(paths):
        # A repeated path fills a row another path should have, perhaps a clinical one: the
        # list is partial whatever its count says (Codex's review of 96cb8a9).
        complete = False
    if size > MAX_PATH_BYTES:
        return _compact(paths, clinical_paths), False
    return paths, complete


def _all_paths(pr: dict) -> list[str]:
    """Every plain path GitHub gave, before any cut; anything odd is simply not matched."""
    try:
        nodes = _list(_obj(pr.get("files")).get("nodes"))
    except FetchError:
        return []
    out = []
    for node in nodes:
        path = node.get("path") if isinstance(node, dict) else None
        if isinstance(path, str) and path:
            out.append(path)  # any length: a long clinical path is still clinical (4945de9)
    return out


def _clinical(paths: list[str] | None, clinical_paths: tuple[str, ...]) -> bool:
    return any(fnmatchcase(p, pattern) for p in paths or () for pattern in clinical_paths)


def _cut(pull: dict, clinical_paths: tuple[str, ...], keep_one: bool) -> None:
    """Cut a pull request's file list to fit, keeping what it proved: if a path matched a
    clinical rule, `clinical_known` says so, whatever is kept (Codex's review of 9dbb868: a
    long clinical path, or the step that nulls every list, erased the evidence and with it the
    warning that clinical files were merged without a clinician)."""
    if _clinical(pull.get("files"), clinical_paths):
        pull["clinical_known"] = True
    pull["files"] = _compact(pull.get("files"), clinical_paths) if keep_one else None
    if pull["files"] is None:
        pull.pop("files_complete", None)
    else:
        pull["files_complete"] = False


def _compact(paths: list[str] | None, clinical_paths: tuple[str, ...]) -> list[str] | None:
    """A file list cut down to fit: one path that matches a clinical rule, kept so the model
    still knows the change is clinical and still warns when a clinician's approval is missing
    (Codex's review of 69ed8e3), or null ("not known") when none matches. The list is then
    partial either way: the rest may be clinical too."""
    # The shortest match, and only a short one: a stranger's long clinical-looking paths must
    # not keep a large list alive while known facts are cut (Fable's pre-review of 8152df0).
    matches = [p for p in paths or () if any(fnmatchcase(p, pattern) for pattern in clinical_paths)]
    if matches:
        shortest = min(matches, key=lambda p: len(json.dumps(p)))
        if len(json.dumps(shortest)) <= MAX_KEPT_PATH:
            return [shortest]
    return None


VANISHED = "0" * 40  # a review's commit that is gone (force-pushed away): never the head


def _reviews(
    pr: dict,
    clinicians: tuple[str, ...],
    merged_at: datetime | None,
    now: datetime | None = None,
) -> list[dict]:
    """The clinicians' reviews, the only ones the model reads, one connection per clinician
    (`rv<i>`). A part missing or cut off makes the reviews "not known". Each review is first
    placed in time, and one submitted after a merge is skipped before anything else about it is
    checked (Codex's reviews of 84df535 and 5d06878). GitHub gives a review's current state with
    the time it was submitted, so when a review was dismissed isn't known: every review is
    kept, and the model decides "not known" only when its verdict depends on one (audit of
    42a3721: dropping them all hid a changes request in force at the merge). A review of a
    vanished commit is kept as one that is never the head."""
    out = []
    ids: set[str] = set()
    for i, login in enumerate(clinicians):
        if f"rv{i}" not in pr:
            raise _Incomplete()
        for node in _connection(pr.get(f"rv{i}"), MAX_REVIEWS):
            n = _obj(node)
            # One review in two clinicians' lists may stand for an omitted one (pre-review of
            # 6b7da87), as a repeat within one list may.
            if n.get("id") in ids:
                raise _Incomplete()
            ids.add(n.get("id"))
            state = n.get("state")
            if state == "PENDING":
                # An App never sees another user's draft review: one here is a surprise, and
                # the reviews are not known (Codex's review of b03ad71; pre-review of 6b7da87).
                raise _Incomplete()
            submitted = n.get("submittedAt")
            if submitted is None:
                raise _Incomplete()  # a review that can't be placed in time: no guess
            at = _placed(_time(submitted), now)
            if merged_at is not None and at > merged_at:
                continue  # after the merge: skipped before anything else (audit of 0585599)
            author = n.get("author")
            # GitHub filtered by author, and logins are case-insensitive: anything else in this
            # clinician's own connection (no author, a deleted account, a bot, a kind GitHub
            # didn't say) is a surprise, never "someone else": the reviews are not known
            # (Codex's reviews of 07c05d4 and 322b659: skipping one could hide a changes request).
            if not isinstance(author, dict) or author.get("__typename") != "User":
                raise _Incomplete()
            seen = author.get("login")
            if not isinstance(seen, str) or seen.lower() != login.lower():
                raise _Incomplete()
            if not isinstance(state, str) or state not in REVIEW_STATES:
                raise _bad()
            if "commit" not in n:
                raise _Incomplete()  # left out: not known, never "gone" (Codex, 7ac622f)
            commit = n.get("commit")
            commit_id = VANISHED if commit is None else _sha(_obj(commit).get("oid"))
            if commit is not None and commit_id == VANISHED:
                raise _Incomplete()  # GitHub's own oid can't be the sentinel (6b7da87)
            out.append(
                {
                    "user": login,
                    "user_type": "User",
                    "state": state,
                    "commit_id": commit_id,
                    "at": _time(submitted),
                }
            )
    return out


CHECK_FRESH = timedelta(days=7)
# A result dated later than this after the refresh is wrongly dated, not fresh: it would pass
# for longer than seven days (Codex's review of 9650d02). A few minutes allow for clock drift.
FUTURE_SKEW = timedelta(minutes=5)
# Freshness changes with time, and a snapshot is read long after it is written: each item says
# when its counted passes stop being fresh (checks_fresh_until), and a reader counts none of
# them after that, failures still failing (A5b). The time a snapshot takes to be written then
# never matters (Codex's reviews of 05062fc to 28d71fe; owner's decision, 2026-11-25).


def _checks(
    pr: dict,
    head: str,
    app: str,
    required: tuple[str, ...],
    now: datetime | None = None,
    expiry: list | None = None,
) -> tuple[list[dict], bool]:
    """(the head commit's results for the required check names, whether they are complete).
    Check runs from the configured app only: a same-named run from any other app can never
    satisfy a required check (Codex's review of bf76866). Whatever can't be read whole makes
    the list partial, never empty: a failure GitHub did report is kept, since any failure
    fails a check, and a partial list never passes (Fable's pre-review of 4945de9: a failing
    check vanished whenever the reading was degraded). Names that aren't required are passed
    over before anything else about them is read. Each pass counted adds the time it stops
    being fresh to `expiry`."""
    expiry = [] if expiry is None else expiry
    complete = not pr.get("__checks_partial__")
    out: list[dict] = []
    # When GitHub has results for the test merge commit, it judges that commit, not the head.
    # Such results aren't read here, so the list is partial (Codex's review of 23bfb61).
    if "potentialMergeCommit" not in pr:
        complete = False  # left out by a retry: never read as "no test merge commit" (42a3721)
    merge = pr.get("potentialMergeCommit")
    if merge is not None:
        try:
            merge = _obj(merge)
            if _sha(merge.get("oid")) in (head, VANISHED):
                complete = False  # never the head (6b7da87), nor "gone" (Codex, 34ad21c)
            if "status" not in merge:
                complete = False  # left out: not known, never "no statuses" (Codex, a34154f)
            merge_status = merge.get("status")
            if merge_status is not None and _list(_obj(merge_status).get("contexts")):
                complete = False
            if _int(_obj(merge.get("checkSuites")).get("totalCount")) > 0:
                complete = False
        except FetchError:
            complete = False
    commits = _list(_obj(pr.get("commits")).get("nodes"))
    # Exactly the head: an open pull request always has one, and asked for the last one, GitHub
    # gives one row (pre-review of 07c3480: none read as "no checks", a second was ignored).
    if len(commits) != 1:
        if not commits:
            return [], False
        complete = False
    # The head's own row, wherever it is: with several, a later one may be the head, and its
    # failures still count (Codex's review of cc29d6e).
    # Every row naming the head is read, and a malformed sibling only makes the list partial:
    # it never stops the head's own row being read (Codex's review of 2084eb4).
    heads = []
    for row in commits:
        try:
            commit = _obj(_obj(row).get("commit"))
            oid = _sha(commit.get("oid"))
        except FetchError:
            complete = False
            continue
        if oid == head:
            heads.append(commit)
    if not heads:
        raise _Incomplete()  # results for another commit: none of them apply
    if len(heads) > 1:
        complete = False
    run_ids: set[str] = set()
    suites: list = []
    for commit in heads:
        try:
            suites_conn = _obj(commit.get("checkSuites"))
            nodes = _list(suites_conn.get("nodes"))
        except FetchError:
            complete = False
            continue
        # A count that can't be read only makes the list partial: what GitHub did give,
        # a failure among it, is still read (Codex's review of 6e22a60).
        if not _whole(suites_conn, nodes, MAX_SUITES):
            complete = False
        suites += nodes
    for suite in suites:
        if not isinstance(suite, dict):
            complete = False
            continue
        # A run in two suites may stand for an omitted one: every suite's runs are counted here,
        # before any suite is passed over (pre-review of 07c3480; Codex's review of cc29d6e).
        raw_runs = suite.get("checkRuns")
        raw_runs = raw_runs.get("nodes") if isinstance(raw_runs, dict) else None
        for raw in raw_runs if isinstance(raw_runs, list) else ():
            run_id = raw.get("id") if isinstance(raw, dict) else None
            if isinstance(run_id, str):
                if run_id in run_ids:
                    complete = False
                run_ids.add(run_id)
        suite_app = suite.get("app")
        slug = suite_app.get("slug") if isinstance(suite_app, dict) else None
        unknown = "app" not in suite or (
            suite_app is not None and not (isinstance(slug, str) and APP_SLUG.fullmatch(slug))
        )
        if unknown or (suite_app is None and not _provably_no_required(suite, required)):
            # Left out, wrongly shaped or not a slug (28009de, 42a3721, 9044492), or null (as a
            # GraphQL error leaves it) with runs that may be required ones (d99b49a): not
            # known, yet read as the configured app's, so a failure in it still fails (0f323f6).
            complete = False
            suite_app, slug = {}, app
        if slug != "github-actions" and suite.get("workflowRun", 0) is not None:
            # Left out (d99b49a) or there: not known, as only Actions suites have one (6b7da87).
            # The configured app's own suite is still read on, so a failure in it still fails
            # (pre-review of 8c4bfec).
            complete = False
            if slug != app:
                continue
        if suite_app is None or slug != app:
            # Not the configured app: its successes never count, but a failing or unfinished
            # run with a required name keeps the checks from passing (pre-review of e995f6a).
            # An Actions suite's own workflow run must still read as one (Fable, ba87dc7).
            if not _provably_harmless_runs(suite, required) or (
                slug == "github-actions" and _run_event(suite.get("workflowRun", 0)) is False
            ):
                complete = False
            continue
        # Only runs started by a pull request, a push, the merge queue, or a review or
        # deployment event (CHECK_EVENTS) can stand for a PR's required checks (Codex's review
        # of f37d0c7). Only GitHub Actions suites have a
        # workflow run; another app's checks are taken as GitHub gives them (de9a6fb).
        if app == "github-actions":
            workflow_run = suite.get("workflowRun")
            event = workflow_run.get("event") if isinstance(workflow_run, dict) else None
            # Left out, wrongly shaped, or null with runs that may hold a required check: its
            # event can't be told, so not known (audits of 0585599, 42a3721 and 28009de). Its
            # runs are still read, so a failure in them still fails (pre-review of b8b1ca7);
            # being partial, the list never passes on them.
            unknown_event = "workflowRun" not in suite or (
                workflow_run is not None and not _run_event(workflow_run)
            )
            if (
                workflow_run is None
                and not unknown_event
                and _provably_no_required(suite, required)
            ):
                continue  # provably whole, with no required check: nothing to read
            if unknown_event or workflow_run is None:
                complete = False
            elif event not in CHECK_EVENTS:
                # GitHub leaves such a run out of a PR's required checks (Codex's review of
                # f37d0c7), so its success never counts. But a failing or unfinished run with a
                # required name may still bear on the merge box: not known, never dropped
                # silently, and never passed (audit of 80e8fb3).
                if not _provably_harmless_runs(suite, required):
                    complete = False
                continue
        try:
            runs_conn = _obj(suite.get("checkRuns"))
            runs = _list(runs_conn.get("nodes"))
        except FetchError:
            runs, complete = [], False
        else:
            if not _whole(runs_conn, runs, MAX_RUNS):
                complete = False
        for run in runs:
            if not isinstance(run, dict):
                complete = False
                continue
            name = run.get("name")
            if not isinstance(name, str) or not name:
                complete = False  # wrongly shaped: not known, never skipped (audit of 28009de)
                continue
            # Only required names. A pass counts only under the exact name (Codex's review of
            # dc1eb14); anything else under the name in another case still counts against it
            # (Codex's review of 0f79663).
            key = _required_name(name, required)
            if key is None:
                continue
            raw_status = run.get("status")
            conclusion = run.get("conclusion")
            if not isinstance(raw_status, str) or not (
                conclusion is None or isinstance(conclusion, str)
            ):
                complete = False  # Codex's review of 23bfb61: an odd one raised TypeError
                continue
            if conclusion is not None and conclusion not in CHECK_CONCLUSIONS:
                # Only GitHub's own values, exactly: a "success" in another case would skip the
                # freshness check below and still read as passed (Codex's review of b1fef32).
                complete = False
                continue
            if (
                "conclusion" not in run
                or "completedAt" not in run
                or (raw_status != "COMPLETED" and run.get("completedAt") is not None)
            ):
                # Left out, or a finish time on a run not completed: not known, never pending
                # (pre-review of 6b7da87). Still read on: a failure it reports still fails.
                complete = False
            if raw_status not in CHECK_STATUS_STATES or (
                conclusion is not None and raw_status != "COMPLETED"
            ):
                # Only GitHub's own states, and a conclusion only once completed: an odd one,
                # or a failure "in progress", is not known, never pending (pre-review of
                # 07c3480).
                complete = False
                continue
            status = CHECK_STATUS.get(raw_status, "queued")  # waiting, pending: not done
            if status == "completed" and conclusion in ("SKIPPED", "NEUTRAL"):
                conclusion = "SUCCESS"  # GitHub counts both as satisfying a required check
            if status == "completed" and conclusion == "SUCCESS":
                # A success counts only while fresh: GitHub needs one within the past seven
                # days (5d06878). An old one, or one with no time, is no pass, and leaves the
                # list not known, so a fresh one of the same name can never mask it (Codex's
                # review of 2736aee).
                done = run.get("completedAt")
                if done is None or now is None:
                    complete = False
                    continue
                try:
                    stale_at = datetime.fromisoformat(_time(done)) + CHECK_FRESH
                except (FetchError, OverflowError):
                    # An odd time, or one too late to add a week to: this one result is
                    # unknown, the rest still counts (Codex's reviews of 0e2139f and 1e0f9b0).
                    complete = False
                    continue
                if not _fresh(stale_at, now):
                    complete = False
                    continue
                if key != name:
                    continue  # a pass under another case of the name: never counted
                expiry.append(stale_at)
            out.append(
                {
                    "name": key,
                    "head_sha": head,
                    "status": status,
                    "conclusion": conclusion.lower() if conclusion else None,
                }
            )
    for commit in heads:
        cautions, statuses_complete = _status_cautions(commit, head, required, now, expiry)
        out += cautions
        complete = complete and statuses_complete
    return out, complete


def _required_name(name: str, required: tuple[str, ...]) -> str | None:
    """The required check this name stands for, matched exactly or else ignoring case, or
    None."""
    if name in required:
        return name
    folded = name.casefold()
    return next((r for r in required if r.casefold() == folded), None)


def _provably_harmless_runs(suite: dict, required: tuple[str, ...]) -> bool:
    """Whether a suite's run list is readable whole and holds no unfinished or failing run
    with a required name (successes, and runs of other names, are harmless)."""
    runs = suite.get("checkRuns")
    if not isinstance(runs, dict):
        return False
    nodes, total = runs.get("nodes"), runs.get("totalCount")
    if not isinstance(nodes, list) or type(total) is not int or total != len(nodes):
        return False
    if not _distinct(nodes) or len(nodes) > MAX_RUNS:  # a repeat, or more than asked for
        return False
    for r in nodes:
        if not isinstance(r, dict) or not isinstance(r.get("name"), str) or not r["name"]:
            return False
        if _required_name(r["name"], required) is not None and not (
            r.get("status") == "COMPLETED"
            and r.get("conclusion") in ("SUCCESS", "SKIPPED", "NEUTRAL")
        ):
            return False
    return True


def _run_event(run: Any) -> bool | None:
    """Whether a workflow run's event reads as one (lowercase, as GitHub names them); None for
    no run."""
    if run is None:
        return None
    event = run.get("event") if isinstance(run, dict) else None
    return isinstance(event, str) and EVENT.fullmatch(event) is not None


EVENT = re.compile(r"[a-z_]+")


def _provably_no_required(suite: dict, required: tuple[str, ...]) -> bool:
    """Whether a suite's run list is readable whole and names no required check."""
    runs = suite.get("checkRuns")
    if not isinstance(runs, dict):
        return False
    nodes, total = runs.get("nodes"), runs.get("totalCount")
    if not isinstance(nodes, list) or type(total) is not int or total != len(nodes):
        return False
    if not _distinct(nodes) or len(nodes) > MAX_RUNS:  # a repeat, or more than asked for
        return False
    return all(
        isinstance(r, dict)
        and isinstance(r.get("name"), str)
        and r["name"] != ""
        and _required_name(r["name"], required) is None
        for r in nodes
    )


def _status_cautions(
    commit: dict,
    head: str,
    required: tuple[str, ...],
    now: datetime | None = None,
    expiry: list | None = None,
) -> tuple[list[dict], bool]:
    """(the head commit's statuses for required names, as cautions only, whether complete).
    When a status and a check run share a required name, GitHub needs both to pass (Codex's
    review of ab64500). A status that isn't a success counts against that name; a successful
    one adds nothing, because a status can't be tied to an app the way a check run can, but
    only while fresh, as for a check run: an old one, or one with no time, leaves the list not
    known, never passed (Codex's review of 099ef9b)."""
    if "status" not in commit:
        return [], False  # left out: not known, never "no statuses" (Codex's review of 2736aee)
    raw = commit.get("status")
    if raw is None:
        return [], True
    try:
        contexts = _list(_obj(raw).get("contexts"))
    except FetchError:
        return [], False
    out, complete = [], True
    names: set[str] = set()
    for context in contexts:
        if not isinstance(context, dict):
            complete = False
            continue
        name = context.get("context")
        if not isinstance(name, str) or not name:
            complete = False  # wrongly shaped: not known (audit of 28009de)
            continue
        # GitHub gives one row per context: a repeat may stand for an omitted one (pre-review
        # of 07c3480).
        if name.casefold() in names:
            complete = False
        names.add(name.casefold())
        # In any case: a status only ever counts against a name (Codex's review of 0f79663).
        key = _required_name(name, required)
        if key is None:
            continue
        name = key
        state = context.get("state")
        if not isinstance(state, str) or state not in STATUS_STATES:
            complete = False
            continue
        # Every state's time is checked, not only a success's: one left out, odd or in the
        # future makes the list not known (pre-review of 6b7da87); a failure is still read on.
        created: datetime | None
        try:
            created = datetime.fromisoformat(_time(context.get("createdAt")))
            if now is not None and created > now + FUTURE_SKEW:
                raise _bad()
        except FetchError:
            created, complete = None, False
        if state == "SUCCESS":
            try:
                stale_at = None if created is None else created + CHECK_FRESH
            except OverflowError:
                stale_at = None
            if stale_at is None or now is None or not _fresh(stale_at, now):
                complete = False
            elif expiry is not None:
                expiry.append(stale_at)  # the passes stand only while it is fresh
            continue
        pending = state in ("PENDING", "EXPECTED")
        out.append(
            {
                "name": name,
                "head_sha": head,
                "status": "in_progress" if pending else "completed",
                "conclusion": None if pending else "failure",
            }
        )
    return out, complete


def _issue(
    repo: str, pr: dict, now: datetime | None = None
) -> tuple[int, dict | None, dict | None]:
    """(how many issues the PR closes, the issue's model input or None, its screen fields).
    An issue in another repository gives no issue: its number would point at the wrong one
    here (Codex's review of f772122)."""
    refs = _obj(pr.get("closingIssuesReferences"))
    total = _int(refs.get("totalCount"))
    nodes = _list(refs.get("nodes"))
    if total != len(nodes) or total > MAX_ISSUES:
        return None, None, None  # a count that disagrees: not even how many is known
    if total != 1:
        return total, None, None  # none, or several: the model can't pick one, so no guess
    node = _obj(nodes[0])
    if _obj(node.get("repository")).get("nameWithOwner") != repo:
        return total, None, None
    number = _int(node.get("number"))
    state = node.get("state")
    if state not in ("OPEN", "CLOSED"):
        raise _bad()
    if number == 0 or number == pr.get("number"):
        return total, None, None  # no issue has number 0, or the pull request's own number
    screen = {"number": number, "title": _str(node.get("title"), MAX_TITLE) or "(untitled)"}
    try:
        events = _connection(node.get("timelineItems"), MAX_EVENTS)
    except _Incomplete:
        return total, None, screen
    timeline = []
    try:
        for event in events:
            e = _event(event, repo, now)
            # Only the agent:ready label's events, and closings and reopenings: the model reads
            # no others, and keeping them all, once per pull request, could fill the snapshot
            # (Codex's review of dc1eb14). A closing ends the authorisation as an unlabel does,
            # so leaving them out would show a closed-and-reopened issue as still authorised.
            # GitHub's label names ignore case: an event on the label in another case is a
            # surprise, never another label (pre-review of 6b7da87); so is its removal under
            # the name with spaces round it, which GitHub never keeps.
            label = e["label"]
            if label not in (None, READY_LABEL) and (
                label.casefold() == READY_LABEL.casefold()
                or (e["event"] == "unlabeled" and label.strip() == READY_LABEL)
            ):
                raise _Incomplete()
            if e["event"] in ("closed", "reopened") or e["label"] == READY_LABEL:
                timeline.append(e)
    except _Incomplete:
        return total, None, screen
    issue = {"number": number, "state": state.lower(), "timeline": timeline}
    return total, issue, screen


EVENT_KINDS = {
    "LabeledEvent": "labeled",
    "UnlabeledEvent": "unlabeled",
    "ClosedEvent": "closed",
    "ReopenedEvent": "reopened",
}


def _event(event: Any, repo: str, now: datetime | None = None) -> dict:
    """One label event, its label name exact (_exact), or a closing or reopening. A closing
    names the pull request that closed it (closer_pr) only when GitHub says it was one in this
    repository; anything else (a commit, a project, another repository, none) is null, which
    the model never takes as the merge's own closing."""
    e = _obj(event)
    kind = EVENT_KINDS.get(e.get("__typename"))
    if kind is None:
        raise _bad()
    # A deleted account is kept as "ghost": it can never authorise, but its removal of the
    # label still withdraws an authorisation (Codex's review of f772122: skipping it could
    # leave an earlier authorisation in force).
    actor = _login(e.get("actor")) or "ghost"
    at = _time(e.get("createdAt"))
    _placed(at, now)  # one dated in the future leaves the issue not known
    out = {"event": kind, "actor": actor, "at": at}
    if kind in ("labeled", "unlabeled"):
        out["label"] = _exact(_obj(e.get("label")).get("name"))
    else:
        out["label"] = None
    if kind == "closed":
        closer = e.get("closer")
        closer_pr = None
        if isinstance(closer, dict) and closer.get("__typename") == "PullRequest":
            same = _obj(closer.get("repository")).get("nameWithOwner") == repo
            closer_pr = _int(closer.get("number")) if same else None
        elif closer is not None and not isinstance(closer, dict):
            raise _bad()
        out["closer_pr"] = closer_pr
    return out


def _item(repo: str, cfg: FetcherConfig, node: Any, now: datetime | None = None) -> dict:
    """One pull request as a snapshot item. A part that wasn't asked for (a lite or retried
    read) or couldn't be read is "not known"."""
    pr = _obj(node)
    number = _int(pr.get("number"))
    head = _sha(pr.get("headRefOid"))
    if head == VANISHED:
        raise _bad()  # the sentinel for a vanished commit is never a head (pre-review of 6b7da87)
    # Each of these may be null, but GitHub always gives the key: one left out is never read as
    # null, "not merged" or "open" (pre-review of 6b7da87).
    if not {"closedAt", "mergedAt", "mergedBy"} <= set(pr):
        raise _bad()
    state = pr.get("state")
    if state not in ("OPEN", "CLOSED", "MERGED"):
        raise _bad()
    merged = pr.get("merged")
    draft = pr.get("isDraft")
    fork = pr.get("isCrossRepository")
    if not all(isinstance(v, bool) for v in (merged, draft, fork)):
        raise _bad()
    # A contradictory answer is never read as the calmer half (Fable's pre-review of 8152df0:
    # state MERGED with merged false read as closed without merging).
    if merged != (state == "MERGED") or merged != (pr.get("mergedAt") is not None):
        raise _bad()
    # An open pull request has no closing time, and a closed one has one: otherwise an "open"
    # one closed long ago fell out of the window silently (Fable's pre-review of a21bd27).
    if (state == "OPEN") != (pr.get("closedAt") is None):
        raise _bad()
    # A merged pull request closed when it merged, and neither can be in the future: one time
    # drives the window and the other the cut-off for reviews and authorisation (pre-review
    # of 07c3480). GitHub gives merged_by only for a merged one.
    if merged:
        # GitHub closes a pull request as it merges it, and on real merges the closing time is
        # often a second later (pre-review of 8c4bfec: 6 of 85 recent merges). Before the merge,
        # or later than a few seconds, is a contradiction.
        gap = datetime.fromisoformat(_time(pr.get("closedAt"))) - datetime.fromisoformat(
            _time(pr.get("mergedAt"))
        )
        if not timedelta(0) <= gap <= timedelta(seconds=5):
            raise _bad()
    if not merged and pr.get("mergedBy") is not None:
        raise _bad()
    try:
        if state != "OPEN":
            _placed(_time(pr.get("closedAt")), now)
    except _Incomplete:
        raise _bad() from None
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
        # Billy never publishes from a fork: a pull request from one is flagged, however its
        # issue link looks (Fable's pre-review of 8152df0).
        "from_fork": fork,
    }
    # Parts that can't be read whole are null ("not known"): the model never reads them as
    # clean, and still judges everything that is known.
    try:
        if "files" not in pr:
            raise _Incomplete()
        patterns = tuple(settings.clinical_paths)
        if _clinical(_all_paths(pr), patterns):
            pull["clinical_known"] = True  # survives any later cut (9dbb868)
        pull["files"], complete = _files(pr, patterns)
        if not complete:
            pull["files_complete"] = False
    except (_Incomplete, *_SHAPE):
        pull["files"] = None
        pull.pop("files_complete", None)
    merged_at = datetime.fromisoformat(pull["merged_at"]) if merged else None
    try:
        # The head the reviews are matched against must not be contradicted by GitHub's own
        # commit rows (pre-review of 6b7da87), for an open or a closed PR alike. A row that
        # can't be read says nothing, as in a lite read: only readable rows that name other
        # commits, and never the head, leave the reviews not known (pre-review of 8c4bfec).
        if _head_contradicted(pr, head):
            raise _Incomplete()
        pull["reviews"] = _reviews(pr, cfg.clinicians, merged_at, now)
    except (_Incomplete, *_SHAPE):
        # null: "not known", so the model still judges what is known (Codex's review of
        # 198a66e: leaving the key out made the whole PR unreadable and hid its warnings).
        pull["reviews"] = None
    # Checks only for an open pull request. Once it is merged or closed, GitHub no longer shows
    # the test merge commit it judged, so no reading of the checks can match its verdict; the
    # merge box enforced them at the time (owner's decision, 2026-11-25, after Codex's review
    # of a1e05e5).
    pull["checks"] = None
    expiry: list[datetime] = []
    if state == "OPEN" and "commits" in pr:
        try:
            required = tuple(settings.required_checks)
            pull["checks"], complete = _checks(pr, head, settings.checks_app, required, now, expiry)
            if not complete:
                pull["checks_complete"] = False  # a failure in it still fails; it never passes
        except (_Incomplete, *_SHAPE):
            pull["checks"] = None
    # When the first counted pass stops being fresh: after it no pass counts; failures do.
    fresh_until = None
    if pull["checks"] is not None and expiry:
        fresh_until = min(expiry).astimezone(UTC).isoformat()
    try:
        linked, issue, issue_screen = _issue(repo, pr, now)
    except _SHAPE:
        linked, issue, issue_screen = None, None, None  # not known: no claim from it
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
    try:
        title = _str(pr.get("title"), MAX_TITLE) or NO_TITLE  # nothing left once cleaned
    except _SHAPE:
        # Only shown, never judged: a title that can't be read must not make the whole pull
        # request unreadable and hide what is known about it (Codex's review of c3ee86b).
        title = NO_TITLE
    return {
        "id": f"{repo}#{number}",  # unique across owners (Codex's review of 0cf099c)
        "repo": repo,
        "number": number,
        "title": title,
        "url": f"https://github.com/{repo}/pull/{number}",
        "closed_at": None if pr.get("closedAt") is None else _time(pr.get("closedAt")),
        "linked_issues": linked,
        "issue": None
        if issue_screen is None
        else dict(issue_screen, url=f"https://github.com/{repo}/issues/{issue_screen['number']}"),
        "checks_fresh_until": fresh_until,
        "task": task,
    }


def _closed_page(
    conn: Any, since: datetime
) -> tuple[list[int], str | None, list[int], list[datetime], bool]:
    """(numbers closed in the window, the cursor of the next page if it may hold more, every
    row's number, for finding repeats, every row's update time, for checking the order across
    pages, and whether the page casts doubt on stopping early)."""
    conn = _obj(conn)
    nodes = _list(conn.get("nodes"))
    numbers, rows, updated = [], [], []
    impossible = False
    for node in nodes:
        node = _obj(node)
        number = _int(node.get("number"))
        rows.append(number)
        updated.append(datetime.fromisoformat(_time(node.get("updatedAt"))))
        # A closed pull request always has a closing time: one without is a bad answer, never
        # skipped quietly (Fable's pre-review of 8152df0).
        closed_at = datetime.fromisoformat(_time(node.get("closedAt")))
        # Closing updates a pull request: an update before its closing can't be, and the page's
        # update times then say nothing about the next (Codex's review of cc29d6e).
        impossible = impossible or updated[-1] < closed_at
        # Never more read in detail than a page holds: more than asked for is doubtful (below)
        # and cut to the page's size (pre-review of b8b1ca7).
        if closed_at >= since and len(rows) <= MAX_CLOSED:
            numbers.append(number)
    info = _obj(conn.get("pageInfo"))
    has_next = info.get("hasNextPage")
    if not isinstance(has_next, bool):
        raise _bad()
    # Newest-updated first: if the last one was still updated in the window, more may lie past
    # it (Codex's review of f37d0c7).
    last_in_window = bool(updated) and updated[-1] >= since
    # That order is checked, never trusted: a page out of order says nothing about the next, so
    # it is read too, or the list marked cut off (pre-review of 07c3480).
    disordered = any(a < b for a, b in zip(updated, updated[1:], strict=False))
    # A page that can't support stopping is doubtful, and remembered whatever later pages look
    # like (6b7da87): out of order or impossible, even when it is the last (Codex, 34ad21c);
    # short or empty though it says more follow (9cc8f43, 8c4bfec); or more rows than asked for.
    doubtful = (
        disordered
        or impossible
        or (has_next and len(nodes) != MAX_CLOSED)
        or len(nodes) > MAX_CLOSED
    )
    if has_next and (last_in_window or doubtful):
        cursor = info.get("endCursor")
        if not isinstance(cursor, str) or not 0 < len(cursor) <= 512:
            raise _bad()
        return numbers, cursor, rows, updated, doubtful
    return numbers, None, rows, updated, doubtful


def _listing(
    repo: str, data: Any, now: datetime, more_pages: Callable[[str], Any] | None = None
) -> tuple[list[int], bool]:
    """(the numbers to read in detail, whether more pull requests may exist than the list
    shows: open ones past the first page, or closed ones in the 14-day window past the last
    page read)."""
    repository = _obj(_obj(data).get("repository"))
    open_conn = _obj(repository.get("open"))
    open_nodes = _list(open_conn.get("nodes"))
    more_open = _int(open_conn.get("totalCount")) != len(open_nodes) or len(open_nodes) > MAX_OPEN
    since = now - timedelta(days=RECENT_DAYS)
    # More than asked for is flagged, and never all read in detail (pre-review of 8c4bfec).
    numbers = [_int(_obj(n).get("number")) for n in open_nodes[:MAX_OPEN]]
    rows = list(numbers)  # every row read, older closed ones included
    closed, cursor, page_rows, times, doubt = _closed_page(repository.get("closed"), since)
    numbers += closed
    rows += page_rows
    pages = 1
    # The order is checked across pages too: a page that starts later than the last one ended
    # breaks the cut-off the earlier pages relied on (Codex's review of b03ad71).
    disordered = False
    while cursor is not None and more_pages is not None and pages < CLOSED_PAGES:
        page = _obj(_obj(more_pages(cursor)).get("repository")).get("closed")
        closed, cursor, page_rows, page_times, page_doubt = _closed_page(page, since)
        # Promised more, an empty page is no end: the list changed (Codex's review of 7ac622f).
        doubt = doubt or page_doubt or not page_rows
        if times and page_times and page_times[0] > times[-1]:
            disordered = True
        times += page_times
        numbers += closed
        rows += page_rows
        pages += 1
    # Any repeat among every row read, within a page, across pages or between the lists, older
    # ones included, means the list changed while it was read, or GitHub's answer is odd: one
    # may be missing (Codex's reviews of 07c05d4 and 96cb8a9).
    repeated = len(set(rows)) != len(rows)
    cut_off = more_open or repeated or disordered or doubt or cursor is not None
    return list(dict.fromkeys(numbers)), cut_off


# Failures that may pass on asking again: a pull request is asked for in full once more before
# it is read lite (Fable's pre-review of 4945de9). Lite reads are then shown, with their
# "not known" parts raising alerts (audit of 28009de).
TRANSIENT = HEAVY - {"too-large", "too-heavy"}


def _details(
    github: GitHub,
    token: str,
    owner: str,
    name: str,
    numbers: list[int],
    deadline: float | None = None,
    clinicians: tuple[str, ...] = (),
) -> list:
    """[(number, node, lite)] for these pull requests, in order; node UNREADABLE when GitHub's
    answer didn't hold it whole. `lite` is False for a full read, else why it was cut short
    (the failure's code, or "retry")."""

    def fetch(batch: list[int], omit: frozenset, lite) -> list:
        try:
            query = detail_query(batch, omit, clinicians)
            data = github.graphql(
                token,
                query,
                {"owner": owner, "name": name},
                placeable=lambda path: _optional_place(path, len(batch)),
            )
            _on_time(deadline)
        except FetchError as error:
            # Errors on some fields, with the rest of the answer: what GitHub did supply is
            # still judged (Codex's review of c3ee86b). With no usable answer, the error
            # stands and the batch is split as before.
            _on_time(deadline)
            partial = _partial(error, batch, lite)
            if partial is None:
                raise
            # A retry leaves out what this read already left out, too (audit of 42a3721: a lite
            # read's retry asked for the large pieces again).
            return [
                (n, Retry(node.pieces | omit) if isinstance(node, Retry) else node, lt)
                for n, node, lt in partial
            ]
        repository = _obj(_obj(data).get("repository"))
        # Missing or null: never silently dropped (Codex's review of 48929aa). It is shown as
        # unreadable; one deleted since the list is gone from the next refresh's list.
        return [(n, repository.get(f"p{i}") or UNREADABLE, lite) for i, n in enumerate(batch)]

    # A sound bound (Codex's review of 05062fc): a batch of b pull requests is split only when
    # its own read fails, so at most 2b - 1 reads in all; a lone one is then read once more,
    # lite, and with its core only (3 more); and each pull request's Retry is resolved once,
    # where its answer came, with one retry and then its core (2 more). At most 7 each.
    budget = [7 * len(numbers) + 2]

    def fetch_raw(batch: list[int], omit: frozenset, lite) -> list:
        if budget[0] <= 0:
            raise FetchError("over-budget")  # never HEAVY: it always fails the refresh
        budget[0] -= 1
        return fetch(batch, omit, lite)

    def resolve(entries: list) -> list:
        """Each Retry asked for again once without its pieces in error, then, if that is still
        not usable or is too heavy, with its core only (Codex's reviews of 0e2139f, 099ef9b and
        0f79663). Still nothing usable: unreadable. A core read GitHub can't answer fails the
        refresh."""
        out = []
        for number, node, lite in entries:
            if isinstance(node, Retry):
                steps = [node.pieces, ALL_PIECES] if node.pieces != ALL_PIECES else [ALL_PIECES]
                node = UNREADABLE
                for omit in steps:
                    try:
                        ((_, got, _),) = fetch_raw([number], omit, "retry")
                    except FetchError as error:
                        if error.code in HEAVY and omit != ALL_PIECES:
                            continue
                        if not _its_own(error, 1):
                            raise
                        continue
                    if isinstance(got, dict):
                        node = got
                        # Lite only if files, reviews or checks were left out: a retry without
                        # just the title reads everything that matters (audit of 42a3721).
                        if omit & (LARGE | {"reviews"}):
                            lite = lite or "retry"
                        break
            out.append((number, node, lite))
        return out

    def read(batch: list[int], again: bool = True) -> list:
        # Only the batch's own read decides a split: a retry's failure never splits it again,
        # so nothing is read twice (Codex's review of 05062fc).
        try:
            entries = fetch_raw(batch, frozenset(), False)
        except FetchError as error:
            if error.code not in HEAVY and not _its_own(error, len(batch)):
                raise
            code = error.code
        else:
            return resolve(entries)
        if len(batch) > 1:
            half = len(batch) // 2
            return read(batch[:half]) + read(batch[half:])
        if again and code in TRANSIENT:
            return read(batch, again=False)  # once more in full before cutting it short
        for omit in (LARGE, ALL_PIECES):
            try:
                entries = fetch_raw(batch, omit, code)
            except FetchError as error:
                if error.code in HEAVY and omit != ALL_PIECES:
                    continue  # still too heavy lite: the core only (Codex's review of 099ef9b)
                if not _its_own(error, 1):
                    raise
                return [(batch[0], UNREADABLE, code)]
            return resolve(entries)
        raise AssertionError("unreachable")  # the core read returns or raises

    out = []
    for i in range(0, len(numbers), BATCH):
        out += read(numbers[i : i + BATCH])
    return out


UNREADABLE = object()  # a pull request whose own data GitHub couldn't give whole


def _model_reads(task: dict | None) -> bool:
    """Whether the task model accepts this task: only then is the pull request readable
    (Codex's review of 8152df0: a built task the model rejects is UNKNOWN all the same)."""
    if task is None:
        return False
    try:
        parse(dict(task, paused=False))  # paused comes from the stop marker (A5b)
    except (InvalidInput, TypeError, ValueError, KeyError, AttributeError, OverflowError):
        return False
    return True


NO_TITLE = "(this pull request's title couldn't be read)"


def _unreadable(repo: str, number: int) -> dict:
    """A pull request that couldn't be read: shown, with task null, which the model shows as
    UNKNOWN (an alert). Never left out: that would look calmer than GitHub."""
    return {
        "id": f"{repo}#{number}",  # unique across owners (Codex's review of 0cf099c)
        "repo": repo,
        "number": number,
        "title": "(this pull request couldn't be read)",
        "url": f"https://github.com/{repo}/pull/{number}",
        "closed_at": None,
        "linked_issues": None,  # not known
        "issue": None,
        "checks_fresh_until": None,
        "task": None,
    }


def repo_items(
    repo: str,
    cfg: FetcherConfig,
    github: GitHub,
    token: str,
    now: datetime,
    deadline: float | None = None,
):
    """(items, whether more pull requests may exist than were read)."""
    owner, name = repo.split("/", 1)
    listing = github.graphql(token, LIST_QUERY, {"owner": owner, "name": name})
    _on_time(deadline)

    def more_pages(cursor: str) -> Any:
        variables = {"owner": owner, "name": name, "after": cursor}
        page = github.graphql(token, CLOSED_QUERY, variables)
        _on_time(deadline)
        return page

    numbers, more = _listing(repo, listing, now, more_pages)
    since = now - timedelta(days=RECENT_DAYS)
    items = []
    details = _details(github, token, owner, name, numbers, deadline, tuple(cfg.clinicians))
    readable = False
    for number, node, _lite in details:
        try:
            if node is UNREADABLE:
                raise _bad()
            item = _item(repo, cfg, node, now)
            if item["number"] != number:
                raise _bad()
        except (FetchError, TypeError, ValueError, AttributeError, KeyError, OverflowError):
            # This pull request's own data is wrongly shaped. Any such error, not only the
            # fetcher's own (Codex's review of 48929aa: an unhashable review state raised
            # TypeError and failed the refresh for every repository).
            item = _unreadable(repo, number)
        readable = readable or _model_reads(item["task"])
        # A pull request closed between the list and its details still belongs here. One the
        # details place before the window contradicts the list: it is kept, never dropped (it
        # may be an unsafe merge), and the repository marked cut off (pre-review of 07c3480).
        if item["closed_at"] is not None and datetime.fromisoformat(item["closed_at"]) < since:
            more = True
        items.append(item)
    # No guard on reads cut short (lite): a lite read keeps reviews, and leaves files and checks
    # "not known", which raises an alert, so it is never greener than GitHub. Rejecting such a
    # refresh let two huge pull requests from anyone stall every repository (audit of 28009de).
    if len(details) > 1 and not readable:
        # Every pull request unreadable is no per-PR problem: fail, keeping the last good
        # snapshot, rather than replace it with nothing but unreadable entries (7faf35a).
        # Judged on the items as built, not on GitHub's answer: pull requests that were all
        # there but all failed their checks here passed the guard (Codex's review of c3ee86b).
        # Only with more than one: a lone pull request with bad data of its own is shown as
        # unreadable, never a reason to leave every repository stale (Fable's pre-review of
        # a21bd27).
        raise _bad()
    return items, more


def refresh(cfg: FetcherConfig, github: GitHub, now: datetime) -> dict:
    """One refresh: check the App is still read-only and limited to the configured
    repositories, read each one, and return the snapshot. The token is revoked whatever
    happens."""
    repos = sorted(cfg.repos)
    # A whole refresh has a time limit: a slow but answering GitHub must not hold the lock
    # (and every later request, "busy") for long (Fable's pre-review of 8152df0).
    deadline = time.monotonic() + REFRESH_DEADLINE
    # Every request to GitHub, the first ones included, starts only within the limit and gets
    # only the time left (Codex's review of c5adbba); the token's revocation alone always runs.
    github.deadline = deadline
    installation = github.installation(cfg.owner, repos)
    token = github.token(installation)
    try:
        github.repositories(token, repos)
        items, truncated = [], []
        for repo in repos:
            repo_list, more = repo_items(repo, cfg, github, token, now, deadline)
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
        _on_time(deadline)
        _fit(snapshot)
        _on_time(deadline)
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


DECISIVE = ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")


def _essential_reviews(reviews: list[dict], head: str, pull: dict) -> list[dict]:
    """The reviews the clinician gate reads (tasks._clinician_approved), for each clinician
    only those at their latest time and, for a merged pull request, at their latest time up to
    the merge: among their decisive reviews of the head (the approval), and among their decisive
    reviews of any commit (an outstanding changes request blocks; Fable's review of 0cf099c).
    Same verdict, far fewer entries."""
    merged_at = pull.get("merged_at")
    limit = datetime.fromisoformat(merged_at) if merged_at else None

    def latest(candidates: list[dict]) -> list[dict]:
        by_user: dict[str, list[dict]] = {}
        for review in candidates:
            by_user.setdefault(review["user"], []).append(review)
        kept = []
        for user_reviews in by_user.values():
            times = [datetime.fromisoformat(r["at"]) for r in user_reviews]
            wanted = {max(times)}
            if limit is not None:
                before = [t for t in times if t <= limit]
                if before:
                    wanted.add(max(before))
                # And the latest strictly before the merge: a review in the merge's own second
                # may be set aside, and then that one decides (audit of ea9b32a).
                strictly = [t for t in times if t < limit]
                if strictly:
                    wanted.add(max(strictly))
            kept += [r for r, t in zip(user_reviews, times, strict=True) if t in wanted]
        return kept

    decisive = [r for r in reviews if r["state"] in DECISIVE]
    chosen = latest([r for r in decisive if r["commit_id"] == head]) + latest(decisive)
    return [r for r in reviews if any(r is c for c in chosen)]


def _essential_checks(checks: list[dict], head: str) -> list[dict]:
    """One entry per required check name, carrying its worst result on the head commit
    (tasks._checks: any failure fails it, else anything unfinished leaves it pending, else it
    passed). Same verdict, far fewer entries."""
    worst: dict[str, dict] = {}

    def badness(check: dict) -> int:
        if check["status"] == "completed" and check["conclusion"] != "success":
            return 2
        return 1 if check["status"] != "completed" else 0

    for check in checks:
        if check["head_sha"] != head:
            continue
        name = check["name"]
        if name not in worst or badness(check) > badness(worst[name]):
            worst[name] = check
    return list(worst.values())


def _fit(snapshot: dict) -> None:
    """Keep the snapshot under MAX_SNAPSHOT as written. File lists are the one large part
    anyone can make (Codex's review of 72607b3: several repositories of long, escaped paths
    stopped every refresh), so the largest are cut down until it fits: to one known clinical
    path, so a known clinical change stays known (69ed8e3), or else to "not known" (null);
    either way the model treats the rest as possibly clinical. What remains is bounded
    and comes from trusted accounts: titles are capped, and labels and statuses need write or
    triage access. Then reviews and checks are cut to exactly what the verdict reads, and last,
    whole items are left out, their repository marked truncated. Only if nothing is left does
    the refresh fail ("too-large")."""

    def size() -> int:
        return len(encode(dict(snapshot, token_revoked=False)))

    def cut(candidates: list, saving, apply) -> bool:
        """Cut candidates in order until the estimated saving covers the excess, then
        measure once, and repeat: a handful of full measurements, not one per cut (Fable's
        pre-review of a21bd27: re-measuring after every cut took up to 38 s)."""
        excess = size() - MAX_SNAPSHOT
        while excess > 0 and candidates:
            saved = 0
            while candidates and saved < excess:
                candidate = candidates.pop(0)
                saved += saving(candidate)
                apply(candidate)
            excess = size() - MAX_SNAPSHOT
        return excess <= 0

    if size() <= MAX_SNAPSHOT:
        return
    tasks = [
        i["task"] for i in snapshot["items"] if i["task"] and i["task"]["pull_request"].get("files")
    ]
    tasks.sort(key=lambda t: len(encode({"f": t["pull_request"]["files"]})), reverse=True)

    def files_saving(task: dict) -> int:
        return len(encode({"f": task["pull_request"]["files"]}))

    if cut(
        tasks,
        files_saving,
        lambda t: _cut(t["pull_request"], tuple(t["clinical_paths"]), keep_one=True),
    ):
        return
    # Then every file list still there: null (Fable's pre-review of 8152df0: lists were kept
    # while whole items, a known unsafe merge among them, were cut).
    for item in snapshot["items"]:
        if item["task"] and item["task"]["pull_request"].get("files"):
            _cut(item["task"]["pull_request"], tuple(item["task"]["clinical_paths"]), False)
    if size() <= MAX_SNAPSHOT:
        return
    # Then reviews and checks are cut down to exactly what the verdict reads, never to "not
    # known" (Codex's review of d75f891: nulling a complete review list turned a confirmed
    # clinical merge without a clinician into "reviews not verified"; nulling failing checks
    # would do the same to CHECKS_FAILING). The model reaches the same verdict from the short
    # lists as from the full ones.
    for pull in [i["task"]["pull_request"] for i in snapshot["items"] if i["task"]]:
        if pull.get("reviews"):
            pull["reviews"] = _essential_reviews(pull["reviews"], pull["head_sha"], pull)
        if pull.get("checks"):
            pull["checks"] = _essential_checks(pull["checks"], pull["head_sha"])
    if size() <= MAX_SNAPSHOT:
        return
    # Last, whole items, each repository so cut listed in "truncated", as when GitHub's list is
    # cut off. A stale snapshot for every repository would be worse (Codex's review of
    # dc1eb14). The order is by how much an item matters: unreadable first, then calm ones
    # (oldest closed, then least recently updated open), then those needing attention, and
    # UNSAFE ones last, so a known unsafe merge is the last thing cut, after any number of
    # strangers' fork PRs (Fable's pre-reviews of 8152df0 and a21bd27).
    items = snapshot["items"]

    def rank(item: dict) -> int:
        if item["task"] is None:
            return 0
        status = derive(dict(item["task"], paused=False))
        if status.state is State.UNSAFE:
            return 3
        return 2 if status.needs_attention else 1

    closed = sorted((i for i in items if i["closed_at"] is not None), key=lambda i: i["closed_at"])
    opened = [i for i in items if i["closed_at"] is None][::-1]
    order = sorted(closed + opened, key=rank)  # stable: the age order holds within a rank

    def drop(item: dict) -> None:
        items.remove(item)
        if item["repo"] not in snapshot["truncated"]:
            snapshot["truncated"].append(item["repo"])

    if cut(order, lambda i: len(encode(i)), drop):
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


def open_regular(path: Path | str) -> int:
    """A read-only descriptor for a regular file, never through a symlink. Opened without
    blocking, so a FIFO or device in its place can't hang the read, and refused unless regular
    (Codex's review of b1fef32: the config was read before it was checked)."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{os.fspath(path)!r} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_json(
    folder: Path, name: str, limit: int = MAX_SNAPSHOT, strict: bool = False
) -> dict | None:
    """The file's JSON object, or None when it is missing or unreadable. With `strict`, only a
    missing file gives None: a failure to open it raises OSError (pre-review of 9537b08: an
    unreadable status file was taken for "no earlier refresh"), and a malformed, oversized or
    non-object file raises ValueError (Codex's review of 9aeff19)."""
    try:
        fd = open_regular(folder / name)
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
