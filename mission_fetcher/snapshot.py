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
the stop marker itself, and the state for a pull request with no linked issue. `runs` is empty:
phase A5 starts with GitHub data only (issue #15, 2026-11-24).
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from string import Template
from typing import Any

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
SHA = re.compile(r"[0-9a-f]{40}")
CONTROL = re.compile(r"[\x00-\x1f\x7f  ‪-‮⁦-⁩]")
REVIEW_STATES = {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"}
CHECK_STATUS = {"QUEUED": "queued", "IN_PROGRESS": "in_progress", "COMPLETED": "completed"}

QUERY = Template("""
query($$owner: String!, $$name: String!) {
  repository(owner: $$owner, name: $$name) {
    open: pullRequests(states: OPEN, first: $open,
                       orderBy: {field: UPDATED_AT, direction: DESC}) {
      totalCount
      nodes { ...pr }
    }
    closed: pullRequests(states: [CLOSED, MERGED], first: $closed,
                         orderBy: {field: UPDATED_AT, direction: DESC}) {
      nodes { ...pr }
    }
  }
}
fragment pr on PullRequest {
  number title state isDraft merged closedAt
  mergedBy { login }
  headRefName headRefOid
  files(first: $files) { totalCount nodes { path } }
  reviews(last: $reviews) {
    totalCount
    nodes { state submittedAt author { __typename login } commit { oid } }
  }
  commits(last: 1) {
    nodes { commit { oid checkSuites(first: $suites) {
      totalCount
      nodes { checkRuns(first: $runs) { totalCount nodes { name status conclusion } } }
    } } }
  }
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
}
""").substitute(
    open=MAX_OPEN,
    closed=MAX_CLOSED,
    files=MAX_FILES,
    reviews=MAX_REVIEWS,
    suites=MAX_SUITES,
    runs=MAX_RUNS,
    issues=MAX_ISSUES,
    events=MAX_EVENTS,
)


class _Incomplete(Exception):
    """This part of GitHub's answer can't be trusted whole: leave it out."""


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


def _files(pr: dict) -> list[str]:
    """The changed paths exactly as GitHub gives them: they are only matched against the
    clinical patterns, never shown, so cleaning them could only make two paths look alike and
    let a clinical one slip past its rule (Codex's review of f772122). A path that isn't a
    plain, bounded string leaves the list out, so the model shows UNKNOWN."""
    paths = []
    for node in _connection(pr.get("files"), MAX_FILES):
        path = _obj(node).get("path")
        if not isinstance(path, str) or not 0 < len(path) <= 4096 or "\x00" in path:
            raise _Incomplete()
        paths.append(path)
    return paths


def _reviews(pr: dict) -> list[dict]:
    out = []
    for node in _connection(pr.get("reviews"), MAX_REVIEWS):
        n = _obj(node)
        state = n.get("state")
        if state == "PENDING":
            continue  # a draft review nobody else can see
        if state not in REVIEW_STATES:
            raise _bad()
        author = n.get("author")
        commit = n.get("commit")
        if commit is None or n.get("submittedAt") is None:
            raise _Incomplete()  # a review whose commit is gone can't be placed: no guess
        out.append(
            {
                "user": _login(author) or "ghost",
                "user_type": "Bot"
                if isinstance(author, dict) and author.get("__typename") == "Bot"
                else "User",
                "state": state,
                "commit_id": _sha(_obj(commit).get("oid")),
                "at": _time(n.get("submittedAt")),
            }
        )
    return out


def _checks(pr: dict, head: str) -> list[dict]:
    commits = _list(_obj(pr.get("commits")).get("nodes"))
    if not commits:
        return []
    commit = _obj(_obj(commits[0]).get("commit"))
    if _sha(commit.get("oid")) != head:
        raise _Incomplete()
    out = []
    for suite in _connection(commit.get("checkSuites"), MAX_SUITES):
        for run in _connection(_obj(suite).get("checkRuns"), MAX_RUNS):
            r = _obj(run)
            status = CHECK_STATUS.get(r.get("status"), "queued")  # waiting, pending: not done
            conclusion = r.get("conclusion")
            if conclusion is not None and not isinstance(conclusion, str):
                raise _bad()
            out.append(
                {
                    "name": _str(r.get("name"), 100),
                    "head_sha": head,
                    "status": status,
                    "conclusion": conclusion.lower() if conclusion else None,
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
    for event in events:
        e = _obj(event)
        kind = {"LabeledEvent": "labeled", "UnlabeledEvent": "unlabeled"}.get(e.get("__typename"))
        if kind is None:
            raise _bad()
        # A deleted account is kept as "ghost": it can never authorise, but its removal of the
        # label still withdraws an authorisation (Codex's review of f772122: skipping it could
        # leave an earlier authorisation in force).
        actor = _login(e.get("actor")) or "ghost"
        timeline.append(
            {
                "event": kind,
                "label": _str(_obj(e.get("label")).get("name"), 100),
                "actor": actor,
                "at": _time(e.get("createdAt")),
            }
        )
    issue = {"number": number, "state": state.lower(), "timeline": timeline}
    return total, issue, screen


def _item(repo: str, cfg: FetcherConfig, node: Any) -> dict:
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
        "head_sha": head,
    }
    # Incomplete parts are left out: the model then shows UNKNOWN, never a guessed state.
    for key, read in (
        ("files", lambda: _files(pr)),
        ("reviews", lambda: _reviews(pr)),
        ("checks", lambda: _checks(pr, head)),
    ):
        try:
            pull[key] = read()
        except _Incomplete:
            pass
    linked, issue, issue_screen = _issue(repo, pr)
    task = {
        "repo": repo,
        "owner": cfg.owner,
        "clinicians": list(cfg.clinicians),
        "clinical_paths": list(settings.clinical_paths),
        "required_checks": list(settings.required_checks),
        "max_fix_rounds": 1,
        "branch": {"name": _str(pr.get("headRefName")), "head": head},
        "runs": [],
        "pull_request": pull,
    }
    if issue is not None:
        task["issue"] = issue
    short = repo.split("/", 1)[1]
    return {
        "id": f"{short}-{number}",
        "repo": repo,
        "number": number,
        "title": _str(pr.get("title"), MAX_TITLE),
        "url": f"https://github.com/{repo}/pull/{number}",
        "closed_at": None if pr.get("closedAt") is None else _time(pr.get("closedAt")),
        "linked_issues": linked,
        "issue": None
        if issue_screen is None
        else dict(issue_screen, url=f"https://github.com/{repo}/issues/{issue_screen['number']}"),
        "task": task,
    }


def repo_items(repo: str, cfg: FetcherConfig, data: dict, now: datetime) -> tuple[list, bool]:
    """(items, whether more open pull requests exist than one request returned)."""
    repository = _obj(_obj(data).get("repository"))
    open_conn = _obj(repository.get("open"))
    open_nodes = _list(open_conn.get("nodes"))
    more_open = _int(open_conn.get("totalCount")) > len(open_nodes)
    since = now - timedelta(days=RECENT_DAYS)
    items = [_item(repo, cfg, n) for n in open_nodes]
    for node in _list(_obj(repository.get("closed")).get("nodes")):
        closed_at = _obj(node).get("closedAt")
        if closed_at is not None and datetime.fromisoformat(_time(closed_at)) >= since:
            items.append(_item(repo, cfg, node))
    return items, more_open


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
            owner, name = repo.split("/", 1)
            data = github.graphql(token, QUERY, {"owner": owner, "name": name})
            repo_list, more = repo_items(repo, cfg, data, now)
            items += repo_list
            if more:
                truncated.append(repo)
    finally:
        github.revoke(token)
    snapshot = {
        "version": VERSION,
        "fetched_at": now.astimezone(UTC).isoformat(),
        "repos": repos,
        "truncated": truncated,
        "items": items,
    }
    if len(json.dumps(snapshot)) > MAX_SNAPSHOT:
        raise FetchError("too-large")
    return snapshot


# ---------------------------------------------------------------- files


def write_json(folder: Path, name: str, data: dict) -> None:
    """Write `name` in `folder` whole, then rename it into place: a reader never sees half a
    file. Never through a symlink (the folder is opened with O_NOFOLLOW and used by its file
    descriptor); private while being written, then readable by the folder's group (the web
    app's account) only."""
    text = json.dumps(data, indent=1, sort_keys=True).encode("utf-8")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    folder_fd = os.open(folder, flags)
    try:
        group = os.fstat(folder_fd).st_gid
        tmp = f".{name}.{os.getpid()}.tmp"
        create = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(tmp, create, 0o600, dir_fd=folder_fd)
        try:
            try:
                # The web app reads through the folder's group, which a new file inherits only
                # in a setgid folder (checked at start-up); refuse a file that didn't (Codex's
                # review of f772122), rather than write one the web app can't read.
                if os.fstat(fd).st_gid != group:
                    raise OSError("the new file didn't inherit the folder's group")
                os.write(fd, text)
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
        os.fsync(folder_fd)
    finally:
        os.close(folder_fd)


def read_json(folder: Path, name: str, limit: int = MAX_SNAPSHOT) -> dict | None:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(folder / name, flags)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        return None
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None
