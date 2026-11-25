"""The task-state model (phase A2): one task's state, derived from GitHub-shaped data.

Pure and deterministic: `derive(task)` reads one dict and returns one `TaskStatus`. It makes no
network calls, reads no files, keeps no state between calls and never looks at the clock, so
the same input always gives the same answer. Every input is untrusted: text in issues, comments
and labels never authorises anything, and anything missing, malformed or contradictory gives
`State.UNKNOWN` (needs attention), never a guessed approval.

States follow the design's task state machine (mission-control.md §6 in
DrZaff/ai-medicine-collective), plus two safety states this model adds: UNSAFE (an invariant is
broken, for example a merged commit nobody reviewed) and UNKNOWN (the input can't be trusted).

Input contract (all keys are checked; unknown keys are ignored). Every field shown is required,
with no defaults, unless marked optional or limited to some steps: a missing one makes the
input UNKNOWN, never a silently weaker gate. required_checks must name at least one check;
clinical_paths may be an explicit empty list.

    {
      "repo": "owner/name",                  # the repository this task belongs to
      "owner": "login",                      # the only account whose actions authorise or merge
      "clinicians": ["login"],               # accounts whose GitHub approval counts as clinical
      "clinical_paths": ["evidence/*", ...], # fnmatch patterns; a match makes the change clinical
      "required_checks": ["lint", "test"],   # check names that must pass on the head commit
      "max_fix_rounds": 1,                   # blocking reviews allowed before the owner decides
      "paused": false,                       # the stop switch
      "issue": {"number": 7, "state": "open" | "closed", "timeline": [event, ...]},
      "branch": {"name": "claude/x", "head": "<40 hex>" | null} | null,  # the source branch
      "runs": [run, ...] | null,             # Billy's run records (build, review, publish, ...);
                                             # null: not read (A5a, GitHub data only)
      "pull_request": pull_request | null,
    }

    event         {"event": "labeled" | "unlabeled" | "authorized" | <other>, "label": str,
                   "actor": "login", "at": "ISO 8601 with a time zone"}
                   Only "labeled agent:ready" or "authorized" (an approved-action record, such as
                   the owner's direct instruction) by the owner authorise work. Anything else,
                   including the label's mere presence and every comment body, is ignored.
                   A labeled or unlabeled event must name its label.
    run           {"step": "build" | "review" | "publish" | "question" | "failure",
                   "repo": "owner/name", "branch": str, "sha": "<40 hex>", "at": ISO 8601,
                   (build and review records must name the task's source branch; records for
                    another repository or branch, or from before the owner's authorisation
                    began, are ignored and flagged)
                   "status": "started" | "finished",          (build and review)
                   "verdict": "no_blocking_findings" | "changes_needed",   (finished review)
                   "findings": [{"severity": "blocking" | "should_fix" | "note"}],  (finished
                                                               review; [] when there are none)
                   "pr": int,                                  (publish)
                   "files": [path]}                            (optional, any step)
    pull_request  {"number": int, "state": "open" | "closed", "draft": bool, "merged": bool,
                   "merged_by": "login" | null, "merged_at": ISO 8601 (when merged),
                   "head_sha": "<40 hex>", "files": [path],
                   "reviews": [{"user": "login", "user_type": "User" | "Bot",
                                "state": "APPROVED" | "CHANGES_REQUESTED" | "COMMENTED" |
                                         "DISMISSED", "commit_id": "<40 hex>", "at": ISO 8601}],
                   "checks": [{"name": str, "head_sha": "<40 hex>",
                               "status": "queued" | "in_progress" | "completed",
                               "conclusion": "success" | "failure" | ... | null}] | null}
                   checks null means "not known" (A5a: the fetcher can't match GitHub's
                   verdict once a PR is merged or closed). It is never read as passed: an
                   open PR's checks then count as not passed, and a merged PR is judged on
                   everything else, with CHECKS_UNVERIFIED instead of a checks verdict.
                   files and reviews may be null in the same way (A5a: GitHub's answer was
                   incomplete, such as a renamed file). Unknown files may be clinical, so an
                   open PR waits for a clinician (FILES_UNVERIFIED); unknown reviews give no
                   clinical approval (REVIEWS_UNVERIFIED). A merged PR is still judged on
                   everything that is known, and nothing unknown is claimed either way.
                   "files_complete": false (optional) marks a list known to be partial (a
                   rename or a cut-off list): its known clinical paths still count, and the
                   rest may be clinical (FILES_UNVERIFIED). merged_by may be null for a merged
                   PR whose merger can't be identified: that is unsafe (MERGER_UNKNOWN), since
                   nothing shows the owner merged it. Only authorisation
                   given by then counts for the merge (a label added afterwards proves
                   nothing, and removing it afterwards withdraws nothing).
    The task's "issue" may be null: no readable, authorised issue is linked (none, several,
    one in another repository, or one whose events couldn't be read; issue #15, decision
    A5-2). An open PR then shows as NOT_LINKED, calmly, rather than UNSAFE; a merged one is
    still judged on everything else, with ISSUE_NOT_LINKED instead of a claim that the work
    was never authorised.

Example, as a phase A3 screen would use it:

    status = derive(task)
    status.state            # State.AWAITING_OWNER
    status.needs_attention  # True: something waits for the owner
    status.flags            # frozenset({Flag.CHECKS_PASSED}), for badges
    status.reasons          # ("Review passed for 1a2b3c4d5e6f; required checks passed ...",)
    status.head_sha, status.reviewed_sha, status.pr   # for links and the exact-SHA display
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Any

READY_LABEL = "agent:ready"
# Matched with fullmatch: "$" would also accept a trailing newline.
SHA = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
LOGIN = re.compile(r"[A-Za-z0-9-]+(\[bot\])?")


class State(StrEnum):
    PROPOSED = "proposed"  # an issue nobody has authorised (yet)
    READY = "ready"  # the owner authorised it; no work yet
    BUILDING = "building"  # work started, or new commits nobody has reported
    BUILT = "built"  # the builder reported the head commit; review pending
    REVIEWING = "reviewing"  # a review of the head commit is under way
    CHANGES_NEEDED = "changes_needed"  # the review of the head found blocking problems
    REVIEWED = "reviewed"  # the head passed review; no pull request yet
    PUBLISHED = "published"  # a PR whose head is the reviewed commit; checks pending or failing
    CLINICAL_REVIEW = "clinical_review"  # clinical files: waiting for a clinician's approval
    AWAITING_OWNER = (
        "awaiting_owner"  # ready for the owner's decision (merge, or fix rounds used up)
    )
    MERGED = "merged"  # merged by the owner, after a passing review of that exact commit
    BLOCKED = "blocked"  # the agent asked a question
    FAILED = "failed"  # the work failed, with a reason
    PAUSED = "paused"  # the stop switch is on
    CLOSED = "closed"  # closed without merging
    NOT_LINKED = "not_linked"  # a PR with no readable, authorised issue linked (A5-2)
    UNSAFE = "unsafe"  # an invariant is broken; see the flags
    UNKNOWN = "unknown"  # the input can't be trusted; see the reasons


class Flag(StrEnum):
    INVALID_INPUT = "invalid_input"
    CONFLICTING_RECORDS = "conflicting_records"
    LABEL_WITHOUT_OWNER = "label_without_owner"  # agent:ready applied by someone else
    UNAUTHORIZED_WORK = "unauthorized_work"  # runs or a PR with no owner authorisation
    WRONG_REPO_RECORD = "wrong_repo_record"  # a run record for another repository (ignored)
    WRONG_BRANCH_RECORD = "wrong_branch_record"  # a run record for another branch (ignored)
    STALE_REVIEW = "stale_review"  # a review exists, but for an older commit
    REVIEW_MISSING = "review_missing"
    PR_BEFORE_REVIEW = "pr_before_review"  # a PR is open while its head has no passing review
    HEAD_MISMATCH = "head_mismatch"  # the PR head isn't the commit that was reviewed and published
    FIX_ROUNDS_EXHAUSTED = "fix_rounds_exhausted"
    # a record from before the owner's current authorisation began (ignored)
    RECORD_BEFORE_AUTHORIZATION = "record_before_authorization"
    CHECKS_PASSED = "checks_passed"
    CHECKS_PENDING = "checks_pending"
    CHECKS_MISSING = "checks_missing"  # a required check has no result for the head commit
    CHECKS_STALE = "checks_stale"  # results exist, but for another commit
    CHECKS_FAILING = "checks_failing"
    CLINICAL = "clinical"
    CLINICAL_APPROVAL_MISSING = "clinical_approval_missing"
    # A clinician's approval of the head was checked and found (set only where it is checked:
    # Codex's review of 877fd21, the view had to guess from the state).
    CLINICIAN_APPROVED = "clinician_approved"
    # A merged PR with no issue: its authorisation can't be verified (A5a, GitHub data only).
    AUTHORIZATION_UNVERIFIED = "authorization_unverified"
    UNAUTHORIZED_MERGE = "unauthorized_merge"  # merged by someone other than the owner
    MERGED_UNREVIEWED = "merged_unreviewed"  # the merged commit never passed review
    MERGED_WITHOUT_CLINICIAN = "merged_without_clinician"
    MERGED_WITH_CHECKS_NOT_PASSED = "merged_with_checks_not_passed"
    # The checks' results aren't known here (pull_request.checks is null): no verdict either way.
    CHECKS_UNVERIFIED = "checks_unverified"
    RUNS_UNVERIFIED = "runs_unverified"  # Billy's run records not read: no review claim
    # The changed files aren't known here (pull_request.files is null): they may be clinical.
    FILES_UNVERIFIED = "files_unverified"
    # The PR's reviews aren't known here (pull_request.reviews is null): no clinical approval.
    REVIEWS_UNVERIFIED = "reviews_unverified"
    # An open PR whose linked issue is closed: it isn't finished, whatever the issue says.
    ISSUE_CLOSED_PR_OPEN = "issue_closed_pr_open"
    # No readable, authorised issue is linked to the PR (issue is null).
    ISSUE_NOT_LINKED = "issue_not_linked"
    # A merged PR whose merger can't be identified: nothing shows the owner merged it.
    MERGER_UNKNOWN = "merger_unknown"


ATTENTION_STATES = frozenset(
    {
        State.CHANGES_NEEDED,
        State.CLINICAL_REVIEW,
        State.AWAITING_OWNER,
        State.BLOCKED,
        State.FAILED,
        State.UNSAFE,
        State.UNKNOWN,
    }
)
ATTENTION_FLAGS = frozenset(
    {
        Flag.LABEL_WITHOUT_OWNER,
        Flag.WRONG_REPO_RECORD,
        Flag.WRONG_BRANCH_RECORD,
        Flag.RECORD_BEFORE_AUTHORIZATION,
        Flag.PR_BEFORE_REVIEW,
        Flag.CHECKS_FAILING,
        Flag.MERGED_WITH_CHECKS_NOT_PASSED,
        Flag.ISSUE_NOT_LINKED,
        Flag.ISSUE_CLOSED_PR_OPEN,
        # Unknown files or reviews can hide a clinical change merged without a clinician, so
        # they always need a look (pre-review of 9537b08).
        Flag.FILES_UNVERIFIED,
        Flag.REVIEWS_UNVERIFIED,
    }
)


# Flags that put a task under "Waiting for you" (not an alert), whatever its state: a known
# missing clinician approval waits on a clinician, even when Billy's records aren't read and
# the state is BUILT (Codex's review of dc1eb14).
WAITING_FLAGS = frozenset({Flag.CLINICAL_APPROVAL_MISSING})


@dataclass(frozen=True)
class TaskStatus:
    state: State
    flags: frozenset[Flag] = frozenset()
    reasons: tuple[str, ...] = ()
    head_sha: str | None = None  # the commit the task is at now
    reviewed_sha: str | None = None  # the commit whose review applies, if any
    pr: int | None = None

    @property
    def needs_attention(self) -> bool:
        return self.state in ATTENTION_STATES or bool(
            self.flags & (ATTENTION_FLAGS | WAITING_FLAGS)
        )


class InvalidInput(ValueError):
    pass


# ---------------------------------------------------------------- validation


def _req(cond: bool, message: str) -> None:
    if not cond:
        raise InvalidInput(message)


def _text(value: Any, name: str) -> str:
    _req(isinstance(value, str) and value != "", f"{name} must be a non-empty string")
    return value


def _sha(value: Any, name: str) -> str:
    _req(isinstance(value, str) and bool(SHA.fullmatch(value)), f"{name} must be a full 40-hex SHA")
    return value


def _login(value: Any, name: str) -> str:
    _req(isinstance(value, str) and bool(LOGIN.fullmatch(value)), f"{name} must be a GitHub login")
    return value


def _time(value: Any, name: str) -> datetime:
    _req(isinstance(value, str), f"{name} must be an ISO 8601 time")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise InvalidInput(f"{name} must be an ISO 8601 time") from None
    _req(parsed.tzinfo is not None, f"{name} must include a time zone")
    return parsed


def _choice(value: Any, allowed, name: str) -> str:
    _req(
        isinstance(value, str) and value in allowed,
        f"{name} must be one of {', '.join(sorted(allowed))}",
    )
    return value


def _list(value: Any, name: str) -> list:
    _req(isinstance(value, list), f"{name} must be a list")
    return value


def _map(value: Any, name: str) -> Mapping:
    _req(isinstance(value, Mapping), f"{name} must be an object")
    return value


def _need(m: dict, key: str, name: str) -> Any:
    """A field that must be present. No default: a missing field must never weaken a gate."""
    _req(key in m, f"{name} is required")
    return m[key]


def _strings(value: Any, name: str) -> tuple[str, ...]:
    return tuple(_text(v, f"{name}[]") for v in _list(value, name))


@dataclass(frozen=True)
class _Event:
    kind: str
    label: str | None
    actor: str
    at: datetime


@dataclass(frozen=True)
class _Run:
    step: str
    repo: str
    branch: str | None
    sha: str | None
    at: datetime
    status: str
    verdict: str | None
    blocking: bool
    pr: int | None
    files: tuple[str, ...]


@dataclass(frozen=True)
class _Review:
    user: str
    is_bot: bool
    state: str
    commit: str
    at: datetime


@dataclass(frozen=True)
class _Check:
    name: str
    sha: str
    status: str
    conclusion: str | None


@dataclass(frozen=True)
class _PR:
    number: int
    open: bool
    draft: bool
    merged: bool
    merged_by: str | None
    merged_at: datetime | None  # None only when not merged
    head: str
    files: tuple[str, ...] | None  # None: not known
    files_complete: bool  # False: the list is known to be partial
    reviews: tuple[_Review, ...] | None  # None: not known
    checks: tuple[_Check, ...] | None  # None: not known


@dataclass(frozen=True)
class _Task:
    repo: str
    owner: str
    clinicians: frozenset[str]
    clinical_paths: tuple[str, ...]
    required_checks: tuple[str, ...]
    max_fix_rounds: int
    paused: bool
    issue_known: bool  # False: issue was null (no readable, authorised issue linked)
    issue_open: bool
    timeline: tuple[_Event, ...]
    branch: str | None
    branch_head: str | None
    runs: tuple[_Run, ...] | None  # None: not read
    pr: _PR | None


SEVERITIES = frozenset({"blocking", "should_fix", "note"})
RUN_STEPS = frozenset({"build", "review", "publish", "question", "failure"})
REVIEW_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"})


def _parse_run(raw: Any, i: int) -> _Run:
    r = _map(raw, f"runs[{i}]")
    step = _choice(r.get("step"), RUN_STEPS, f"runs[{i}].step")
    repo = _text(r.get("repo"), f"runs[{i}].repo")
    _req(bool(REPO.fullmatch(repo)), f"runs[{i}].repo must be owner/name")
    status = _choice(
        _need(r, "status", f"runs[{i}].status") if step in ("build", "review") else "finished",
        ("started", "finished"),
        f"runs[{i}].status",
    )
    verdict = r.get("verdict")
    if step == "review" and status == "finished":
        verdict = _choice(verdict, ("no_blocking_findings", "changes_needed"), f"runs[{i}].verdict")
    if step == "review" and status == "finished":
        findings = _list(_need(r, "findings", f"runs[{i}].findings"), f"runs[{i}].findings")
    else:
        findings = _list(r.get("findings", []), f"runs[{i}].findings")
    # Every finding must carry a known severity: a missing or unknown one is refused rather
    # than read as harmless, so malformed review data can never produce a passing review.
    severities = [
        _choice(
            _map(f, f"runs[{i}].findings[{j}]").get("severity"),
            SEVERITIES,
            f"runs[{i}].findings[{j}].severity",
        )
        for j, f in enumerate(findings)
    ]
    blocking = "blocking" in severities
    sha = r.get("sha")
    if step in ("build", "review", "publish") and not (step == "build" and status == "started"):
        sha = _sha(sha, f"runs[{i}].sha")
    elif sha is not None:
        sha = _sha(sha, f"runs[{i}].sha")
    pr = r.get("pr")
    if step == "publish":
        _req(isinstance(pr, int) and not isinstance(pr, bool), f"runs[{i}].pr must be a number")
    branch = r.get("branch")
    if step in ("build", "review") or branch is not None:
        # A build or review is bound to its source branch, so it must name one.
        branch = _text(branch, f"runs[{i}].branch")
    return _Run(
        step=step,
        repo=repo,
        branch=branch,
        sha=sha,
        at=_time(r.get("at"), f"runs[{i}].at"),
        status=status,
        verdict=verdict,
        blocking=blocking,
        pr=pr,
        files=_strings(r.get("files", []), f"runs[{i}].files"),
    )


def _complete(p: Mapping) -> bool:
    value = p.get("files_complete", True)
    _req(isinstance(value, bool), "pull_request.files_complete must be true or false")
    return value


def _parse_pr(raw: Any) -> _PR:
    p = _map(raw, "pull_request")
    number = p.get("number")
    _req(isinstance(number, int) and not isinstance(number, bool), "pull_request.number")
    state = _choice(p.get("state"), ("open", "closed"), "pull_request.state")
    draft = _need(p, "draft", "pull_request.draft")
    _req(isinstance(draft, bool), "pull_request.draft must be true or false")
    merged = _need(p, "merged", "pull_request.merged")
    _req(isinstance(merged, bool), "pull_request.merged must be true or false")
    _req(not (merged and state == "open"), "pull_request can't be open and merged")
    merged_by = _need(p, "merged_by", "pull_request.merged_by")
    if merged:
        merged_by = None if merged_by is None else _login(merged_by, "pull_request.merged_by")
    reviews = []
    raw_reviews = _need(p, "reviews", "pull_request.reviews")
    for i, raw_review in enumerate(
        [] if raw_reviews is None else _list(raw_reviews, "pull_request.reviews")
    ):
        rv = _map(raw_review, f"pull_request.reviews[{i}]")
        review_state = _choice(rv.get("state"), REVIEW_STATES, f"pull_request.reviews[{i}].state")
        user_type = _choice(
            _need(rv, "user_type", f"pull_request.reviews[{i}].user_type"),
            ("User", "Bot"),
            f"pull_request.reviews[{i}].user_type",
        )
        user = _login(rv.get("user"), f"pull_request.reviews[{i}].user")
        reviews.append(
            _Review(
                user=user,
                is_bot=user_type == "Bot" or user.endswith("[bot]"),
                state=review_state,
                commit=_sha(rv.get("commit_id"), f"pull_request.reviews[{i}].commit_id"),
                at=_time(rv.get("at"), f"pull_request.reviews[{i}].at"),
            )
        )
    checks = []
    raw_checks = _need(p, "checks", "pull_request.checks")
    for i, raw_check in enumerate(
        [] if raw_checks is None else _list(raw_checks, "pull_request.checks")
    ):
        c = _map(raw_check, f"pull_request.checks[{i}]")
        status = _choice(
            c.get("status"),
            ("queued", "in_progress", "completed"),
            f"pull_request.checks[{i}].status",
        )
        conclusion = _need(c, "conclusion", f"pull_request.checks[{i}].conclusion")
        _req(
            conclusion is None or isinstance(conclusion, str),
            f"pull_request.checks[{i}].conclusion",
        )
        checks.append(
            _Check(
                name=_text(c.get("name"), f"pull_request.checks[{i}].name"),
                sha=_sha(c.get("head_sha"), f"pull_request.checks[{i}].head_sha"),
                status=status,
                conclusion=conclusion,
            )
        )
    return _PR(
        number=number,
        open=state == "open",
        draft=draft,
        merged=merged,
        merged_by=merged_by,
        merged_at=_time(_need(p, "merged_at", "pull_request.merged_at"), "pull_request.merged_at")
        if merged
        else None,
        head=_sha(p.get("head_sha"), "pull_request.head_sha"),
        files=None
        if (raw_files := _need(p, "files", "pull_request.files")) is None
        else _strings(raw_files, "pull_request.files"),
        reviews=None if raw_reviews is None else tuple(reviews),
        files_complete=_complete(p),
        checks=None if raw_checks is None else tuple(checks),
    )


def parse(raw: Any) -> _Task:
    """Validate one task's input; raises InvalidInput with the first problem found."""
    t = _map(raw, "task")
    repo = _text(t.get("repo"), "repo")
    _req(bool(REPO.fullmatch(repo)), "repo must be owner/name")
    raw_issue = _need(t, "issue", "issue")
    issue = {"state": "open", "timeline": []} if raw_issue is None else _map(raw_issue, "issue")
    if raw_issue is not None:
        number = issue.get("number")
        _req(
            isinstance(number, int) and not isinstance(number, bool),
            "issue.number must be a number",
        )
        _choice(issue.get("state"), ("open", "closed"), "issue.state")
    timeline = []
    for i, raw_event in enumerate(
        _list(_need(issue, "timeline", "issue.timeline"), "issue.timeline")
    ):
        e = _map(raw_event, f"issue.timeline[{i}]")
        kind = _text(e.get("event"), f"issue.timeline[{i}].event")
        label = e.get("label")
        if kind in ("labeled", "unlabeled"):
            # A label event must say which label: a removal with no label must never be read
            # as "some other label" and so hide a withdrawn authorisation.
            label = _text(
                _need(e, "label", f"issue.timeline[{i}].label"), f"issue.timeline[{i}].label"
            )
        timeline.append(
            _Event(
                kind=kind,
                label=label if isinstance(label, str) else None,
                actor=_login(e.get("actor"), f"issue.timeline[{i}].actor"),
                at=_time(e.get("at"), f"issue.timeline[{i}].at"),
            )
        )
    # "branch", "branch.head" and "pull_request" may be null (none yet), but must be present:
    # an absent key is a gap in the data, not evidence that nothing exists.
    branch = _need(t, "branch", "branch")
    branch_name = branch_head = None
    if branch is not None:
        b = _map(branch, "branch")
        branch_name = _text(b.get("name"), "branch.name")
        head_raw = _need(b, "head", "branch.head")
        if head_raw is not None:
            branch_head = _sha(head_raw, "branch.head")
    # Safety settings have no defaults: a missing one must never quietly switch a gate off.
    for key in ("clinicians", "clinical_paths", "required_checks", "max_fix_rounds", "paused"):
        _req(key in t, f"{key} is required")
    required_checks = _strings(t["required_checks"], "required_checks")
    _req(bool(required_checks), "required_checks must name at least one check")
    max_rounds = t["max_fix_rounds"]
    _req(
        isinstance(max_rounds, int) and not isinstance(max_rounds, bool) and max_rounds >= 0,
        "max_fix_rounds must be a whole number",
    )
    paused = t["paused"]
    _req(isinstance(paused, bool), "paused must be true or false")
    pr_raw = _need(t, "pull_request", "pull_request")
    return _Task(
        repo=repo,
        owner=_login(t.get("owner"), "owner"),
        clinicians=frozenset(
            _login(c, "clinicians[]") for c in _list(t["clinicians"], "clinicians")
        ),
        clinical_paths=_strings(t["clinical_paths"], "clinical_paths"),
        required_checks=required_checks,
        max_fix_rounds=max_rounds,
        paused=paused,
        issue_known=raw_issue is not None,
        issue_open=issue["state"] == "open",
        timeline=tuple(timeline),
        branch=branch_name,
        branch_head=branch_head,
        runs=_parse_runs(_need(t, "runs", "runs")),
        pr=None if pr_raw is None else _parse_pr(pr_raw),
    )


def _parse_runs(value: Any) -> tuple[_Run, ...] | None:
    """null: Billy's run records were not read (A5a: GitHub data only). That is never read as
    "no review happened" (Codex's review of 9537b08: an empty list made every merged PR look
    unreviewed)."""
    if value is None:
        return None
    return tuple(_parse_run(r, i) for i, r in enumerate(_list(value, "runs")))


# ---------------------------------------------------------------- derivation


def _authorization(
    task: _Task, flags: set[Flag], until: datetime | None = None
) -> tuple[datetime | None, datetime | None]:
    """(since, last): when the owner's current authorisation began, and the owner's latest
    authorising action, or (None, None) if the work is not authorised now.

    Only the owner's own "labeled agent:ready" or "authorized" event counts. Authorising again
    while already authorised keeps the start (so earlier work in the same authorisation still
    counts) and moves `last` (which answers an agent's question). Removing the label, by anyone,
    withdraws it; an add and a removal at the same instant count as withdrawn. With `until`
    (a merge), later events are ignored: they can't authorise or withdraw what is done."""
    since: datetime | None = None
    last: datetime | None = None
    # At the same instant a removal sorts last, so it wins over an add or an authorisation.
    for e in sorted(task.timeline, key=lambda e: (e.at, e.kind == "unlabeled")):
        if until is not None and e.at > until:
            break
        ready = e.label == READY_LABEL
        if e.kind == "labeled" and ready and e.actor != task.owner:
            flags.add(Flag.LABEL_WITHOUT_OWNER)
        elif (e.kind == "labeled" and ready) or (e.kind == "authorized" and e.actor == task.owner):
            since = e.at if since is None else since
            last = e.at
        elif e.kind == "unlabeled" and ready:
            since = last = None
    return since, last


def _checks(task: _Task, head: str, flags: set[Flag]) -> bool:
    """True only if every required check completed successfully on exactly this commit."""
    pr = task.pr
    if pr.checks is None:
        # Not known: never passed (A5a). The caller decides what that means.
        flags.add(Flag.CHECKS_UNVERIFIED)
        return False
    ok = True
    for name in task.required_checks:
        here = [c for c in pr.checks if c.name == name and c.sha == head]
        if not here:
            ok = False
            stale = any(c.name == name for c in pr.checks)
            flags.add(Flag.CHECKS_STALE if stale else Flag.CHECKS_MISSING)
        elif any(c.status == "completed" and c.conclusion != "success" for c in here):
            ok = False
            flags.add(Flag.CHECKS_FAILING)
        elif not all(c.status == "completed" for c in here):
            ok = False
            flags.add(Flag.CHECKS_PENDING)
    if ok:
        flags.add(Flag.CHECKS_PASSED)
    return ok


def _clinician_approved(task: _Task, head: str, until: datetime | None = None) -> bool:
    """A clinician's own GitHub approval of exactly this commit, not later withdrawn, with no
    clinician asking for changes to it. Bots never count, and neither does any review report
    outside GitHub's reviews (such as Codex's). Each clinician's latest decisive review counts;
    two different decisions at the same instant are ambiguous and block, whatever the input
    order. With `until` (a merge), later reviews never count: an approval after the merge
    can't make it compliant (Codex's review of 69ed8e3)."""
    if task.pr.reviews is None:
        return False  # not known: no approval (A5a)
    by_user: dict[str, list[_Review]] = {}
    for rv in task.pr.reviews:
        if rv.is_bot or rv.user not in task.clinicians or rv.commit != head:
            continue
        if until is not None and rv.at > until:
            continue
        if rv.state in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            by_user.setdefault(rv.user, []).append(rv)
    decisions = set()
    for reviews in by_user.values():
        at = max(rv.at for rv in reviews)
        states = {rv.state for rv in reviews if rv.at == at}
        decisions.add(states.pop() if len(states) == 1 else "AMBIGUOUS")
    return "APPROVED" in decisions and not decisions & {"CHANGES_REQUESTED", "AMBIGUOUS"}


def derive(raw: Any) -> TaskStatus:
    """The state of one task. Never raises on bad input: that gives State.UNKNOWN."""
    try:
        task = parse(raw)
    except InvalidInput as error:
        return TaskStatus(State.UNKNOWN, frozenset({Flag.INVALID_INPUT}), (str(error),))
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError) as error:
        # A shape parse() doesn't anticipate. Still never raise: the input can't be trusted.
        return TaskStatus(
            State.UNKNOWN,
            frozenset({Flag.INVALID_INPUT}),
            (f"Unreadable input ({type(error).__name__}).",),
        )
    flags: set[Flag] = set()
    reasons: list[str] = []
    pr = task.pr

    def status(state: State, reason: str, head=None, reviewed=None) -> TaskStatus:
        out_state = state
        if task.paused and state not in (State.MERGED, State.CLOSED, State.UNSAFE, State.UNKNOWN):
            out_state = State.PAUSED
            reasons.append(f"Stop switch is on (would be {state.value}).")
        return TaskStatus(
            out_state,
            frozenset(flags),
            (reason, *reasons),
            head,
            reviewed,
            pr.number if pr else None,
        )

    # Records for another repository or branch never count, and are reported. A build or review
    # must name exactly the task's source branch (parse() requires one); with no source branch
    # known, none can be matched. Publish records are bound by PR number and commit instead.
    runs_known = task.runs is not None
    if not runs_known:
        flags.add(Flag.RUNS_UNVERIFIED)
    runs = []
    for r in task.runs or ():
        if r.repo != task.repo:
            flags.add(Flag.WRONG_REPO_RECORD)
        elif r.step in ("build", "review") and (task.branch is None or r.branch != task.branch):
            flags.add(Flag.WRONG_BRANCH_RECORD)
        elif r.branch is not None and r.step != "publish" and r.branch != task.branch:
            flags.add(Flag.WRONG_BRANCH_RECORD)
        else:
            runs.append(r)

    merged_at = pr.merged_at if pr and pr.merged else None
    since, last_owner_action = _authorization(task, flags, merged_at)
    if not task.issue_known:
        # A merged PR: what authorised it can't be verified from GitHub's current link, and it
        # is history, so a calm note, not an alert (Codex's review of 28546f5).
        merged_pr = bool(pr and pr.merged)
        flags.add(Flag.AUTHORIZATION_UNVERIFIED if merged_pr else Flag.ISSUE_NOT_LINKED)

    # Only records from within the owner's current authorisation are this task's work. Earlier
    # records (before it began, or from a withdrawn one) never count, and are reported.
    current = [r for r in runs if since is not None and r.at >= since]
    if since is not None and len(current) < len(runs):
        flags.add(Flag.RECORD_BEFORE_AUTHORIZATION)
    if since is None and not task.issue_known and pr and pr.merged:
        # A merged PR whose authorisation can't be verified: its records can't be scoped to
        # an authorisation, so every record for its branch up to the merge counts, rather
        # than none (Codex's review of b7d568e: discarding them all claimed the merged commit
        # was never reviewed). A passing review of exactly the merged commit is still needed.
        current = list(runs)
    if merged_at is not None:
        # A review recorded after the merge can't make that merge compliant (Codex's review
        # of 69ed8e3).
        current = [r for r in current if r.at <= merged_at]

    # Two finished reviews of the same commit that disagree: nothing about it can be trusted.
    verdicts: dict[str, set[str]] = {}
    for r in current:
        if r.step == "review" and r.status == "finished":
            passed = r.verdict == "no_blocking_findings" and not r.blocking
            verdicts.setdefault(r.sha, set()).add("pass" if passed else "fail")
    if any(len(v) > 1 for v in verdicts.values()):
        flags.add(Flag.CONFLICTING_RECORDS)
        return TaskStatus(
            State.UNKNOWN,
            frozenset(flags),
            ("Two reviews of the same commit disagree; check the run records.",),
        )

    head = pr.head if pr else task.branch_head
    # Clinical gating looks at every file any record touched, authorised or not: when in
    # doubt, clinical.
    files = set(pr.files or () if pr else ())
    for r in runs:
        # A record made after a merge is later work: it never makes the finished merge
        # clinical (Codex's review of c5ccf49).
        if merged_at is None or r.at <= merged_at:
            files.update(r.files)
    if any(fnmatchcase(f, pat) for f in files for pat in task.clinical_paths):
        flags.add(Flag.CLINICAL)
    # Files not known, or a list known to be partial, may be clinical: gate on that, but
    # never claim either way (A5a). Known clinical paths in a partial list still count.
    partial = bool(pr and (pr.files is None or not pr.files_complete))
    files_unknown = partial and bool(task.clinical_paths)
    if partial:
        flags.add(Flag.FILES_UNVERIFIED)
    maybe_clinical = Flag.CLINICAL in flags or files_unknown

    # Merged: judged on its own, because it is final. Only the owner merges, and only a
    # commit that passed review (and, for clinical files, a clinician's approval).
    if pr and pr.merged:
        reviewed = verdicts.get(pr.head) == {"pass"}
        problems = []
        if pr.merged_by is None:
            # Nothing shows the owner merged it (A5a: a deleted or unreadable account).
            flags.add(Flag.MERGER_UNKNOWN)
            problems.append("merged by an account that can't be identified")
        elif pr.merged_by != task.owner:
            flags.add(Flag.UNAUTHORIZED_MERGE)
            problems.append(f"merged by {pr.merged_by}, not the owner")
        if runs_known and not reviewed:  # records not read: no claim either way
            flags.add(Flag.MERGED_UNREVIEWED)
            problems.append("the merged commit never passed review")
        if maybe_clinical and pr.reviews is None:
            flags.add(Flag.REVIEWS_UNVERIFIED)  # approval not known: no claim either way
        elif Flag.CLINICAL in flags and _clinician_approved(task, pr.head, merged_at):
            flags.add(Flag.CLINICIAN_APPROVED)
        elif Flag.CLINICAL in flags:
            flags.add(Flag.MERGED_WITHOUT_CLINICIAN)
            problems.append("clinical files merged without a clinician's approval of that commit")
        if since is None and task.issue_known:
            flags.add(Flag.UNAUTHORIZED_WORK)
            problems.append("the work was never authorised by the owner")
        checks_ok = _checks(task, pr.head, flags)
        if problems:
            return status(State.UNSAFE, "Merged, but " + "; ".join(problems) + ".", pr.head)
        # Unknown checks give CHECKS_UNVERIFIED (from _checks), not a claim either way.
        if not checks_ok and pr.checks is not None:
            flags.add(Flag.MERGED_WITH_CHECKS_NOT_PASSED)
        if not runs_known:
            return status(
                State.MERGED,
                f"Merged by the owner at {pr.head[:12]}. Billy's review records aren't read "
                "here, so its review isn't shown.",
                pr.head,
            )
        return status(
            State.MERGED,
            f"Merged by the owner at the reviewed commit {pr.head[:12]}.",
            pr.head,
            pr.head,
        )

    # A closed issue never makes an open PR look finished: anyone can open a PR that "fixes"
    # a closed issue (pre-review of 9537b08). The PR goes on through every gate, flagged.
    if pr and pr.open and not task.issue_open:
        flags.add(Flag.ISSUE_CLOSED_PR_OPEN)
    elif (pr and not pr.open) or not task.issue_open:
        return status(State.CLOSED, "Closed without merging.", head)

    def github_gates() -> None:
        """What GitHub itself shows about an open PR, judged on every path, so an early
        return never hides a failing check or a missing clinician approval (Codex's review of
        9fb21c8)."""
        if pr and pr.open:
            _checks(task, pr.head, flags)
            if maybe_clinical and _clinician_approved(task, pr.head):
                flags.add(Flag.CLINICIAN_APPROVED)
            elif maybe_clinical:
                # Unread reviews claim nothing either way (Codex's review of dc1eb14).
                if pr.reviews is None:
                    flags.add(Flag.REVIEWS_UNVERIFIED)
                else:
                    flags.add(Flag.CLINICAL_APPROVAL_MISSING)

    if since is None and not task.issue_known:
        github_gates()
        return status(
            State.NOT_LINKED,
            "Not linked to an authorised issue: none is linked, several are, or the one "
            "linked couldn't be read.",
            head,
        )
    if since is None:
        # Any sign of work counts: run records, a PR, or a commit on the source branch.
        if runs or pr or head is not None:
            github_gates()
            flags.add(Flag.UNAUTHORIZED_WORK)
            return status(
                State.UNSAFE, "Work exists, but the owner never authorised this task.", head
            )
        return status(State.PROPOSED, "Not authorised by the owner.", head)

    # A published PR whose head moved off the published (reviewed) commit is unsafe. This is
    # checked before any other gate, so an open question or a failure can't hide the warning,
    # and against every publish record for this PR, not only the current authorisation's: a
    # publish makes a PR for one exact commit, so its head never legitimately moves.
    if pr:
        published = [r for r in runs if r.step == "publish" and r.pr == pr.number]
        if any(r.sha != pr.head for r in published):
            flags.add(Flag.HEAD_MISMATCH)
            return status(
                State.UNSAFE,
                f"PR #{pr.number}'s head {pr.head[:12]} is not the commit that was reviewed "
                "and published. Do not approve it.",
                head,
            )

    # An agent's question holds the task until the owner acts after it (authorises again).
    # Later builds or reviews never clear it: only the owner can. An owner action at the same
    # instant as the question doesn't count as an answer.
    unanswered = [
        r
        for r in current
        if r.step == "question" and not (last_owner_action and last_owner_action > r.at)
    ]
    if unanswered:
        return status(State.BLOCKED, "The agent asked a question; waiting for the owner.", head)
    # A failure among the latest records (any of them, if several share the latest instant)
    # means the task failed; a later record means the agent tried again.
    latest_at = max((r.at for r in current), default=None)
    if any(r.step == "failure" and r.at == latest_at for r in current):
        return status(State.FAILED, "The latest run failed.", head)

    if head is None:
        if any(r.step == "build" for r in current):
            return status(State.BUILDING, "Work started; no commit yet.")
        return status(State.READY, "Authorised by the owner; no work yet.")

    # Fix rounds: commits that failed review since the owner's latest decision. Once they exceed
    # the limit, the task waits for the owner whatever happens next: further builds or a later
    # passing review don't clear it. Only the owner authorising again (after the review that
    # used the last round) starts a new budget.
    failed_rounds = {
        r.sha
        for r in current
        if r.step == "review"
        and r.status == "finished"
        and verdicts.get(r.sha) == {"fail"}
        and r.at >= last_owner_action
    }
    if len(failed_rounds) > task.max_fix_rounds:
        flags.add(Flag.FIX_ROUNDS_EXHAUSTED)
        return status(
            State.AWAITING_OWNER,
            f"{len(failed_rounds)} commits failed review, more than the "
            f"{task.max_fix_rounds} fix round(s) allowed; the owner decides.",
            head,
        )

    if not runs_known and head is not None:
        # Without Billy's records nothing is known of its review: no claim that one is
        # missing or that the PR came before it, and never a passed review. Everything
        # GitHub does show is still judged and flagged (Codex's review of 69ed8e3): the
        # required checks, and for a possibly clinical change, the clinician's approval.
        github_gates()
        return status(
            State.BUILT,
            f"{head[:12]}: Billy's review records aren't read here, so its review isn't shown.",
            head,
        )

    head_verdict = verdicts.get(head)
    if verdicts and head_verdict is None:
        flags.add(Flag.STALE_REVIEW)
    reported = any(r.step == "build" and r.sha == head for r in current)
    reviewing = any(r.step == "review" and r.status == "started" and r.sha == head for r in current)

    if head_verdict is None:
        flags.add(Flag.REVIEW_MISSING)
        if pr:
            flags.add(Flag.PR_BEFORE_REVIEW)
        if reviewing:
            return status(State.REVIEWING, f"Review of {head[:12]} under way.", head)
        if reported or pr:
            return status(State.BUILT, f"{head[:12]} is waiting for review.", head)
        return status(State.BUILDING, f"{head[:12]} hasn't been reported by the builder.", head)

    if head_verdict == {"fail"}:
        return status(State.CHANGES_NEEDED, f"Review of {head[:12]} found blocking problems.", head)

    # The head commit passed review.
    if not pr:
        return status(State.REVIEWED, f"{head[:12]} passed review; not published yet.", head, head)
    # Clinician approval is judged before the checks gate, so a PR waiting on its checks
    # never shows approval as needed when it is given (Codex's review of 28546f5).
    approved = maybe_clinical and _clinician_approved(task, head)
    if approved:
        flags.add(Flag.CLINICIAN_APPROVED)
    elif maybe_clinical and pr.reviews is None:
        flags.add(Flag.REVIEWS_UNVERIFIED)
    elif maybe_clinical:
        flags.add(Flag.CLINICAL_APPROVAL_MISSING)
    if not _checks(task, head, flags):
        return status(
            State.PUBLISHED,
            f"PR #{pr.number} is the reviewed commit; required checks have not all passed.",
            head,
            head,
        )
    if maybe_clinical and not approved:
        return status(
            State.CLINICAL_REVIEW,
            f"Clinical files: waiting for a clinician's approval of {head[:12]}.",
            head,
            head,
        )
    return status(
        State.AWAITING_OWNER,
        f"Review passed for {head[:12]}; required checks passed; waiting for the owner.",
        head,
        head,
    )
