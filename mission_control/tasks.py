"""The task-state model (phase A2): one task's state, derived from GitHub-shaped data.

Pure and deterministic: `derive(task)` reads one dict and returns one `TaskStatus`. It makes no
network calls, reads no files, keeps no state between calls and never looks at the clock, so
the same input always gives the same answer. Every input is untrusted: text in issues, comments
and labels never authorises anything, and anything missing, malformed or contradictory gives
`State.UNKNOWN` (needs attention), never a guessed approval.

States follow the design's task state machine (mission-control.md §6 in
DrZaff/ai-medicine-collective), plus two safety states this model adds: UNSAFE (an invariant is
broken, for example a merged commit nobody reviewed) and UNKNOWN (the input can't be trusted).

Input contract (all keys are checked; unknown keys are ignored):

    {
      "repo": "owner/name",                  # the repository this task belongs to
      "owner": "login",                      # the only account whose actions authorise or merge
      "clinicians": ["login"],               # accounts whose GitHub approval counts as clinical
      "clinical_paths": ["evidence/*", ...], # fnmatch patterns; a match makes the change clinical
      "required_checks": ["lint", "test"],   # check names that must pass on the head commit
      "max_fix_rounds": 1,                   # blocking reviews allowed before the owner decides
      "paused": false,                       # the stop switch
      "issue": {"number": 7, "state": "open" | "closed", "timeline": [event, ...]},
      "branch": {"name": "claude/x", "head": "<40 hex>"} | null,
      "runs": [run, ...],                    # Billy's run records (build, review, publish, ...)
      "pull_request": pull_request | null,
    }

    event         {"event": "labeled" | "unlabeled" | "authorized" | <other>, "label": str,
                   "actor": "login", "at": "ISO 8601 with a time zone"}
                   Only "labeled agent:ready" or "authorized" (an approved-action record, such as
                   the owner's direct instruction) by the owner authorise work. Anything else,
                   including the label's mere presence and every comment body, is ignored.
    run           {"step": "build" | "review" | "publish" | "question" | "failure",
                   "repo": "owner/name", "branch": str, "sha": "<40 hex>", "at": ISO 8601,
                   "status": "started" | "finished",          (build and review; default finished)
                   "verdict": "no_blocking_findings" | "changes_needed",   (finished review)
                   "findings": [{"severity": "blocking" | "should_fix" | "note"}],
                   "pr": int,                                  (publish)
                   "files": [path]}                            (optional, any step)
    pull_request  {"number": int, "state": "open" | "closed", "draft": bool, "merged": bool,
                   "merged_by": "login" | null, "head_sha": "<40 hex>", "files": [path],
                   "reviews": [{"user": "login", "user_type": "User" | "Bot",
                                "state": "APPROVED" | "CHANGES_REQUESTED" | "COMMENTED" |
                                         "DISMISSED", "commit_id": "<40 hex>", "at": ISO 8601}],
                   "checks": [{"name": str, "head_sha": "<40 hex>",
                               "status": "queued" | "in_progress" | "completed",
                               "conclusion": "success" | "failure" | ... | null}]}

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
SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
LOGIN = re.compile(r"^[A-Za-z0-9-]+(\[bot\])?$")


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
    CHECKS_PASSED = "checks_passed"
    CHECKS_PENDING = "checks_pending"
    CHECKS_MISSING = "checks_missing"  # a required check has no result for the head commit
    CHECKS_STALE = "checks_stale"  # results exist, but for another commit
    CHECKS_FAILING = "checks_failing"
    CLINICAL = "clinical"
    CLINICAL_APPROVAL_MISSING = "clinical_approval_missing"
    UNAUTHORIZED_MERGE = "unauthorized_merge"  # merged by someone other than the owner
    MERGED_UNREVIEWED = "merged_unreviewed"  # the merged commit never passed review
    MERGED_WITHOUT_CLINICIAN = "merged_without_clinician"
    MERGED_WITH_CHECKS_NOT_PASSED = "merged_with_checks_not_passed"


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
        Flag.PR_BEFORE_REVIEW,
        Flag.CHECKS_FAILING,
        Flag.MERGED_WITH_CHECKS_NOT_PASSED,
    }
)


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
        return self.state in ATTENTION_STATES or bool(self.flags & ATTENTION_FLAGS)


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
    _req(isinstance(value, str) and bool(SHA.match(value)), f"{name} must be a full 40-hex SHA")
    return value


def _login(value: Any, name: str) -> str:
    _req(isinstance(value, str) and bool(LOGIN.match(value)), f"{name} must be a GitHub login")
    return value


def _time(value: Any, name: str) -> datetime:
    _req(isinstance(value, str), f"{name} must be an ISO 8601 time")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise InvalidInput(f"{name} must be an ISO 8601 time") from None
    _req(parsed.tzinfo is not None, f"{name} must include a time zone")
    return parsed


def _list(value: Any, name: str) -> list:
    _req(isinstance(value, list), f"{name} must be a list")
    return value


def _map(value: Any, name: str) -> Mapping:
    _req(isinstance(value, Mapping), f"{name} must be an object")
    return value


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
    head: str
    files: tuple[str, ...]
    reviews: tuple[_Review, ...]
    checks: tuple[_Check, ...]


@dataclass(frozen=True)
class _Task:
    repo: str
    owner: str
    clinicians: frozenset[str]
    clinical_paths: tuple[str, ...]
    required_checks: tuple[str, ...]
    max_fix_rounds: int
    paused: bool
    issue_open: bool
    timeline: tuple[_Event, ...]
    branch: str | None
    branch_head: str | None
    runs: tuple[_Run, ...]
    pr: _PR | None


RUN_STEPS = frozenset({"build", "review", "publish", "question", "failure"})
REVIEW_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"})


def _parse_run(raw: Any, i: int) -> _Run:
    r = _map(raw, f"runs[{i}]")
    step = r.get("step")
    _req(step in RUN_STEPS, f"runs[{i}].step must be one of {sorted(RUN_STEPS)}")
    repo = _text(r.get("repo"), f"runs[{i}].repo")
    _req(bool(REPO.match(repo)), f"runs[{i}].repo must be owner/name")
    status = r.get("status", "finished")
    _req(status in ("started", "finished"), f"runs[{i}].status must be started or finished")
    verdict = r.get("verdict")
    findings = _list(r.get("findings", []), f"runs[{i}].findings")
    if step == "review" and status == "finished":
        _req(
            verdict in ("no_blocking_findings", "changes_needed"),
            f"runs[{i}].verdict must be no_blocking_findings or changes_needed",
        )
    blocking = any(_map(f, f"runs[{i}].findings[]").get("severity") == "blocking" for f in findings)
    sha = r.get("sha")
    if step in ("build", "review", "publish") and not (step == "build" and status == "started"):
        sha = _sha(sha, f"runs[{i}].sha")
    elif sha is not None:
        sha = _sha(sha, f"runs[{i}].sha")
    pr = r.get("pr")
    if step == "publish":
        _req(isinstance(pr, int) and not isinstance(pr, bool), f"runs[{i}].pr must be a number")
    branch = r.get("branch")
    if branch is not None:
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


def _parse_pr(raw: Any) -> _PR:
    p = _map(raw, "pull_request")
    number = p.get("number")
    _req(isinstance(number, int) and not isinstance(number, bool), "pull_request.number")
    state = p.get("state")
    _req(state in ("open", "closed"), "pull_request.state must be open or closed")
    merged = p.get("merged", False)
    _req(isinstance(merged, bool), "pull_request.merged must be true or false")
    _req(not (merged and state == "open"), "pull_request can't be open and merged")
    merged_by = p.get("merged_by")
    if merged:
        merged_by = _login(merged_by, "pull_request.merged_by")
    reviews = []
    for i, raw_review in enumerate(_list(p.get("reviews", []), "pull_request.reviews")):
        rv = _map(raw_review, f"pull_request.reviews[{i}]")
        _req(rv.get("state") in REVIEW_STATES, f"pull_request.reviews[{i}].state")
        _req(rv.get("user_type", "User") in ("User", "Bot"), f"pull_request.reviews[{i}].user_type")
        user = _login(rv.get("user"), f"pull_request.reviews[{i}].user")
        reviews.append(
            _Review(
                user=user,
                is_bot=rv.get("user_type", "User") == "Bot" or user.endswith("[bot]"),
                state=rv["state"],
                commit=_sha(rv.get("commit_id"), f"pull_request.reviews[{i}].commit_id"),
                at=_time(rv.get("at"), f"pull_request.reviews[{i}].at"),
            )
        )
    checks = []
    for i, raw_check in enumerate(_list(p.get("checks", []), "pull_request.checks")):
        c = _map(raw_check, f"pull_request.checks[{i}]")
        status = c.get("status")
        _req(status in ("queued", "in_progress", "completed"), f"pull_request.checks[{i}].status")
        conclusion = c.get("conclusion")
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
        draft=bool(p.get("draft", False)),
        merged=merged,
        merged_by=merged_by,
        head=_sha(p.get("head_sha"), "pull_request.head_sha"),
        files=_strings(p.get("files", []), "pull_request.files"),
        reviews=tuple(reviews),
        checks=tuple(checks),
    )


def parse(raw: Any) -> _Task:
    """Validate one task's input; raises InvalidInput with the first problem found."""
    t = _map(raw, "task")
    repo = _text(t.get("repo"), "repo")
    _req(bool(REPO.match(repo)), "repo must be owner/name")
    issue = _map(t.get("issue"), "issue")
    _req(isinstance(issue.get("number"), int), "issue.number must be a number")
    _req(issue.get("state") in ("open", "closed"), "issue.state must be open or closed")
    timeline = []
    for i, raw_event in enumerate(_list(issue.get("timeline", []), "issue.timeline")):
        e = _map(raw_event, f"issue.timeline[{i}]")
        label = e.get("label")
        timeline.append(
            _Event(
                kind=_text(e.get("event"), f"issue.timeline[{i}].event"),
                label=label if isinstance(label, str) else None,
                actor=_login(e.get("actor"), f"issue.timeline[{i}].actor"),
                at=_time(e.get("at"), f"issue.timeline[{i}].at"),
            )
        )
    branch = t.get("branch")
    branch_name = branch_head = None
    if branch is not None:
        b = _map(branch, "branch")
        branch_name = _text(b.get("name"), "branch.name")
        branch_head = _sha(b.get("head"), "branch.head")
    max_rounds = t.get("max_fix_rounds", 1)
    _req(
        isinstance(max_rounds, int) and not isinstance(max_rounds, bool) and max_rounds >= 0,
        "max_fix_rounds must be a whole number",
    )
    paused = t.get("paused", False)
    _req(isinstance(paused, bool), "paused must be true or false")
    pr_raw = t.get("pull_request")
    return _Task(
        repo=repo,
        owner=_login(t.get("owner"), "owner"),
        clinicians=frozenset(
            _login(c, "clinicians[]") for c in _list(t.get("clinicians", []), "clinicians")
        ),
        clinical_paths=_strings(t.get("clinical_paths", []), "clinical_paths"),
        required_checks=_strings(t.get("required_checks", []), "required_checks"),
        max_fix_rounds=max_rounds,
        paused=paused,
        issue_open=issue["state"] == "open",
        timeline=tuple(timeline),
        branch=branch_name,
        branch_head=branch_head,
        runs=tuple(_parse_run(r, i) for i, r in enumerate(_list(t.get("runs", []), "runs"))),
        pr=None if pr_raw is None else _parse_pr(pr_raw),
    )


# ---------------------------------------------------------------- derivation


def _authorization(task: _Task, flags: set[Flag]) -> datetime | None:
    """When the owner last authorised the work, or None. Only the owner's own "labeled
    agent:ready" or "authorized" event counts. Removing the label (by anyone) withdraws it, and
    an add and a removal at the same instant count as withdrawn: when in doubt, not authorised."""
    current: datetime | None = None
    # At the same instant a removal sorts last, so it wins over an add or an authorisation.
    for e in sorted(task.timeline, key=lambda e: (e.at, e.kind == "unlabeled")):
        if e.kind == "labeled" and e.label == READY_LABEL:
            if e.actor == task.owner:
                current = e.at
            else:
                flags.add(Flag.LABEL_WITHOUT_OWNER)
        elif e.kind == "unlabeled" and e.label == READY_LABEL:
            current = None
        elif e.kind == "authorized" and e.actor == task.owner:
            current = e.at
    return current


def _checks(task: _Task, head: str, flags: set[Flag]) -> bool:
    """True only if every required check completed successfully on exactly this commit."""
    pr = task.pr
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


def _clinician_approved(task: _Task, head: str) -> bool:
    """A clinician's own GitHub approval of exactly this commit, not later withdrawn. Bots never
    count, and neither does any review report outside GitHub's reviews (such as Codex's)."""
    latest: dict[str, _Review] = {}
    for rv in sorted(task.pr.reviews, key=lambda r: r.at):
        if rv.is_bot or rv.user not in task.clinicians or rv.commit != head:
            continue
        if rv.state in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[rv.user] = rv
    return any(rv.state == "APPROVED" for rv in latest.values())


def derive(raw: Any) -> TaskStatus:
    """The state of one task. Never raises on bad input: that gives State.UNKNOWN."""
    try:
        task = parse(raw)
    except InvalidInput as error:
        return TaskStatus(State.UNKNOWN, frozenset({Flag.INVALID_INPUT}), (str(error),))
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

    # Records for another repository or branch never count, and are reported.
    runs = []
    for r in task.runs:
        if r.repo != task.repo:
            flags.add(Flag.WRONG_REPO_RECORD)
        elif task.branch and r.branch and r.branch != task.branch and r.step != "publish":
            flags.add(Flag.WRONG_BRANCH_RECORD)
        else:
            runs.append(r)

    # Two finished reviews of the same commit that disagree: nothing about it can be trusted.
    verdicts: dict[str, set[str]] = {}
    for r in runs:
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

    authorized_at = _authorization(task, flags)
    head = pr.head if pr else task.branch_head
    files = set(pr.files if pr else ())
    for r in runs:
        files.update(r.files)
    if any(fnmatchcase(f, pat) for f in files for pat in task.clinical_paths):
        flags.add(Flag.CLINICAL)

    # Merged: judged on its own, because it is final. Only the owner merges, and only a
    # commit that passed review (and, for clinical files, a clinician's approval).
    if pr and pr.merged:
        reviewed = verdicts.get(pr.head) == {"pass"}
        problems = []
        if pr.merged_by != task.owner:
            flags.add(Flag.UNAUTHORIZED_MERGE)
            problems.append(f"merged by {pr.merged_by}, not the owner")
        if not reviewed:
            flags.add(Flag.MERGED_UNREVIEWED)
            problems.append("the merged commit never passed review")
        if Flag.CLINICAL in flags and not _clinician_approved(task, pr.head):
            flags.add(Flag.MERGED_WITHOUT_CLINICIAN)
            problems.append("clinical files merged without a clinician's approval of that commit")
        if authorized_at is None:
            flags.add(Flag.UNAUTHORIZED_WORK)
            problems.append("the work was never authorised by the owner")
        checks_ok = _checks(task, pr.head, flags)
        if problems:
            return status(State.UNSAFE, "Merged, but " + "; ".join(problems) + ".", pr.head)
        if not checks_ok:
            flags.add(Flag.MERGED_WITH_CHECKS_NOT_PASSED)
        return status(
            State.MERGED,
            f"Merged by the owner at the reviewed commit {pr.head[:12]}.",
            pr.head,
            pr.head,
        )

    if (pr and not pr.open) or not task.issue_open:
        return status(State.CLOSED, "Closed without merging.", head)

    if authorized_at is None:
        if runs or pr:
            flags.add(Flag.UNAUTHORIZED_WORK)
            return status(
                State.UNSAFE, "Work exists, but the owner never authorised this task.", head
            )
        return status(State.PROPOSED, "Not authorised by the owner.", head)

    # Only what happened after the latest authorisation counts as this round of work.
    current = [r for r in runs if r.at >= authorized_at]
    latest = max(current, key=lambda r: r.at, default=None)
    if latest and latest.step == "failure":
        return status(State.FAILED, "The latest run failed.", head)
    if latest and latest.step == "question":
        return status(State.BLOCKED, "The agent asked a question; waiting for the owner.", head)

    if head is None:
        if any(r.step == "build" for r in current):
            return status(State.BUILDING, "Work started; no commit yet.")
        return status(State.READY, "Authorised by the owner; no work yet.")

    # A published PR whose head moved off the published (reviewed) commit is unsafe.
    if pr:
        published = [r for r in current if r.step == "publish" and r.pr == pr.number]
        if any(r.sha != pr.head for r in published):
            flags.add(Flag.HEAD_MISMATCH)
            return status(
                State.UNSAFE,
                f"PR #{pr.number}'s head {pr.head[:12]} is not the commit that was reviewed "
                "and published. Do not approve it.",
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
        rounds = len([sha for sha, v in verdicts.items() if v == {"fail"}])
        if rounds > task.max_fix_rounds:
            flags.add(Flag.FIX_ROUNDS_EXHAUSTED)
            return status(
                State.AWAITING_OWNER,
                f"Review of {head[:12]} found blocking problems and the fix rounds are used "
                "up; the owner decides.",
                head,
            )
        return status(State.CHANGES_NEEDED, f"Review of {head[:12]} found blocking problems.", head)

    # The head commit passed review.
    if not pr:
        return status(State.REVIEWED, f"{head[:12]} passed review; not published yet.", head, head)
    if not _checks(task, head, flags):
        return status(
            State.PUBLISHED,
            f"PR #{pr.number} is the reviewed commit; required checks have not all passed.",
            head,
            head,
        )
    if Flag.CLINICAL in flags and not _clinician_approved(task, head):
        flags.add(Flag.CLINICAL_APPROVAL_MISSING)
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
