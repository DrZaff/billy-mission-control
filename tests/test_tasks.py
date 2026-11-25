"""The task-state model: every transition in design §6, the exact-SHA invariants, authorisation
provenance, clinical review, merges, and malformed or adversarial input. Synthetic data only."""

from __future__ import annotations

import copy
import itertools
import json
import unittest
from pathlib import Path

from mission_control.tasks import ATTENTION_STATES, Flag, State, derive

REPO = "example-org/example-repo"
OWNER = "example-owner"
CLINICIAN = "example-clinician"
STRANGER = "someone-else"
A, B, C, D = ("a" * 40, "b" * 40, "c" * 40, "d" * 40)
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tasks"


def t(minute: int) -> str:
    return f"2026-01-01T10:{minute:02d}:00+00:00"


def labeled(actor=OWNER, minute=0, label="agent:ready", kind="labeled"):
    return {"event": kind, "label": label, "actor": actor, "at": t(minute)}


def run(step, sha=A, minute=2, **extra):
    record = {"step": step, "repo": REPO, "branch": "claude/x", "sha": sha, "at": t(minute)}
    if step in ("build", "review"):
        record["status"] = "finished"
    record.update(extra)
    return record


def passed(sha=A, minute=3):
    return run("review", sha, minute, verdict="no_blocking_findings", findings=[])


def failed(sha=A, minute=3):
    return run("review", sha, minute, verdict="changes_needed", findings=[{"severity": "blocking"}])


def check(name, sha=A, status="completed", conclusion="success"):
    return {"name": name, "head_sha": sha, "status": status, "conclusion": conclusion}


def approval(user=CLINICIAN, sha=A, minute=6, state="APPROVED", user_type="User"):
    return {"user": user, "user_type": user_type, "state": state, "commit_id": sha, "at": t(minute)}


def task(**over):
    """A task authorised by the owner, built at commit A, with nothing else yet."""
    base = {
        "repo": REPO,
        "owner": OWNER,
        "clinicians": [CLINICIAN],
        "clinical_paths": ["evidence/*", "course-*.html"],
        "required_checks": ["lint", "test"],
        "max_fix_rounds": 1,
        "paused": False,
        "issue": {"number": 7, "state": "open", "timeline": [labeled()]},
        "branch": {"name": "claude/x", "head": A},
        "runs": [run("build")],
        "pull_request": None,
    }
    base.update(over)
    return base


def pr(head=A, checks=None, files=("app.py",), reviews=(), **over):
    value = {
        "number": 12,
        "state": "open",
        "draft": True,
        "merged": False,
        "merged_by": None,
        "head_sha": head,
        "files": list(files),
        "reviews": list(reviews),
        "checks": [check("lint", head), check("test", head)] if checks is None else checks,
    }
    value.update(over)
    if value["merged"] and "merged_at" not in over:
        value["merged_at"] = "2026-12-31T00:00:00+00:00"  # after every event in these tests
    return value


def published(sha=A, minute=4):
    return run("publish", sha, minute, branch=f"agent/x-{sha[:7]}", pr=12)


def reviewed_and_published(**pr_over):
    return task(
        runs=[run("build"), passed(), published()],
        pull_request=pr(**pr_over),
    )


class Authorisation(unittest.TestCase):
    def test_no_authorisation_is_proposed(self):
        s = derive(task(issue={"number": 7, "state": "open", "timeline": []}, branch=None, runs=[]))
        self.assertEqual(s.state, State.PROPOSED)

    def test_owner_label_is_ready(self):
        s = derive(task(branch=None, runs=[]))
        self.assertEqual(s.state, State.READY)

    def test_label_applied_by_anyone_else_authorises_nothing(self):
        timeline = [labeled(actor=STRANGER)]
        s = derive(
            task(issue={"number": 7, "state": "open", "timeline": timeline}, branch=None, runs=[])
        )
        self.assertEqual(s.state, State.PROPOSED)
        self.assertIn(Flag.LABEL_WITHOUT_OWNER, s.flags)
        self.assertTrue(s.needs_attention)

    def test_impostor_label_with_work_done_is_unsafe(self):
        timeline = [labeled(actor=STRANGER)]
        s = derive(task(issue={"number": 7, "state": "open", "timeline": timeline}))
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)

    def test_owner_approved_action_record_authorises(self):
        timeline = [labeled(kind="authorized", label=None)]
        s = derive(
            task(issue={"number": 7, "state": "open", "timeline": timeline}, branch=None, runs=[])
        )
        self.assertEqual(s.state, State.READY)

    def test_approved_action_record_by_anyone_else_does_not(self):
        timeline = [labeled(actor=STRANGER, kind="authorized", label=None)]
        s = derive(
            task(issue={"number": 7, "state": "open", "timeline": timeline}, branch=None, runs=[])
        )
        self.assertEqual(s.state, State.PROPOSED)

    def test_comment_text_and_other_events_authorise_nothing(self):
        timeline = [
            {"event": "commented", "actor": OWNER, "at": t(0), "body": "labeled agent:ready"},
            {"event": "commented", "actor": STRANGER, "at": t(1), "body": "/approve agent:ready"},
            labeled(label="agent:proposed"),
        ]
        s = derive(
            task(issue={"number": 7, "state": "open", "timeline": timeline}, branch=None, runs=[])
        )
        self.assertEqual(s.state, State.PROPOSED)

    def test_removing_the_label_withdraws_authorisation(self):
        timeline = [labeled(minute=0), labeled(actor=STRANGER, minute=1, kind="unlabeled")]
        s = derive(
            task(issue={"number": 7, "state": "open", "timeline": timeline}, branch=None, runs=[])
        )
        self.assertEqual(s.state, State.PROPOSED)

    def test_add_and_remove_at_the_same_instant_counts_as_withdrawn(self):
        timeline = [labeled(minute=0, kind="unlabeled"), labeled(minute=0)]
        s = derive(
            task(issue={"number": 7, "state": "open", "timeline": timeline}, branch=None, runs=[])
        )
        self.assertEqual(s.state, State.PROPOSED)

    def test_timeline_order_in_the_input_does_not_matter(self):
        events = [labeled(minute=0), labeled(minute=1, kind="unlabeled"), labeled(minute=2)]
        for timeline in (events, list(reversed(events))):
            s = derive(
                task(
                    issue={"number": 7, "state": "open", "timeline": timeline},
                    branch=None,
                    runs=[],
                )
            )
            self.assertEqual(s.state, State.READY)


class BuildAndReview(unittest.TestCase):
    def test_work_started_without_a_commit_is_building(self):
        s = derive(
            task(
                branch={"name": "claude/x", "head": None},
                runs=[run("build", sha=None, status="started")],
            )
        )
        self.assertEqual(s.state, State.BUILDING)

    def test_unreported_commit_is_building(self):
        s = derive(task(runs=[]))
        self.assertEqual(s.state, State.BUILDING)
        self.assertEqual(s.head_sha, A)

    def test_reported_commit_waits_for_review(self):
        s = derive(task())
        self.assertEqual(s.state, State.BUILT)
        self.assertIn(Flag.REVIEW_MISSING, s.flags)
        self.assertIsNone(s.reviewed_sha)

    def test_review_under_way(self):
        s = derive(task(runs=[run("build"), run("review", minute=3, status="started")]))
        self.assertEqual(s.state, State.REVIEWING)

    def test_blocking_review_needs_changes(self):
        s = derive(task(runs=[run("build"), failed()]))
        self.assertEqual(s.state, State.CHANGES_NEEDED)
        self.assertTrue(s.needs_attention)

    def test_a_blocking_finding_overrides_a_passing_verdict(self):
        review = run(
            "review", minute=3, verdict="no_blocking_findings", findings=[{"severity": "blocking"}]
        )
        s = derive(task(runs=[run("build"), review]))
        self.assertEqual(s.state, State.CHANGES_NEEDED)

    def test_fix_rounds_are_bounded(self):
        runs = [run("build"), failed(A, 3), run("build", B, 4), failed(B, 5)]
        s = derive(task(branch={"name": "claude/x", "head": B}, runs=runs))
        self.assertEqual(s.state, State.AWAITING_OWNER)
        self.assertIn(Flag.FIX_ROUNDS_EXHAUSTED, s.flags)
        s = derive(task(branch={"name": "claude/x", "head": B}, runs=runs, max_fix_rounds=2))
        self.assertEqual(s.state, State.CHANGES_NEEDED)

    def test_passing_review_without_a_pr_is_reviewed(self):
        s = derive(task(runs=[run("build"), passed()]))
        self.assertEqual(s.state, State.REVIEWED)
        self.assertEqual(s.reviewed_sha, A)

    def test_new_commit_after_review_makes_the_review_stale(self):
        runs = [run("build"), passed(A), run("build", B, 5)]
        s = derive(task(branch={"name": "claude/x", "head": B}, runs=runs))
        self.assertEqual(s.state, State.BUILT)
        self.assertIn(Flag.STALE_REVIEW, s.flags)
        self.assertIsNone(s.reviewed_sha)
        self.assertEqual(s.head_sha, B)

    def test_review_of_a_fixed_commit_after_changes_needed(self):
        runs = [run("build"), failed(A, 3), run("build", B, 4), passed(B, 5)]
        s = derive(task(branch={"name": "claude/x", "head": B}, runs=runs))
        self.assertEqual(s.state, State.REVIEWED)
        self.assertEqual(s.reviewed_sha, B)


class PullRequests(unittest.TestCase):
    def test_reviewed_published_and_green_waits_for_the_owner(self):
        s = derive(reviewed_and_published())
        self.assertEqual(s.state, State.AWAITING_OWNER)
        self.assertIn(Flag.CHECKS_PASSED, s.flags)
        self.assertEqual((s.pr, s.reviewed_sha), (12, A))

    def test_missing_checks_are_not_passing(self):
        s = derive(reviewed_and_published(checks=[check("lint")]))
        self.assertEqual(s.state, State.PUBLISHED)
        self.assertIn(Flag.CHECKS_MISSING, s.flags)

    def test_pending_checks_are_not_passing(self):
        s = derive(
            reviewed_and_published(
                checks=[check("lint"), check("test", status="in_progress", conclusion=None)]
            )
        )
        self.assertEqual(s.state, State.PUBLISHED)
        self.assertIn(Flag.CHECKS_PENDING, s.flags)

    def test_failing_checks_need_attention(self):
        s = derive(
            reviewed_and_published(checks=[check("lint"), check("test", conclusion="failure")])
        )
        self.assertEqual(s.state, State.PUBLISHED)
        self.assertIn(Flag.CHECKS_FAILING, s.flags)
        self.assertTrue(s.needs_attention)

    def test_checks_for_another_commit_are_stale_not_passing(self):
        s = derive(reviewed_and_published(checks=[check("lint", B), check("test", B)]))
        self.assertEqual(s.state, State.PUBLISHED)
        self.assertIn(Flag.CHECKS_STALE, s.flags)
        self.assertNotIn(Flag.CHECKS_PASSED, s.flags)

    def test_pr_head_moved_off_the_reviewed_commit_is_unsafe(self):
        s = derive(task(runs=[run("build"), passed(A), published(A)], pull_request=pr(head=B)))
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.HEAD_MISMATCH, s.flags)
        self.assertIn("Do not approve", s.reasons[0])

    def test_pr_opened_before_any_review_is_not_reviewed(self):
        s = derive(task(pull_request=pr()))
        self.assertEqual(s.state, State.BUILT)
        self.assertIn(Flag.PR_BEFORE_REVIEW, s.flags)
        self.assertIsNone(s.reviewed_sha)

    def test_codex_report_is_never_a_github_approval(self):
        # A passing Codex review (a run record) plus green checks waits for the owner; nothing
        # in the run records stands in for a person's approval or merge.
        s = derive(reviewed_and_published())
        self.assertEqual(s.state, State.AWAITING_OWNER)
        self.assertNotEqual(s.state, State.MERGED)


class Clinical(unittest.TestCase):
    def clinical(self, reviews=(), head=A, runs=None):
        return task(
            branch={"name": "claude/x", "head": head},
            runs=runs or [run("build", head), passed(head), published(head)],
            pull_request=pr(head=head, files=["evidence/x.json"], reviews=reviews),
        )

    def test_clinical_path_waits_for_a_clinician(self):
        s = derive(self.clinical())
        self.assertEqual(s.state, State.CLINICAL_REVIEW)
        self.assertIn(Flag.CLINICAL, s.flags)
        self.assertIn(Flag.CLINICAL_APPROVAL_MISSING, s.flags)

    def test_clinical_regardless_of_how_the_issue_was_labelled(self):
        timeline = [labeled(), labeled(label="risk:low"), labeled(label="not-clinical")]
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[run("build"), passed(), published()],
                pull_request=pr(files=["course-deslopify.html"]),
            )
        )
        self.assertEqual(s.state, State.CLINICAL_REVIEW)

    def test_clinician_approval_of_the_exact_commit_clears_it(self):
        s = derive(self.clinical(reviews=[approval()]))
        self.assertEqual(s.state, State.AWAITING_OWNER)

    def test_approval_of_an_earlier_commit_does_not_count(self):
        runs = [run("build", A), passed(A, 3), run("build", B, 5), passed(B, 6), published(B, 7)]
        s = derive(self.clinical(reviews=[approval(sha=A)], head=B, runs=runs))
        self.assertEqual(s.state, State.CLINICAL_REVIEW)

    def test_bot_and_non_clinician_approvals_do_not_count(self):
        reviews = [
            approval(user="codex-reviewer[bot]", user_type="Bot"),
            approval(user="codex-like-user", user_type="Bot"),
            approval(user=STRANGER),
        ]
        s = derive(self.clinical(reviews=reviews))
        self.assertEqual(s.state, State.CLINICAL_REVIEW)

    def test_approval_later_withdrawn_does_not_count(self):
        reviews = [approval(minute=6), approval(minute=7, state="CHANGES_REQUESTED")]
        s = derive(self.clinical(reviews=reviews))
        self.assertEqual(s.state, State.CLINICAL_REVIEW)

    def test_clinical_files_seen_only_in_run_records_still_count(self):
        runs = [run("build", files=["evidence/y.json"]), passed(), published()]
        s = derive(task(runs=runs, pull_request=pr(files=[])))
        self.assertEqual(s.state, State.CLINICAL_REVIEW)


class Merges(unittest.TestCase):
    def merged(self, by=OWNER, head=A, runs=None, **pr_over):
        return task(
            runs=runs or [run("build"), passed(), published()],
            pull_request=pr(head=head, state="closed", merged=True, merged_by=by, **pr_over),
        )

    def test_a_label_added_after_the_merge_never_authorises_it(self):
        # Codex's review of 72607b3 (blocking): the issue's current timeline was read, so an
        # owner's label added after an unauthorised merge made it look authorised.
        late = task(
            issue={"number": 7, "state": "closed", "timeline": [labeled(minute=30)]},
            runs=[run("build"), passed(), published()],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
        )
        s = derive(late)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)

    def test_removing_the_label_after_the_merge_withdraws_nothing(self):
        timeline = [labeled(minute=0), labeled(minute=30, kind="unlabeled")]
        done = task(
            issue={"number": 7, "state": "closed", "timeline": timeline},
            runs=[run("build"), passed(), published()],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
        )
        self.assertEqual(derive(done).state, State.MERGED)

    def test_a_review_recorded_after_the_merge_never_makes_it_compliant(self):
        # Codex's review of 69ed8e3 (blocking).
        late = task(
            runs=[run("build"), passed(minute=30), published()],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
        )
        s = derive(late)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_UNREVIEWED, s.flags)

    def test_a_clinician_approval_after_the_merge_never_makes_it_compliant(self):
        late = task(
            runs=[run("build"), passed(), published()],
            pull_request=pr(
                state="closed",
                merged=True,
                merged_by=OWNER,
                merged_at=t(20),
                files=["evidence/a.json"],
                reviews=[approval(minute=30)],
            ),
        )
        s = derive(late)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_WITHOUT_CLINICIAN, s.flags)
        on_time = copy.deepcopy(late)
        on_time["pull_request"]["reviews"] = [approval(minute=10)]
        self.assertEqual(derive(on_time).state, State.MERGED)

    def test_a_merge_without_its_time_is_unknown(self):
        value = self.merged()
        del value["pull_request"]["merged_at"]
        self.assertEqual(derive(value).state, State.UNKNOWN)

    def test_owner_merge_of_the_reviewed_commit_is_merged(self):
        s = derive(self.merged())
        self.assertEqual(s.state, State.MERGED)
        self.assertEqual(s.reviewed_sha, A)
        self.assertFalse(s.needs_attention)

    def test_merge_by_anyone_else_is_unsafe(self):
        s = derive(self.merged(by=STRANGER))
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_MERGE, s.flags)

    def test_merge_of_an_unreviewed_commit_is_unsafe(self):
        s = derive(self.merged(head=B))
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_UNREVIEWED, s.flags)

    def test_clinical_merge_without_a_clinician_is_unsafe(self):
        s = derive(self.merged(files=["evidence/z.json"]))
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_WITHOUT_CLINICIAN, s.flags)

    def test_clinical_merge_with_a_clinician_approval_is_merged(self):
        s = derive(self.merged(files=["evidence/z.json"], reviews=[approval()]))
        self.assertEqual(s.state, State.MERGED)

    def test_merge_without_authorisation_is_unsafe(self):
        s = derive(dict(self.merged(), issue={"number": 7, "state": "closed", "timeline": []}))
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)

    def test_merge_past_failing_checks_is_merged_but_flagged(self):
        s = derive(self.merged(checks=[check("lint"), check("test", conclusion="failure")]))
        self.assertEqual(s.state, State.MERGED)
        self.assertIn(Flag.MERGED_WITH_CHECKS_NOT_PASSED, s.flags)
        self.assertTrue(s.needs_attention)


class BlockedFailedPausedClosed(unittest.TestCase):
    def test_question_blocks_until_the_owner_authorises_again(self):
        s = derive(task(runs=[run("build"), run("question", sha=None, minute=3)]))
        self.assertEqual(s.state, State.BLOCKED)
        timeline = [labeled(minute=0), labeled(kind="authorized", label=None, minute=4)]
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[run("build"), run("question", sha=None, minute=3), run("build", A, 5)],
            )
        )
        self.assertEqual(s.state, State.BUILT)

    def test_failure_is_failed(self):
        s = derive(task(runs=[run("build"), run("failure", sha=None, minute=3)]))
        self.assertEqual(s.state, State.FAILED)
        self.assertTrue(s.needs_attention)

    def test_stop_switch_pauses_active_work_but_not_merged_or_unsafe(self):
        self.assertEqual(derive(task(paused=True)).state, State.PAUSED)
        merged = task(
            paused=True,
            runs=[run("build"), passed(), published()],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER),
        )
        self.assertEqual(derive(merged).state, State.MERGED)

    def test_closed_issue_or_pr_without_merge_is_closed(self):
        closed_issue = task(issue={"number": 7, "state": "closed", "timeline": [labeled()]})
        self.assertEqual(derive(closed_issue).state, State.CLOSED)
        self.assertEqual(derive(task(pull_request=pr(state="closed"))).state, State.CLOSED)


class UntrustedAndBrokenInput(unittest.TestCase):
    def test_contradictory_reviews_of_one_commit_are_unknown(self):
        s = derive(task(runs=[run("build"), passed(minute=3), failed(minute=4)]))
        self.assertEqual(s.state, State.UNKNOWN)
        self.assertIn(Flag.CONFLICTING_RECORDS, s.flags)

    def test_duplicate_identical_records_are_harmless(self):
        s = derive(task(runs=[run("build"), run("build"), passed(), passed()]))
        self.assertEqual(s.state, State.REVIEWED)

    def test_records_for_another_repository_are_ignored(self):
        other = passed()
        other["repo"] = "example-org/other-repo"
        s = derive(task(runs=[run("build"), other]))
        self.assertEqual(s.state, State.BUILT)
        self.assertIn(Flag.WRONG_REPO_RECORD, s.flags)

    def test_records_for_another_branch_are_ignored(self):
        other = passed()
        other["branch"] = "claude/other"
        s = derive(task(runs=[run("build"), other]))
        self.assertEqual(s.state, State.BUILT)
        self.assertIn(Flag.WRONG_BRANCH_RECORD, s.flags)

    def test_malformed_input_is_unknown_never_an_error(self):
        broken = [
            None,
            [],
            "task",
            {},
            task(repo="not a repo"),
            task(owner=""),
            task(branch={"name": "claude/x", "head": "abc123"}),
            task(branch={"name": "claude/x", "head": "A" * 40}),
            task(issue={"number": 7, "state": "maybe", "timeline": []}),
            task(issue={"number": "7", "state": "open", "timeline": []}),
            task(issue={"number": 7, "state": "open", "timeline": "labeled"}),
            task(issue={"number": 7, "state": "open", "timeline": [{"event": "labeled"}]}),
            task(
                issue={
                    "number": 7,
                    "state": "open",
                    "timeline": [dict(labeled(), at="2026-01-01T10:00:00")],  # no time zone
                }
            ),
            task(runs=[dict(run("build"), step="deploy")]),
            task(runs=[run("review")]),  # a finished review with no verdict
            task(runs=[dict(run("build"), at="yesterday")]),
            task(pull_request=pr(state="open", merged=True, merged_by=OWNER)),
            task(pull_request=dict(pr(), number=True)),
            task(pull_request=dict(pr(), files_complete="no")),
            task(pull_request=pr(checks=[{"name": "lint", "head_sha": A, "status": "done"}])),
            task(pull_request=pr(reviews=[approval(state="LGTM")])),
            task(max_fix_rounds=-1),
            task(paused="no"),
        ]
        for value in broken:
            s = derive(value)
            self.assertEqual(s.state, State.UNKNOWN, value)
            self.assertIn(Flag.INVALID_INPUT, s.flags, value)
            self.assertTrue(s.reasons, value)

    def test_deterministic_and_leaves_its_input_unchanged(self):
        value = reviewed_and_published()
        before = copy.deepcopy(value)
        first, second = derive(value), derive(value)
        self.assertEqual(first, second)
        self.assertEqual(value, before)


class CodexReviewOf107bd35(unittest.TestCase):
    """Regressions for Codex's review of 107bd35 (three blocking findings, one should-fix)."""

    def test_a_review_that_names_no_branch_never_counts(self):
        for branch in (None, "missing"):
            review = passed()
            if branch is None:
                review["branch"] = None
            else:
                del review["branch"]
            s = derive(task(runs=[run("build"), review]))
            self.assertEqual(s.state, State.UNKNOWN, branch)
            self.assertIn(Flag.INVALID_INPUT, s.flags)

    def test_with_no_source_branch_no_review_counts(self):
        s = derive(task(branch=None, runs=[run("build"), passed(), published()], pull_request=pr()))
        self.assertNotEqual(s.state, State.AWAITING_OWNER)
        self.assertIn(Flag.WRONG_BRANCH_RECORD, s.flags)
        self.assertIn(Flag.REVIEW_MISSING, s.flags)

    def test_a_question_for_another_branch_is_ignored(self):
        question = run("question", sha=None, minute=3, branch="claude/other")
        s = derive(task(runs=[run("build"), passed(minute=2), question]))
        self.assertEqual(s.state, State.REVIEWED)
        self.assertIn(Flag.WRONG_BRANCH_RECORD, s.flags)

    def test_a_review_before_authorisation_never_counts(self):
        timeline = [labeled(minute=5)]
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[run("build", minute=1), passed(minute=2), run("build", minute=6)],
            )
        )
        self.assertEqual(s.state, State.BUILT)
        self.assertIn(Flag.RECORD_BEFORE_AUTHORIZATION, s.flags)
        self.assertIn(Flag.REVIEW_MISSING, s.flags)
        self.assertTrue(s.needs_attention)

    def test_a_failed_review_before_authorisation_neither_conflicts_nor_uses_a_round(self):
        timeline = [labeled(minute=4)]
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[failed(minute=1), failed(B, minute=2), run("build", minute=5), passed(A, 6)],
            )
        )
        self.assertEqual(s.state, State.REVIEWED)
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[failed(minute=1), run("build", minute=5), passed(A, 6)],
            )
        )
        self.assertEqual(s.state, State.REVIEWED)

    def test_merge_reviewed_only_before_authorisation_is_unsafe(self):
        timeline = [labeled(minute=5)]
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[run("build", minute=1), passed(minute=2), published(minute=6)],
                pull_request=pr(state="closed", merged=True, merged_by=OWNER),
            )
        )
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_UNREVIEWED, s.flags)

    def test_reauthorising_after_a_question_keeps_the_earlier_work(self):
        timeline = [labeled(minute=0), labeled(kind="authorized", label=None, minute=5)]
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[run("build"), passed(minute=3), run("question", sha=None, minute=4)],
            )
        )
        self.assertEqual(s.state, State.REVIEWED)
        self.assertNotIn(Flag.RECORD_BEFORE_AUTHORIZATION, s.flags)

    def test_withdrawn_authorisation_restarts_the_clock(self):
        timeline = [labeled(minute=0), labeled(kind="unlabeled", minute=4), labeled(minute=5)]
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[run("build"), passed(minute=3), run("build", minute=6)],
            )
        )
        self.assertEqual(s.state, State.BUILT)
        self.assertIn(Flag.RECORD_BEFORE_AUTHORIZATION, s.flags)

    def clinical(self, reviews):
        return derive(
            task(
                runs=[run("build", files=["evidence/x.json"]), passed(), published()],
                pull_request=pr(files=["evidence/x.json"], reviews=reviews),
            )
        )

    def test_simultaneous_approve_and_withdraw_is_not_approved_in_either_order(self):
        approve = approval(minute=6)
        withdraw = approval(minute=6, state="DISMISSED")
        for reviews in ([approve, withdraw], [withdraw, approve]):
            s = self.clinical(reviews)
            self.assertEqual(s.state, State.CLINICAL_REVIEW, [r["state"] for r in reviews])

    def test_another_clinicians_changes_requested_blocks(self):
        other = "example-clinician-2"
        reviews = [approval(minute=6), approval(user=other, minute=7, state="CHANGES_REQUESTED")]
        s = derive(
            task(
                clinicians=[CLINICIAN, other],
                runs=[run("build", files=["evidence/x.json"]), passed(), published()],
                pull_request=pr(files=["evidence/x.json"], reviews=reviews),
            )
        )
        self.assertEqual(s.state, State.CLINICAL_REVIEW)

    def test_a_later_approval_still_replaces_an_earlier_withdrawal(self):
        s = self.clinical([approval(minute=6, state="DISMISSED"), approval(minute=7)])
        self.assertEqual(s.state, State.AWAITING_OWNER)

    def test_unhashable_or_wrongly_typed_choices_are_unknown(self):
        bad = [
            task(runs=[dict(run("build"), step=["build"])]),
            task(runs=[dict(run("build"), step={"build": 1})]),
            task(runs=[dict(run("build"), status=["finished"])]),
            task(runs=[dict(passed(), verdict={"x": 1})]),
            task(issue={"number": 7, "state": ["open"], "timeline": []}),
            task(issue={"number": True, "state": "open", "timeline": []}),
            task(pull_request=pr(state={"open": 1})),
            task(pull_request=pr(draft=[])),
            task(pull_request=pr(reviews=[approval(state=["APPROVED"])])),
            task(pull_request=pr(reviews=[approval(user_type={"a": 1})])),
            task(pull_request=pr(checks=[check("lint", status=["completed"])])),
        ]
        for value in bad:
            s = derive(value)
            self.assertEqual(s.state, State.UNKNOWN, value)
            self.assertIn(Flag.INVALID_INPUT, s.flags, value)

    def test_junk_in_any_field_never_raises(self):
        junk = (None, True, 0, -1, 1.5, "", "x", [], [None], {}, {"a": []}, ["a" * 40])
        base = task(
            runs=[run("build", files=["evidence/x.json"]), passed(), published()],
            pull_request=pr(reviews=[approval()]),
        )

        def paths(value, prefix=()):
            yield prefix
            if isinstance(value, dict):
                for key, item in value.items():
                    yield from paths(item, (*prefix, key))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    yield from paths(item, (*prefix, index))

        count = 0
        for path in list(paths(base)):
            if not path:
                continue
            for value in junk:
                broken = copy.deepcopy(base)
                parent = broken
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = value
                s = derive(broken)  # must not raise
                self.assertIsInstance(s.state, State)
                count += 1
        self.assertGreater(count, 500)


class CodexReviewOfE7833bd(unittest.TestCase):
    """Regressions for Codex's review of e7833bd (two blocking findings)."""

    def test_findings_without_a_known_severity_are_refused(self):
        for finding in (
            {},
            {"severity": None},
            {"severity": "BLOCKING"},
            {"severity": "high"},
            {"severity": ["blocking"]},
            "blocking",
            None,
        ):
            review = run("review", A, 3, verdict="no_blocking_findings", findings=[finding])
            for extra in ((), (published(),)):
                s = derive(
                    task(
                        runs=[run("build"), review, *extra],
                        pull_request=pr() if extra else None,
                    )
                )
                self.assertEqual(s.state, State.UNKNOWN, finding)
                self.assertIn(Flag.INVALID_INPUT, s.flags, finding)

    def test_a_merge_with_a_malformed_finding_is_never_merged(self):
        review = run("review", A, 3, verdict="no_blocking_findings", findings=[{}])
        s = derive(
            task(
                runs=[run("build"), review, published()],
                pull_request=pr(state="closed", merged=True, merged_by=OWNER),
            )
        )
        self.assertEqual(s.state, State.UNKNOWN)

    def test_known_nonblocking_severities_still_pass(self):
        findings = [{"severity": "should_fix"}, {"severity": "note"}]
        review = run("review", A, 3, verdict="no_blocking_findings", findings=findings)
        self.assertEqual(derive(task(runs=[run("build"), review])).state, State.REVIEWED)

    def test_later_work_does_not_answer_a_question(self):
        runs = [
            run("build"),
            run("question", sha=None, minute=3),
            run("build", minute=4),
            passed(A, 5),
        ]
        s = derive(task(runs=runs))
        self.assertEqual(s.state, State.BLOCKED)
        s = derive(task(runs=runs, pull_request=pr()))
        self.assertEqual(s.state, State.BLOCKED)

    def test_only_an_owner_action_after_the_question_answers_it(self):
        runs = [run("build"), run("question", sha=None, minute=3), passed(A, 5)]
        for minute, expected in ((3, State.BLOCKED), (4, State.REVIEWED)):
            timeline = [labeled(minute=0), labeled(kind="authorized", label=None, minute=minute)]
            s = derive(task(issue={"number": 7, "state": "open", "timeline": timeline}, runs=runs))
            self.assertEqual(s.state, expected, minute)
        # Someone else's authorisation answers nothing.
        timeline = [labeled(minute=0), labeled(STRANGER, kind="authorized", label=None, minute=4)]
        s = derive(task(issue={"number": 7, "state": "open", "timeline": timeline}, runs=runs))
        self.assertEqual(s.state, State.BLOCKED)

    def test_same_instant_records_give_the_same_state_in_any_order(self):
        cases = [
            [run("build", minute=3), run("question", sha=None, minute=3)],
            [passed(A, 3), run("failure", sha=None, minute=3)],
            [passed(A, 3), run("question", sha=None, minute=3), run("failure", sha=None, minute=3)],
        ]
        for records in cases:
            states = set()
            for order in itertools.permutations(records):
                states.add(derive(task(runs=[run("build"), *order])).state)
            self.assertEqual(len(states), 1, [r["step"] for r in records])
        self.assertEqual(
            derive(
                task(runs=[run("build"), passed(A, 3), run("failure", sha=None, minute=3)])
            ).state,
            State.FAILED,
        )


class CodexReviewOfFfa417f(unittest.TestCase):
    """Regressions for Codex's review of ffa417f (one blocking finding, one should-fix)."""

    def exhausted_then(self, *later, timeline=None, **over):
        # Commits A and B both fail review: two failed rounds with one allowed.
        runs = [run("build"), failed(A, 3), run("build", B, 4), failed(B, 5), *later]
        return derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline or [labeled()]},
                runs=runs,
                **over,
            )
        )

    def test_more_agent_work_does_not_clear_exhausted_fix_rounds(self):
        later = [
            (run("build", C, 6),),
            (run("build", C, 6), passed(C, 7)),
            (run("build", C, 6), passed(C, 7), dict(published(C, 8))),
        ]
        for records in later:
            over = {"branch": {"name": "claude/x", "head": C}}
            if len(records) == 3:
                over["pull_request"] = pr(head=C)
            s = self.exhausted_then(*records, **over)
            self.assertEqual(s.state, State.AWAITING_OWNER, [r["step"] for r in records])
            self.assertIn(Flag.FIX_ROUNDS_EXHAUSTED, s.flags)

    def test_the_owner_authorising_again_starts_a_new_budget(self):
        timeline = [labeled(minute=0), labeled(kind="authorized", label=None, minute=6)]
        s = self.exhausted_then(
            run("build", C, 7),
            passed(C, 8),
            timeline=timeline,
            branch={"name": "claude/x", "head": C},
        )
        self.assertEqual(s.state, State.REVIEWED)
        self.assertNotIn(Flag.FIX_ROUNDS_EXHAUSTED, s.flags)

    def test_an_owner_action_before_the_last_failed_round_doesnt_reset_it(self):
        timeline = [labeled(minute=0), labeled(kind="authorized", label=None, minute=4)]
        s = self.exhausted_then(
            run("build", C, 6),
            failed(C, 7),
            run("build", D, 8),
            passed(D, 9),
            timeline=timeline,
            branch={"name": "claude/x", "head": D},
        )
        self.assertEqual(s.state, State.AWAITING_OWNER)

    def test_identifiers_with_a_trailing_newline_are_refused(self):
        bad = [
            task(branch={"name": "claude/x", "head": A + "\n"}),
            task(runs=[run("build", A + "\n")]),
            task(repo=REPO + "\n"),
            task(owner=OWNER + "\n"),
            task(pull_request=pr(head=A + "\n")),
            task(pull_request=pr(checks=[check("lint", A + "\n"), check("test")])),
        ]
        for value in bad:
            s = derive(value)
            self.assertEqual(s.state, State.UNKNOWN, value)
            self.assertIn(Flag.INVALID_INPUT, s.flags)


class CodexReviewOfBc6fe45(unittest.TestCase):
    """Regressions for Codex's review of bc6fe45 (one blocking finding, one should-fix)."""

    SAFETY = ("clinicians", "clinical_paths", "required_checks", "max_fix_rounds", "paused")

    def test_a_missing_safety_setting_is_unknown_never_a_weaker_gate(self):
        for key in self.SAFETY:
            value = reviewed_and_published()
            del value[key]
            s = derive(value)
            self.assertEqual(s.state, State.UNKNOWN, key)
            self.assertIn(Flag.INVALID_INPUT, s.flags, key)

    def test_required_checks_must_name_at_least_one(self):
        s = derive(reviewed_and_published() | {"required_checks": []})
        self.assertEqual(s.state, State.UNKNOWN)

    def test_explicit_empty_clinical_paths_are_allowed(self):
        s = derive(reviewed_and_published() | {"clinical_paths": []})
        self.assertEqual(s.state, State.AWAITING_OWNER)

    def test_a_commit_on_the_branch_without_authorisation_is_unsafe(self):
        s = derive(task(issue={"number": 7, "state": "open", "timeline": []}, runs=[]))
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)
        self.assertTrue(s.needs_attention)

    def test_an_empty_branch_without_authorisation_is_still_proposed(self):
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": []},
                branch={"name": "claude/x", "head": None},
                runs=[],
            )
        )
        self.assertEqual(s.state, State.PROPOSED)


class CodexReviewOf014006c(unittest.TestCase):
    """Regression for Codex's review of 014006c (blocking): a missing field must never weaken
    a gate. Every field the model decides with is required; only a run's files are optional."""

    def clinical_pr(self):
        return task(
            runs=[run("build"), passed(), published()],  # the run records name no files
            pull_request=pr(files=["evidence/x.json"]),
        )

    def test_missing_pr_files_cannot_skip_clinical_approval(self):
        self.assertEqual(derive(self.clinical_pr()).state, State.CLINICAL_REVIEW)
        value = self.clinical_pr()
        del value["pull_request"]["files"]
        s = derive(value)
        self.assertEqual(s.state, State.UNKNOWN)
        self.assertIn(Flag.INVALID_INPUT, s.flags)

    def test_every_deciding_field_is_required(self):
        def without(path):
            value = reviewed_and_published(reviews=[approval()])
            value["runs"].append(passed(A, 3))
            parent = value
            for key in path[:-1]:
                parent = parent[key]
            del parent[path[-1]]
            return value

        paths = [
            ("runs",),
            ("issue", "timeline"),
            ("runs", 0, "status"),  # a build
            ("runs", 1, "status"),  # a review
            ("runs", 1, "findings"),
            ("pull_request", "files"),
            ("pull_request", "merged"),
            ("pull_request", "draft"),
            ("pull_request", "reviews"),
            ("pull_request", "checks"),
            ("pull_request", "reviews", 0, "user_type"),
        ]
        for path in paths:
            s = derive(without(path))
            self.assertEqual(s.state, State.UNKNOWN, path)
            self.assertIn(Flag.INVALID_INPUT, s.flags, path)

    def test_a_merged_pr_reported_without_merged_is_not_closed(self):
        value = task(
            runs=[run("build")],
            pull_request=pr(state="closed", merged=True, merged_by=STRANGER),
        )
        self.assertEqual(derive(value).state, State.UNSAFE)
        del value["pull_request"]["merged"]
        self.assertEqual(derive(value).state, State.UNKNOWN)

    def test_a_bot_review_without_user_type_never_counts_as_a_clinician(self):
        value = self.clinical_pr()
        value["pull_request"]["reviews"] = [approval()]
        self.assertEqual(derive(value).state, State.AWAITING_OWNER)
        del value["pull_request"]["reviews"][0]["user_type"]
        self.assertEqual(derive(value).state, State.UNKNOWN)

    def test_a_runs_own_files_stay_optional(self):
        record = run("build")
        self.assertNotIn("files", record)
        self.assertEqual(derive(task(runs=[record])).state, State.BUILT)


class CodexReviewOfE4d1a06(unittest.TestCase):
    """Regressions for Codex's review of e4d1a06: an absent key is a gap in the data, never
    evidence that nothing exists. Null stays allowed where the contract allows it."""

    def unsafe_merge(self):
        return task(
            runs=[run("build"), passed()],
            pull_request=pr(state="closed", merged=True, merged_by=STRANGER),
        )

    def test_dropping_a_merged_pr_cannot_hide_an_unsafe_merge(self):
        self.assertEqual(derive(self.unsafe_merge()).state, State.UNSAFE)
        value = self.unsafe_merge()
        del value["pull_request"]
        s = derive(value)
        self.assertEqual(s.state, State.UNKNOWN)
        self.assertIn(Flag.INVALID_INPUT, s.flags)
        self.assertEqual(derive(self.unsafe_merge() | {"pull_request": None}).state, State.REVIEWED)

    def test_a_missing_branch_or_head_is_unknown_but_null_is_allowed(self):
        no_auth = {"issue": {"number": 7, "state": "open", "timeline": []}, "runs": []}
        self.assertEqual(derive(task(**no_auth)).state, State.UNSAFE)  # unauthorised commit
        value = task(**no_auth)
        del value["branch"]["head"]
        self.assertEqual(derive(value).state, State.UNKNOWN)
        value = task(**no_auth)
        del value["branch"]
        self.assertEqual(derive(value).state, State.UNKNOWN)
        null_head = task(branch={"name": "claude/x", "head": None}, **no_auth)
        self.assertEqual(derive(null_head).state, State.PROPOSED)
        self.assertEqual(derive(task(branch=None, **no_auth)).state, State.PROPOSED)

    def test_an_unlabeled_event_without_its_label_cannot_hide_a_withdrawal(self):
        removal = labeled(kind="unlabeled", minute=1)
        value = task(issue={"number": 7, "state": "open", "timeline": [labeled(), removal]})
        self.assertEqual(derive(value).state, State.UNSAFE)  # withdrawn, yet work exists
        for bad in ("missing", None, ""):
            broken = copy.deepcopy(removal)
            if bad == "missing":
                del broken["label"]
            else:
                broken["label"] = bad
            value = task(issue={"number": 7, "state": "open", "timeline": [labeled(), broken]})
            s = derive(value)
            self.assertEqual(s.state, State.UNKNOWN, bad)

    def test_merged_by_and_check_conclusion_must_be_present(self):
        value = reviewed_and_published()
        del value["pull_request"]["merged_by"]
        self.assertEqual(derive(value).state, State.UNKNOWN)
        value = reviewed_and_published()
        del value["pull_request"]["checks"][0]["conclusion"]
        self.assertEqual(derive(value).state, State.UNKNOWN)
        pending = reviewed_and_published(
            checks=[check("lint", status="in_progress", conclusion=None), check("test")]
        )
        self.assertEqual(derive(pending).state, State.PUBLISHED)


class CodexReviewOf124d733(unittest.TestCase):
    """Regression for the should-fix in Codex's review of 124d733: a moved PR head must be
    reported as UNSAFE / HEAD_MISMATCH even when a question or a failure is also open."""

    def moved(self, *later, timeline=None):
        # Commit A was reviewed and published as PR #12, whose head is now B.
        return derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline or [labeled()]},
                branch={"name": "claude/x", "head": B},
                runs=[run("build"), passed(), published(), *later],
                pull_request=pr(head=B),
            )
        )

    def assert_unsafe(self, s):
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.HEAD_MISMATCH, s.flags)
        self.assertTrue(s.needs_attention)

    def test_an_open_question_does_not_hide_a_moved_head(self):
        self.assert_unsafe(self.moved(run("question", sha=None, minute=5)))

    def test_a_failure_does_not_hide_a_moved_head(self):
        self.assert_unsafe(self.moved(run("failure", sha=None, minute=5)))

    def test_a_question_and_a_failure_together_do_not_hide_it(self):
        self.assert_unsafe(
            self.moved(run("question", sha=None, minute=5), run("failure", sha=None, minute=5))
        )

    def test_a_publish_from_before_a_reauthorisation_still_counts(self):
        timeline = [labeled(minute=0), labeled(kind="unlabeled", minute=5), labeled(minute=6)]
        self.assert_unsafe(self.moved(timeline=timeline))

    def test_the_stop_switch_does_not_hide_it_either(self):
        value = task(
            paused=True,
            branch={"name": "claude/x", "head": B},
            runs=[run("build"), passed(), published(), run("question", sha=None, minute=5)],
            pull_request=pr(head=B),
        )
        self.assert_unsafe(derive(value))

    def test_without_a_moved_head_the_question_still_blocks(self):
        s = derive(
            task(
                runs=[run("build"), passed(), published(), run("question", sha=None, minute=5)],
                pull_request=pr(),
            )
        )
        self.assertEqual(s.state, State.BLOCKED)
        self.assertNotIn(Flag.HEAD_MISMATCH, s.flags)


class Fixtures(unittest.TestCase):
    """Self-contained JSON examples, also meant for phase A3's screens."""

    def test_each_fixture_derives_its_expected_state(self):
        files = sorted(FIXTURES.glob("*.json"))
        self.assertGreaterEqual(len(files), 4)
        for path in files:
            data = json.loads(path.read_text(encoding="utf-8"))
            s = derive(data["task"])
            self.assertEqual(s.state.value, data["expected"]["state"], path.name)
            for flag in data["expected"].get("flags", []):
                self.assertIn(Flag(flag), s.flags, path.name)


class NotKnown(unittest.TestCase):
    """A5a: what the fetcher can't read is null ("not known"), never left out. It is never read
    as clean, and never hides what is known (Codex's reviews of b24ac2d, 198a66e, 3f7d3c2)."""

    def test_an_unidentified_merger_is_unsafe(self):
        s = derive(
            task(
                runs=[run("build"), passed(), published()],
                pull_request=pr(state="closed", merged=True, merged_by=None),
            )
        )
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGER_UNKNOWN, s.flags)
        self.assertNotIn(Flag.UNAUTHORIZED_MERGE, s.flags)  # it doesn't claim who

    def test_no_linked_issue_is_calm_when_open_and_still_judged_when_merged(self):
        open_pr = derive(task(issue=None, pull_request=pr()))
        self.assertEqual(open_pr.state, State.NOT_LINKED)
        self.assertIn(Flag.ISSUE_NOT_LINKED, open_pr.flags)
        self.assertNotIn(Flag.UNAUTHORIZED_WORK, open_pr.flags)
        merged = derive(
            task(issue=None, pull_request=pr(state="closed", merged=True, merged_by="someone"))
        )
        self.assertEqual(merged.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_MERGE, merged.flags)
        self.assertIn(Flag.ISSUE_NOT_LINKED, merged.flags)
        self.assertNotIn(Flag.UNAUTHORIZED_WORK, merged.flags)  # not claimed: not known

    def test_an_absent_issue_key_is_still_unreadable(self):
        value = task()
        del value["issue"]
        self.assertEqual(derive(value).state, State.UNKNOWN)

    def test_a_partial_file_list_keeps_its_known_clinical_paths(self):
        merged = derive(
            task(
                runs=[run("build"), passed(), published()],
                pull_request=pr(
                    state="closed",
                    merged=True,
                    merged_by=OWNER,
                    files=["evidence/x.json"],
                    files_complete=False,
                ),
            )
        )
        self.assertIn(Flag.CLINICAL, merged.flags)  # known clinical: claimed
        self.assertIn(Flag.FILES_UNVERIFIED, merged.flags)
        self.assertIn(Flag.MERGED_WITHOUT_CLINICIAN, merged.flags)
        self.assertEqual(merged.state, State.UNSAFE)
        open_partial = derive(
            dict(
                reviewed_and_published(),
                pull_request=pr(files=["site/x.html"], files_complete=False),
            )
        )
        # The rest may be clinical: it waits for a clinician, without claiming CLINICAL.
        self.assertEqual(open_partial.state, State.CLINICAL_REVIEW)
        self.assertNotIn(Flag.CLINICAL, open_partial.flags)


class Coverage(unittest.TestCase):
    def test_every_state_is_reachable_and_attention_states_are_sensible(self):
        seen = set()
        for case in (
            task(issue={"number": 7, "state": "open", "timeline": []}, branch=None, runs=[]),
            task(branch=None, runs=[]),
            task(runs=[]),
            task(),
            task(runs=[run("build"), run("review", minute=3, status="started")]),
            task(runs=[run("build"), failed()]),
            task(runs=[run("build"), passed()]),
            reviewed_and_published(checks=[check("lint")]),
            task(
                runs=[run("build"), passed(), published()],
                pull_request=pr(files=["evidence/x.json"]),
            ),
            reviewed_and_published(),
            task(
                runs=[run("build"), passed(), published()],
                pull_request=pr(state="closed", merged=True, merged_by=OWNER),
            ),
            task(runs=[run("build"), run("question", sha=None, minute=3)]),
            task(runs=[run("build"), run("failure", sha=None, minute=3)]),
            task(paused=True),
            task(pull_request=pr(state="closed")),
            task(runs=[run("build"), passed(A), published(A)], pull_request=pr(head=B)),
            task(issue=None, pull_request=pr()),
            None,
        ):
            seen.add(derive(case).state)
        self.assertEqual(seen, set(State))
        self.assertNotIn(State.MERGED, ATTENTION_STATES)
        self.assertIn(State.UNSAFE, ATTENTION_STATES)


if __name__ == "__main__":
    unittest.main()
