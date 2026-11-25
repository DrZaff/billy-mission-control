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
        "from_fork": False,
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
        timeline = [
            labeled(minute=0),
            {"event": "closed", "actor": OWNER, "at": t(20), "closer_pr": 12},
            labeled(minute=30, kind="unlabeled"),
        ]
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

    def test_an_approval_is_shown_while_checks_are_still_failing(self):
        # Codex's review of 28546f5: the checks gate returned before the approval was judged.
        value = task(
            runs=[run("build"), passed(), published()],
            pull_request=pr(
                files=["evidence/a.json"],
                checks=[check("lint", A), check("test", A, conclusion="failure")],
                reviews=[approval()],
            ),
        )
        s = derive(value)
        self.assertEqual(s.state, State.PUBLISHED)
        self.assertIn(Flag.CLINICIAN_APPROVED, s.flags)
        self.assertNotIn(Flag.CLINICAL_APPROVAL_MISSING, s.flags)
        value["pull_request"]["reviews"] = []
        self.assertIn(Flag.CLINICAL_APPROVAL_MISSING, derive(value).flags)

    def test_unverifiable_authorisation_never_discards_billys_review_records(self):
        # Codex's review of b7d568e (blocking): a merged PR with no issue lost every record,
        # and so was said never to have passed review.
        reviewed = task(
            issue=None,
            runs=[run("build"), passed(), published()],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
        )
        s = derive(reviewed)
        self.assertEqual(s.state, State.MERGED)
        self.assertNotIn(Flag.MERGED_UNREVIEWED, s.flags)
        self.assertIn(Flag.AUTHORIZATION_UNVERIFIED, s.flags)
        unreviewed = copy.deepcopy(reviewed)
        unreviewed["runs"] = [run("build")]
        s = derive(unreviewed)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_UNREVIEWED, s.flags)  # still caught
        late = copy.deepcopy(reviewed)
        late["runs"] = [run("build"), passed(minute=30)]  # after the merge: never counts
        self.assertIn(Flag.MERGED_UNREVIEWED, derive(late).flags)

    def test_files_recorded_after_the_merge_never_make_it_clinical(self):
        # Codex's review of c5ccf49 (blocking).
        value = task(
            runs=[
                run("build"),
                passed(),
                published(),
                run("build", minute=30, files=["evidence/a.json"]),
            ],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
        )
        s = derive(value)
        self.assertEqual(s.state, State.MERGED)
        self.assertNotIn(Flag.CLINICAL, s.flags)
        value["runs"][-1]["at"] = t(10)  # before the merge: it counts
        self.assertIn(Flag.CLINICAL, derive(value).flags)

    def test_a_closed_issue_ends_the_authorisation_of_an_open_pr(self):
        # Codex's review of 0cf099c (blocking): closing the issue left the open PR eligible for
        # AWAITING_OWNER, beside an alert saying the issue was closed.
        ready = task(runs=[run("build"), passed(), published()], pull_request=pr())
        self.assertEqual(derive(ready).state, State.AWAITING_OWNER)
        # Closed after the authorisation: withdrawn, as removing the label would be (Fable's
        # audit of ca7faa9: one rule for an open PR and its merge).
        closed = copy.deepcopy(ready)
        closed["issue"]["state"] = "closed"
        closed["issue"]["timeline"].append({"event": "closed", "actor": OWNER, "at": t(1)})
        s = derive(closed)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)
        self.assertIn(Flag.ISSUE_CLOSED_PR_OPEN, s.flags)
        self.assertTrue(s.needs_attention)
        # Authorised after its closing: not on the way to a merge until it is reopened.
        closed["issue"]["timeline"].append({"event": "authorized", "actor": OWNER, "at": t(1)})
        closed["issue"]["timeline"][1]["at"] = t(0)
        s = derive(closed)
        self.assertEqual(s.state, State.NOT_LINKED)
        self.assertIn(Flag.ISSUE_CLOSED_PR_OPEN, s.flags)
        self.assertIn(Flag.CHECKS_PASSED, s.flags)  # GitHub's own results are still shown
        self.assertTrue(s.needs_attention)
        self.assertIn("reopen it to go on", s.reasons[0])

    def test_a_fork_pr_is_never_credited_with_billys_records(self):
        # Codex's review of 9dbb868 (blocking): a fork PR reached AWAITING_OWNER.
        ready = task(runs=[run("build"), passed(), published()], pull_request=pr())
        self.assertEqual(derive(ready).state, State.AWAITING_OWNER)
        fork = copy.deepcopy(ready)
        fork["pull_request"]["from_fork"] = True
        s = derive(fork)
        self.assertEqual(s.state, State.NOT_LINKED)
        self.assertIn(Flag.FROM_FORK, s.flags)
        self.assertIsNone(s.reviewed_sha)
        self.assertTrue(s.needs_attention)
        merged = copy.deepcopy(fork)
        merged["pull_request"].update(state="closed", merged=True, merged_by=OWNER)
        merged["pull_request"]["merged_at"] = "2026-12-31T00:00:00+00:00"
        s = derive(merged)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_UNREVIEWED, s.flags)  # Billy never reviewed fork work

    def test_clinical_known_makes_a_change_clinical(self):
        value = task(
            runs=[run("build"), passed(), published()],
            pull_request=pr(clinical_known=True),  # only app.py is listed
        )
        self.assertIn(Flag.CLINICAL, derive(value).flags)
        value["pull_request"]["clinical_known"] = "yes"
        self.assertEqual(derive(value).state, State.UNKNOWN)

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

    def test_a_merged_prs_checks_are_never_judged(self):
        # Results carry no time, so a later run could rewrite the verdict either way (Fable's
        # review of 0cf099c).
        s = derive(self.merged(checks=[check("lint"), check("test", conclusion="failure")]))
        self.assertEqual(s.state, State.MERGED)
        judged = {Flag.CHECKS_FAILING, Flag.CHECKS_PASSED, Flag.CHECKS_UNVERIFIED}
        self.assertFalse(s.flags & judged)
        self.assertFalse(s.needs_attention)


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

    def test_no_linked_issue_is_an_alert_when_open_and_still_judged_when_merged(self):
        open_pr = derive(task(issue=None, pull_request=pr()))
        self.assertEqual(open_pr.state, State.NOT_LINKED)
        self.assertTrue(open_pr.needs_attention)  # an alert, not UNSAFE (audit of 8c62413)
        self.assertIn(Flag.ISSUE_NOT_LINKED, open_pr.flags)
        self.assertNotIn(Flag.UNAUTHORIZED_WORK, open_pr.flags)
        merged = derive(
            task(issue=None, pull_request=pr(state="closed", merged=True, merged_by="someone"))
        )
        self.assertEqual(merged.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_MERGE, merged.flags)
        self.assertIn(
            Flag.AUTHORIZATION_UNVERIFIED, merged.flags
        )  # calm, not ISSUE_NOT_LINKED (28546f5)
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


class FableReviewOf0cf099c(unittest.TestCase):
    """An independent hostile review of the task model, before the next formal review."""

    def test_conflicting_records_never_hide_a_known_unsafe_merge(self):
        value = task(
            runs=[run("build"), passed(), failed(minute=5)],
            pull_request=pr(state="closed", merged=True, merged_by=STRANGER, merged_at=t(30)),
        )
        s = derive(value)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_MERGE, s.flags)
        self.assertIn(Flag.CONFLICTING_RECORDS, s.flags)
        self.assertEqual((s.head_sha, s.pr), (A, 12))

    def test_a_conflict_on_an_older_commit_leaves_the_head_judged(self):
        value = task(
            runs=[
                run("build", B),
                passed(B, 2),
                failed(B, 3),
                run("build", A, 4),
                passed(A, 5),
                published(A, 6),
            ],
            pull_request=pr(),
        )
        s = derive(value)
        self.assertEqual(s.state, State.AWAITING_OWNER)
        self.assertIn(Flag.CONFLICTING_RECORDS, s.flags)
        conflicted_head = copy.deepcopy(value)
        conflicted_head["runs"].append(failed(A, 7))
        conflicted_head["max_fix_rounds"] = 5  # so the conflict itself decides
        s = derive(conflicted_head)
        self.assertEqual(s.state, State.UNKNOWN)
        self.assertEqual(s.pr, 12)

    def test_github_gates_hold_on_every_path_with_records(self):
        failing = [check("lint", conclusion="failure"), check("test")]
        cases = {
            "fix rounds": [run("build"), failed(B, 3), failed(C, 4), passed(A, 5)],
            "changes needed": [run("build"), failed(A, 3)],
            "built": [run("build")],
            "blocked": [run("build"), run("question", sha=None, minute=3)],
            "failed": [run("build"), run("failure", minute=5)],
        }
        for name, runs in cases.items():
            with self.subTest(name):
                s = derive(
                    task(runs=runs, pull_request=pr(checks=failing, files=("evidence/a.json",)))
                )
                self.assertIn(Flag.CHECKS_FAILING, s.flags)
                self.assertIn(Flag.CLINICAL_APPROVAL_MISSING, s.flags)
                approved = task(
                    runs=runs,
                    pull_request=pr(files=("evidence/a.json",), reviews=[approval()]),
                )
                self.assertIn(Flag.CLINICIAN_APPROVED, derive(approved).flags)

    def test_the_stop_switch_never_hides_what_needs_you(self):
        for runs in (
            [run("build"), run("failure", minute=5)],
            [run("build"), run("question", sha=None, minute=3)],
            [run("build"), passed(), published()],
        ):
            s = derive(task(paused=True, runs=runs, pull_request=pr()))
            self.assertEqual(s.state, State.PAUSED)
            self.assertIsNotNone(s.would_be)
            self.assertTrue(s.needs_attention, runs[-1]["step"])

    def test_a_closed_unlinked_or_fork_pr_is_calm(self):
        for over in ({"issue": None}, {}):
            value = task(runs=None, pull_request=pr(state="closed", from_fork=not over), **over)
            s = derive(value)
            self.assertEqual(s.state, State.CLOSED)
            self.assertFalse(s.needs_attention, over)

    def test_records_after_a_merge_raise_no_alert(self):
        value = task(
            runs=[run("build"), passed(), published(), run("build", C, 59, branch="claude/other")],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(30)),
        )
        s = derive(value)
        self.assertEqual(s.state, State.MERGED)
        self.assertNotIn(Flag.WRONG_BRANCH_RECORD, s.flags)
        self.assertFalse(s.needs_attention)

    def test_an_outstanding_changes_request_blocks_approval(self):
        value = task(
            clinicians=[CLINICIAN, "clinician-two"],
            runs=[run("build"), passed(), published()],
            pull_request=pr(
                files=("evidence/a.json",),
                reviews=[
                    approval("clinician-two", sha=B, state="CHANGES_REQUESTED", minute=4),
                    approval(minute=6),
                ],
            ),
        )
        s = derive(value)
        self.assertNotIn(Flag.CLINICIAN_APPROVED, s.flags)
        self.assertEqual(s.state, State.CLINICAL_REVIEW)
        value["pull_request"]["reviews"].append(approval("clinician-two", minute=7))
        self.assertEqual(derive(value).state, State.AWAITING_OWNER)

    def test_a_withdrawn_authorisation_says_so(self):
        timeline = [labeled(), labeled(kind="unlabeled", minute=20)]
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": timeline},
                runs=[run("build"), passed(), published()],
                pull_request=pr(),
            )
        )
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)
        self.assertIn("withdrawn", s.reasons[0])


class CodexReviewOf84df535(unittest.TestCase):
    def test_a_conflicted_commit_uses_a_fix_round(self):
        value = task(
            runs=[
                run("build"),
                failed(B, 3),
                passed(C, 4),
                failed(C, 5),
                passed(A, 6),
                published(A, 7),
            ],
            pull_request=pr(),
        )
        s = derive(value)
        self.assertEqual(s.state, State.AWAITING_OWNER)
        self.assertIn(Flag.FIX_ROUNDS_EXHAUSTED, s.flags)  # never "ready to merge"

    def test_a_merged_commit_with_disagreeing_reviews_says_so(self):
        value = task(
            runs=[run("build"), passed(), failed(minute=4), published(minute=5)],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(30)),
        )
        s = derive(value)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.CONFLICTING_RECORDS, s.flags)
        self.assertNotIn(Flag.MERGED_UNREVIEWED, s.flags)
        self.assertIn("disagree", s.reasons[0])


class FableReviewOf4945de9(unittest.TestCase):
    def test_a_moved_head_is_never_hidden_by_a_closed_or_unlinked_issue(self):
        # Finding 7.
        moved = task(runs=[run("build"), passed(), published(B)], pull_request=pr())
        for over in (
            {"issue": {"number": 7, "state": "closed", "timeline": [labeled()]}},
            {"issue": None},
        ):
            s = derive(dict(moved, **over))
            self.assertEqual(s.state, State.UNSAFE, over)
            self.assertIn(Flag.HEAD_MISMATCH, s.flags)

    def test_disagreeing_records_need_attention(self):
        # Finding 8.
        value = task(
            runs=[
                run("build", B),
                passed(B, 2),
                failed(B, 3),
                run("build", A, 4),
                passed(A, 5),
                published(A, 6),
            ],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(30)),
        )
        s = derive(value)
        self.assertEqual(s.state, State.MERGED)
        self.assertIn(Flag.CONFLICTING_RECORDS, s.flags)
        self.assertTrue(s.needs_attention)

    def test_a_closed_pr_with_unread_parts_is_calm(self):
        # Finding 9.
        closed = dict(pr(state="closed"), files=None, reviews=None, checks=None)
        s = derive(task(runs=None, pull_request=closed))
        self.assertEqual(s.state, State.CLOSED)
        self.assertFalse(s.needs_attention)


class CodexReviewOf0e2139f(unittest.TestCase):
    def test_a_dismissal_that_cant_be_placed_makes_an_approval_uncertain(self):
        # Blocking: a clinician's changes request dismissed after the merge blocked it then.
        reviews = [
            approval("clinician-two", sha=B, state="DISMISSED", minute=4),
            approval(minute=6),
        ]
        value = task(
            clinicians=[CLINICIAN, "clinician-two"],
            runs=[run("build"), passed(), published()],
            pull_request=pr(
                state="closed",
                merged=True,
                merged_by=OWNER,
                merged_at=t(30),
                files=("evidence/a.json",),
                reviews=reviews,
            ),
        )
        s = derive(value)
        self.assertNotIn(Flag.CLINICIAN_APPROVED, s.flags)
        self.assertIn(Flag.DISMISSAL_UNPLACED, s.flags)
        self.assertTrue(s.needs_attention)
        # Without the approval it is certain: a dismissed review is never an approval.
        value["pull_request"]["reviews"] = reviews[:1]
        s = derive(value)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_WITHOUT_CLINICIAN, s.flags)

    def test_a_closed_pr_keeps_its_flags_without_alerts(self):
        closed = dict(pr(state="closed"), files=None)
        s = derive(task(runs=None, pull_request=closed))
        self.assertEqual(s.state, State.CLOSED)
        self.assertIn(Flag.FILES_UNVERIFIED, s.flags)  # still said
        self.assertFalse(s.needs_attention)  # never an alert


class AuditOf42a3721(unittest.TestCase):
    def merged(self, reviews, clinicians=(CLINICIAN,)):
        return derive(
            task(
                clinicians=list(clinicians),
                runs=[run("build"), passed(), published()],
                pull_request=pr(
                    state="closed",
                    merged=True,
                    merged_by=OWNER,
                    merged_at=t(30),
                    files=("evidence/a.json",),
                    reviews=reviews,
                ),
            )
        )

    def test_a_changes_request_in_force_decides_whatever_was_dismissed(self):
        s = self.merged(
            [approval(state="DISMISSED", minute=4), approval(state="CHANGES_REQUESTED", minute=6)]
        )
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_WITHOUT_CLINICIAN, s.flags)
        s = self.merged(
            [
                approval("clinician-two", state="DISMISSED", minute=4),
                approval(state="CHANGES_REQUESTED", minute=6),
            ],
            clinicians=(CLINICIAN, "clinician-two"),
        )
        self.assertIn(Flag.MERGED_WITHOUT_CLINICIAN, s.flags)

    def test_a_later_approval_decides_whatever_was_dismissed(self):
        s = self.merged([approval(state="DISMISSED", minute=4), approval(minute=6)])
        self.assertEqual(s.state, State.MERGED)
        self.assertIn(Flag.CLINICIAN_APPROVED, s.flags)
        self.assertFalse(s.needs_attention)

    def test_no_clinical_paths_means_no_file_alert(self):
        value = task(runs=None, clinical_paths=[], pull_request=dict(pr(), files=None))
        s = derive(value)
        self.assertNotIn(Flag.FILES_UNVERIFIED, s.flags)


class AuditOf28009de(unittest.TestCase):
    def test_a_later_approval_of_another_commit_never_masks_a_dismissal_of_the_head(self):
        value = task(
            clinicians=[CLINICIAN, "clinician-two"],
            runs=[run("build"), passed(), published()],
            pull_request=pr(
                state="closed",
                merged=True,
                merged_by=OWNER,
                merged_at=t(30),
                files=("evidence/a.json",),
                reviews=[
                    approval("clinician-two", minute=4),
                    approval(state="DISMISSED", minute=7),
                    approval(sha=B, minute=8),
                ],
            ),
        )
        s = derive(value)
        self.assertNotIn(Flag.CLINICIAN_APPROVED, s.flags)
        self.assertIn(Flag.DISMISSAL_UNPLACED, s.flags)


class AuditOf0585599(unittest.TestCase):
    def test_a_certain_missing_approval_is_unsafe_whatever_was_dismissed(self):
        value = task(
            clinicians=[CLINICIAN, "clinician-two"],
            runs=[run("build"), passed(), published()],
            pull_request=pr(
                state="closed",
                merged=True,
                merged_by=OWNER,
                merged_at=t(30),
                files=("evidence/a.json",),
                reviews=[
                    approval(state="CHANGES_REQUESTED", minute=6),
                    approval(sha=B, minute=8),
                    approval("clinician-two", state="DISMISSED", minute=8),
                ],
            ),
        )
        s = derive(value)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_WITHOUT_CLINICIAN, s.flags)
        self.assertNotIn(Flag.DISMISSAL_UNPLACED, s.flags)


class AuditOfEa9b32a(unittest.TestCase):
    def merged(self, reviews):
        return derive(
            task(
                runs=[run("build"), passed(), published()],
                pull_request=pr(
                    state="closed",
                    merged=True,
                    merged_by=OWNER,
                    merged_at=t(30),
                    files=("evidence/a.json",),
                    reviews=reviews,
                ),
            )
        )

    def test_a_review_in_the_merges_own_second_is_never_counted_as_before_it(self):
        s = self.merged([approval(minute=30)])  # may have come just after the merge
        self.assertNotIn(Flag.CLINICIAN_APPROVED, s.flags)
        self.assertIn(Flag.DISMISSAL_UNPLACED, s.flags)
        s = self.merged([approval(minute=6), approval(state="CHANGES_REQUESTED", minute=30)])
        self.assertNotIn(Flag.CLINICIAN_APPROVED, s.flags)
        self.assertIn(Flag.DISMISSAL_UNPLACED, s.flags)

    def test_a_comment_in_the_merges_own_second_changes_nothing(self):
        s = self.merged([approval(minute=6), approval(state="COMMENTED", minute=30)])
        self.assertIn(Flag.CLINICIAN_APPROVED, s.flags)


class AuditOfAd78f34(unittest.TestCase):
    def merged(self, **over):
        value = task(
            runs=[run("build"), passed(), published()],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
        )
        value.update(over)
        return derive(value)

    def test_a_pass_in_the_merges_own_second_never_reviews_the_merge(self):
        s = self.merged(runs=[run("build"), passed(minute=20), published()])
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.MERGED_UNREVIEWED, s.flags)
        self.assertEqual(self.merged().state, State.MERGED)  # a pass before it still counts

    def test_a_label_in_the_merges_own_second_never_authorises_it(self):
        s = self.merged(
            issue={"number": 7, "state": "closed", "timeline": [labeled(minute=20)]},
            runs=[run("build", minute=20), passed(minute=20), published(minute=20)],
        )
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)


class AuditOf8c62413(unittest.TestCase):
    def test_unread_reviews_on_known_clinical_files_always_need_a_look(self):
        # Audit of 8c62413: every earlier case also carried FILES_UNVERIFIED, which hid this.
        from mission_control import views

        merged = pr(
            files=("evidence/x.json",),
            state="closed",
            merged=True,
            merged_by=OWNER,
            merged_at=t(20),
        )
        merged["reviews"] = None
        opened = pr(files=("evidence/x.json",))
        opened["reviews"] = None
        for name, value in (("merged", merged), ("open", opened)):
            with self.subTest(name):
                s = derive(task(runs=[run("build"), passed(), published()], pull_request=value))
                self.assertIn(Flag.REVIEWS_UNVERIFIED, s.flags)
                self.assertNotIn(Flag.FILES_UNVERIFIED, s.flags)
                self.assertTrue(s.needs_attention)
                self.assertEqual(views.section(s), "alerts")


class AuditOf7712dec(unittest.TestCase):
    def test_unknown_or_partial_files_are_always_an_alert(self):
        # Audit of 7712dec: nothing held FILES_UNVERIFIED among the attention flags.
        from mission_control import views

        cases = []
        for merged in (True, False):
            for files_over in ({"files": None}, {"files_complete": False}):
                over = {"state": "closed", "merged": True, "merged_by": OWNER, "merged_at": t(20)}
                value = pr(**(over if merged else {}))
                value.update(files_over)
                cases.append((merged, files_over, value))
        for merged, files_over, value in cases:
            with self.subTest(merged=merged, files=files_over):
                s = derive(task(runs=[run("build"), passed(), published()], pull_request=value))
                self.assertIn(Flag.FILES_UNVERIFIED, s.flags)
                self.assertTrue(s.needs_attention)
                self.assertEqual(views.section(s), "alerts")


class CodexReviewOfCae7658(unittest.TestCase):
    """Codex's review of cae7658 (blocking): an issue closed before the merge ended the
    authorisation for an open PR, but not for the same PR once merged."""

    def merged(self, *events):
        return derive(
            task(
                issue={"number": 7, "state": "closed", "timeline": [labeled(), *events]},
                runs=[run("build"), passed(), published()],
                pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
            )
        )

    def closed(self, minute, actor=OWNER, closer_pr=None):
        return {"event": "closed", "actor": actor, "at": t(minute), "closer_pr": closer_pr}

    def reopened(self, minute, actor=OWNER):
        return {"event": "reopened", "actor": actor, "at": t(minute)}

    def test_an_issue_closed_before_the_merge_ends_the_authorisation(self):
        for actor in (OWNER, "someone-else"):
            with self.subTest(actor=actor):
                s = self.merged(self.closed(10, actor))
                self.assertEqual(s.state, State.UNSAFE)
                self.assertIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)
                self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)
                self.assertIn("withdrawn by the time of the merge", " ".join(s.reasons))

    def test_githubs_own_closing_as_the_pr_merges_ends_nothing(self):
        # In the merge's own second, only a closing by this PR (number 12) is known to come
        # with the merge (Codex's review of 4f8c1e9).
        self.assertEqual(self.merged(self.closed(20, closer_pr=12)).state, State.MERGED)
        self.assertEqual(self.merged(self.closed(21)).state, State.MERGED)  # after: nothing

    def test_any_other_closing_in_the_merges_second_is_never_calm(self):
        # It may have come first: not placed, so not known (an alert), and never claimed as a
        # withdrawal either (Fable's audit of ca7faa9).
        bare = self.closed(20)
        del bare["closer_pr"]  # as data from before closer_pr
        for closing in (self.closed(20), self.closed(20, closer_pr=99), bare):
            with self.subTest(closing=closing):
                s = self.merged(closing)
                self.assertEqual(s.state, State.UNKNOWN)
                self.assertIn(Flag.CLOSURE_UNPLACED, s.flags)
                self.assertNotIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)

    def test_closer_pr_must_be_a_number_or_null(self):
        for bad in ("12", True, 1.5):
            with self.subTest(bad=bad):
                s = self.merged(self.closed(20, closer_pr=bad))
                self.assertEqual(s.state, State.UNKNOWN)

    def test_reopening_restores_nothing_but_a_new_authorisation_does(self):
        # A closing ends the authorisation as removing the label does: only the owner
        # authorising again restores it, never a reopening, by anyone (Fable's audit of
        # fe4d72d: a stranger's reopening restored it silently).
        for actor in (OWNER, "someone-else"):
            s = self.merged(self.closed(10), self.reopened(12, actor))
            self.assertEqual(s.state, State.UNSAFE, actor)
        again = {"event": "authorized", "actor": OWNER, "at": t(13)}
        s = self.merged(self.closed(10), self.reopened(12), again)
        self.assertNotIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)
        self.assertNotIn(Flag.UNAUTHORIZED_WORK, s.flags)

    def test_a_reopening_in_doubt_restores_nothing(self):
        # In the merge's own second it may have come after the merge; at the closing's own
        # instant, the closing wins.
        s = self.merged(self.closed(10), self.reopened(20))
        self.assertEqual(s.state, State.UNSAFE)
        for events in ((self.closed(10), self.reopened(10)), (self.reopened(10), self.closed(10))):
            self.assertEqual(self.merged(*events).state, State.UNSAFE, events)

    def test_a_removed_label_before_the_merge_says_withdrawn(self):
        s = self.merged(labeled(minute=10, kind="unlabeled"))
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)

    def test_an_incomplete_file_list_is_never_called_clinical(self):
        # should_fix: the reason said "Clinical files" where the header said "not known".
        value = pr(files=("app.py",))
        value["files_complete"] = False
        s = derive(task(runs=[run("build"), passed(), published()], pull_request=value))
        self.assertEqual(s.state, State.CLINICAL_REVIEW)
        self.assertNotIn("Clinical files", " ".join(s.reasons))
        self.assertIn("may be clinical", " ".join(s.reasons))
        value["files"] = ["evidence/a.json", "app.py"]
        s = derive(task(runs=[run("build"), passed(), published()], pull_request=value))
        self.assertIn("Clinical files", " ".join(s.reasons))


class FableAuditOfB5ac6dd(unittest.TestCase):
    def merged(self, timeline, **over):
        value = task(
            issue={"number": 7, "state": "closed", "timeline": timeline},
            runs=[run("build"), passed(), published()],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
        )
        value.update(over)
        return derive(value)

    def test_a_withdrawn_merge_claims_nothing_about_its_review(self):
        closed = {"event": "closed", "actor": OWNER, "at": t(10)}
        for event in (closed, labeled(minute=10, kind="unlabeled")):
            with self.subTest(event=event["event"]):
                s = self.merged([labeled(), event])
                self.assertEqual(s.state, State.UNSAFE)
                self.assertIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)
                self.assertNotIn(Flag.MERGED_UNREVIEWED, s.flags)
                self.assertNotIn("never", " ".join(s.reasons))

    def test_a_never_authorised_merge_says_so(self):
        s = self.merged([])
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)
        self.assertNotIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)
        self.assertIn("never authorised", " ".join(s.reasons))
        # Closing an issue that was never authorised withdraws nothing either.
        s = self.merged([{"event": "closed", "actor": OWNER, "at": t(10)}])
        self.assertNotIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)
        self.assertIn("never authorised", " ".join(s.reasons))

    def test_a_partial_check_list_never_passes(self):
        value = pr()
        value["checks_complete"] = False
        s = derive(task(runs=[run("build"), passed(), published()], pull_request=value))
        self.assertNotIn(Flag.CHECKS_PASSED, s.flags)
        self.assertIn(Flag.CHECKS_UNVERIFIED, s.flags)
        self.assertEqual(s.state, State.PUBLISHED)
        # A failure in it still fails.
        value["checks"] = [check("lint"), check("test", conclusion="failure")]
        s = derive(task(runs=[run("build"), passed(), published()], pull_request=value))
        self.assertIn(Flag.CHECKS_FAILING, s.flags)

    def test_unread_run_records_never_claim_a_missing_review(self):
        s = derive(task(runs=None, pull_request=pr()))
        self.assertIn(Flag.RUNS_UNVERIFIED, s.flags)
        self.assertNotIn(Flag.REVIEW_MISSING, s.flags)
        self.assertNotIn(Flag.PR_BEFORE_REVIEW, s.flags)


class FableAuditOfFe4d72d(unittest.TestCase):
    def merged(self, timeline, issue_state="closed", **pr_over):
        over = dict(state="closed", merged=True, merged_by=OWNER, merged_at=t(20))
        over.update(pr_over)
        return derive(
            task(
                issue={"number": 7, "state": issue_state, "timeline": [labeled(), *timeline]},
                runs=[run("build"), passed(), published()],
                pull_request=pr(**over),
            )
        )

    def closed(self, minute, closer_pr=None, at=None):
        return {"event": "closed", "actor": OWNER, "at": at or t(minute), "closer_pr": closer_pr}

    def test_a_closing_that_cant_be_placed_is_never_calm(self):
        from mission_control import views

        for name, timeline, state in (
            ("closed, no closing on record", [], "closed"),
            (
                # (A closing before the merge is already a withdrawal: UNSAFE, not this.)
                "closed, last word a reopening",
                [{**self.closed(6), "event": "reopened"}],
                "closed",
            ),
            ("open, last word a closing", [self.closed(20, closer_pr=12)], "open"),
        ):
            with self.subTest(name):
                s = self.merged(timeline, issue_state=state)
                self.assertIn(Flag.CLOSURE_UNPLACED, s.flags)
                self.assertTrue(s.needs_attention)
                self.assertEqual(views.section(s), "alerts")
        s = self.merged([self.closed(20, closer_pr=12)])
        self.assertEqual(s.state, State.MERGED)
        self.assertNotIn(Flag.CLOSURE_UNPLACED, s.flags)
        self.assertFalse(s.needs_attention)

    def test_the_last_word_is_the_latest_event_not_the_last_listed(self):
        # Closed and reopened after the merge, listed out of order: the issue is open, and
        # its latest event agrees.
        reopened = {**self.closed(30), "event": "reopened"}
        s = self.merged([reopened, self.closed(25)], issue_state="open")
        self.assertNotIn(Flag.CLOSURE_UNPLACED, s.flags)
        self.assertEqual(s.state, State.MERGED)

    def test_a_closing_naming_this_pr_before_the_merge_still_counts(self):
        s = self.merged([self.closed(10, closer_pr=12)])
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)

    def test_times_are_compared_to_the_second(self):
        # A removal within the merge's second, after it by a fraction, may have come first.
        late = {**labeled(kind="unlabeled"), "at": "2026-01-01T10:20:00.400000+00:00"}
        self.assertEqual(self.merged([late], issue_state="open").state, State.UNSAFE)
        # A closing in that second, not by the merged PR: can't be placed.
        closing = self.closed(0, at="2026-01-01T10:20:00.400000+00:00")
        self.assertEqual(self.merged([closing]).state, State.UNKNOWN)
        # A closing at 10:19:59.9 is before the merge's second: a withdrawal.
        closing = self.closed(0, at="2026-01-01T10:19:59.900000+00:00")
        s = self.merged([closing])
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)

    def test_a_passing_review_is_still_shown_on_an_unsafe_merge(self):
        s = self.merged([], issue_state="open", merged_by="someone-else")
        self.assertEqual(s.state, State.UNSAFE)
        self.assertEqual(s.reviewed_sha, A)

    def test_an_open_pr_on_a_closed_issue_never_hides_unauthorised_work(self):
        for timeline, withdrawn in (
            ([], False),
            ([labeled(), labeled(minute=1, kind="unlabeled")], True),
        ):
            with self.subTest(withdrawn=withdrawn):
                s = derive(
                    task(
                        issue={"number": 7, "state": "closed", "timeline": timeline},
                        runs=[run("build"), passed(), published()],
                        pull_request=pr(),
                    )
                )
                self.assertEqual(s.state, State.UNSAFE)
                self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)
                self.assertEqual(Flag.AUTHORIZATION_WITHDRAWN in s.flags, withdrawn)
                self.assertNotIn("reopen", " ".join(s.reasons))

    def test_an_open_pr_and_its_merge_read_one_history_alike(self):
        # Fable's audit of ca7faa9 (blocking): closed and reopened, an open PR showed as ready
        # while its merge would be unsafe. Now both are withdrawn, until authorised again.
        closing = {"event": "closed", "actor": OWNER, "at": t(1)}
        reopening = {"event": "reopened", "actor": OWNER, "at": t(1)}
        issue = {"number": 7, "state": "open", "timeline": [labeled(), closing, reopening]}
        base = reviewed_and_published() | {"clinical_paths": [], "issue": issue}
        s = derive(base)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)
        merged = copy.deepcopy(base)
        merged["pull_request"].update(state="closed", merged=True, merged_by=OWNER, merged_at=t(20))
        self.assertEqual(derive(merged).state, State.UNSAFE)
        # Authorised again after the reopening: ready, and its merge is merged.
        again = {"event": "authorized", "actor": OWNER, "at": t(1)}
        for value in (base, merged):
            value["issue"]["timeline"] = [labeled(), closing, reopening, dict(again)]
            value["issue"]["timeline"][1]["at"] = value["issue"]["timeline"][2]["at"] = t(0)
        self.assertEqual(derive(base).state, State.AWAITING_OWNER)
        self.assertEqual(derive(merged).state, State.MERGED)

    def test_unread_checks_on_an_open_pr_are_an_alert(self):
        s = derive(task(runs=None, pull_request=pr(checks=None) | {"checks": None}))
        self.assertIn(Flag.CHECKS_UNVERIFIED, s.flags)
        self.assertTrue(s.needs_attention)

    def test_a_removal_with_no_authorisation_before_it_withdraws_nothing(self):
        s = derive(
            task(
                issue={"number": 7, "state": "open", "timeline": [labeled(kind="unlabeled")]},
                runs=[run("build")],
            )
        )
        self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)
        self.assertNotIn(Flag.AUTHORIZATION_WITHDRAWN, s.flags)

    def test_a_changes_request_after_the_merge_changes_nothing(self):
        s = self.merged(
            [self.closed(20, closer_pr=12)],
            files=("evidence/a.json",),
            reviews=(approval(minute=10), approval(minute=30, state="CHANGES_REQUESTED")),
        )
        self.assertEqual(s.state, State.MERGED)
        self.assertIn(Flag.CLINICIAN_APPROVED, s.flags)


class FableAuditOfCa7faa9(unittest.TestCase):
    def merged(self, timeline, issue_state="open", **over):
        value = task(
            issue={"number": 7, "state": issue_state, "timeline": [labeled(), *timeline]},
            runs=[run("build"), passed(), published()],
            pull_request=pr(state="closed", merged=True, merged_by=OWNER, merged_at=t(20)),
        )
        value.update(over)
        return derive(value)

    def ev(self, kind, minute, **extra):
        return {"event": kind, "actor": OWNER, "at": t(minute), **extra}

    def test_closings_that_dont_alternate_are_never_calm(self):
        for name, timeline, state in (
            ("a reopening with no closing", [self.ev("reopened", 10)], "open"),
            ("a reopening after the merge", [self.ev("reopened", 25)], "open"),
            (
                "closed twice",
                [self.ev("closed", 21), self.ev("closed", 22, closer_pr=12)],
                "closed",
            ),
            (
                "reopened, then GitHub's closing",
                [self.ev("reopened", 10), self.ev("closed", 20, closer_pr=12)],
                "closed",
            ),
        ):
            with self.subTest(name):
                s = self.merged(timeline, issue_state=state)
                self.assertEqual(s.state, State.UNKNOWN)
                self.assertIn(Flag.CLOSURE_UNPLACED, s.flags)
                self.assertTrue(s.needs_attention)

    def test_an_open_pr_on_a_history_that_doesnt_add_up_is_never_ready(self):
        value = reviewed_and_published() | {"clinical_paths": []}
        value["issue"] = {
            "number": 7,
            "state": "open",
            "timeline": [labeled(), self.ev("reopened", 1)],
        }
        s = derive(value)
        self.assertEqual(s.state, State.UNKNOWN)
        self.assertIn(Flag.CLOSURE_UNPLACED, s.flags)
        self.assertIn("Authorise again", s.reasons[0])

    def test_a_closing_and_an_authorisation_in_one_second_withdraw(self):
        # Within one second a closing sorts after an authorisation, whatever the input order.
        value = reviewed_and_published() | {"clinical_paths": []}
        value["issue"] = {
            "number": 7,
            "state": "closed",
            "timeline": [self.ev("closed", 0), labeled()],
        }
        s = derive(value)
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn(Flag.UNAUTHORIZED_WORK, s.flags)

    def test_every_time_is_read_to_the_second(self):
        # A failing review 0.3 s into the merge's own second is in that second.
        late_fail = failed(minute=0) | {"at": "2026-01-01T10:20:00.300000+00:00"}
        s = self.merged(
            [self.ev("closed", 20, closer_pr=12)],
            issue_state="closed",
            runs=[run("build"), passed(), late_fail, published()],
        )
        self.assertEqual(s.state, State.UNSAFE)
        self.assertIn("reviews disagree", " ".join(s.reasons))
        # A clinician's changes request then bounds the approval: not known, never approved.
        s = self.merged(
            [self.ev("closed", 20, closer_pr=12)],
            issue_state="closed",
            pull_request=pr(
                state="closed",
                merged=True,
                merged_by=OWNER,
                merged_at="2026-01-01T10:20:00.000000+00:00",
                files=("evidence/a.json",),
                reviews=(
                    approval(minute=10),
                    approval(state="CHANGES_REQUESTED") | {"at": "2026-01-01T10:20:00.300+00:00"},
                ),
            ),
        )
        self.assertNotIn(Flag.CLINICIAN_APPROVED, s.flags)

    def test_a_closed_issue_still_shows_a_passing_review(self):
        value = task(
            issue={
                "number": 7,
                "state": "closed",
                "timeline": [
                    self.ev("closed", 0),
                    {**labeled(), "event": "authorized", "at": t(1)},
                ],
            },
            runs=[run("build"), passed(), published()],
            pull_request=pr(),
        )
        s = derive(value)
        self.assertEqual(s.state, State.NOT_LINKED)
        self.assertEqual(s.reviewed_sha, A)

    def test_times_are_whole_seconds_in_utc(self):
        # Even with an offset that has a fraction of a second, the second is the UTC one.
        from datetime import UTC, datetime

        from mission_control.tasks import _time

        at = _time("2026-01-01T10:20:00.200000+00:00:00.500000", "at")
        self.assertEqual(at, datetime(2026, 1, 1, 10, 19, 59, tzinfo=UTC))
        self.assertEqual((at.microsecond, at.utcoffset().total_seconds()), (0, 0))
