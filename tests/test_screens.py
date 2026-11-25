"""Phase A3: the read-only screens over synthetic demo data (Demo 0). No server, no network."""

from __future__ import annotations

import copy
import json
import re
import unittest
from wsgiref.util import setup_testing_defaults

from mission_control import demo as demo_module
from mission_control import views
from mission_control.app import READ_METHODS, SECURITY_HEADERS, make_app
from mission_control.demo import DEMO_FILE, DemoError, load
from mission_control.tasks import ATTENTION_FLAGS, Flag, State

DEMO_TEXT = DEMO_FILE.read_text(encoding="utf-8")
DEMO_DATA = json.loads(DEMO_TEXT)
PAGES = ("/", "/tasks", "/usage", "/settings")


def call(app, path: str = "/", method: str = "GET") -> tuple[str, dict[str, str], str]:
    environ: dict = {"PATH_INFO": path, "REQUEST_METHOD": method}
    setup_testing_defaults(environ)
    captured: dict = {}

    def start_response(status, headers, exc_info=None):
        captured["status"], captured["headers"] = status, dict(headers)

    body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], body.decode("utf-8")


def app_for(data: dict):
    text = json.dumps(data)
    return make_app(lambda: load(text))


def with_tasks(*entries) -> dict:
    data = copy.deepcopy(DEMO_DATA)
    data["tasks"] = list(entries)
    return data


def entry(task_id: str) -> dict:
    return copy.deepcopy(next(e for e in DEMO_DATA["tasks"] if e["id"] == task_id))


DEMO = load(DEMO_TEXT)
APP = make_app()
ALL_PATHS = (*PAGES, *(f"/tasks/{e.id}" for e in DEMO.entries))


class DemoData(unittest.TestCase):
    def test_every_state_and_flag_appears_in_the_demo(self):
        states = {e.status.state for e in DEMO.entries}
        flags = set().union(*(e.status.flags for e in DEMO.entries))
        self.assertEqual(states, set(State))
        self.assertLessEqual(ATTENTION_FLAGS, flags)
        self.assertEqual(flags, set(Flag))

    def test_states_are_derived_never_stored(self):
        for raw in DEMO_DATA["tasks"]:
            self.assertEqual(set(raw), {"id", "title", "risk", "task"}, raw["id"])
            self.assertNotIn("state", raw["task"])

    def test_only_synthetic_names(self):
        for raw in DEMO_DATA["tasks"]:
            task = raw["task"]
            if isinstance(task.get("repo"), str):
                self.assertTrue(task["repo"].startswith("example-org/"), raw["id"])
            if isinstance(task.get("owner"), str):
                self.assertTrue(task["owner"].startswith("example-"), raw["id"])

    def test_malformed_demo_files_are_refused(self):
        for bad in (
            "not json",
            "[]",
            json.dumps({**DEMO_DATA, "stop_switch": {"on": "no"}}),
            json.dumps({**DEMO_DATA, "commands": {"review": "x {sha}"}}),
            json.dumps({**DEMO_DATA, "commands": {"review": "no sha", "publish": "{sha}"}}),
            json.dumps({**DEMO_DATA, "commands": {"review": "a\n{sha}", "publish": "{sha}"}}),
            json.dumps({**DEMO_DATA, "refreshed_at": "today"}),
            json.dumps(with_tasks(entry("example-site-901"), entry("example-site-901"))),
            json.dumps(with_tasks({**entry("example-site-901"), "id": "Bad ID"})),
            json.dumps(with_tasks({**entry("example-site-901"), "risk": "extreme"})),
            json.dumps(with_tasks({**entry("example-site-901"), "title": ""})),
        ):
            with self.assertRaises(DemoError, msg=bad[:60]):
                load(bad)

    def test_a_task_with_bad_data_is_unknown_not_an_error(self):
        broken = entry("example-site-901")
        broken["task"]["pull_request"]["head_sha"] = "not a sha"
        demo = load(json.dumps(with_tasks(broken)))
        self.assertEqual(demo.entries[0].status.state, State.UNKNOWN)
        self.assertIsNone(demo.entries[0].repo)

    def test_the_stop_switch_pauses_active_tasks(self):
        data = copy.deepcopy(DEMO_DATA)
        data["stop_switch"]["on"] = True
        demo = load(json.dumps(data))
        for e in demo.entries:
            self.assertIn(
                e.status.state,
                {State.PAUSED, State.MERGED, State.CLOSED, State.UNSAFE, State.UNKNOWN},
                e.id,
            )
        status, _, body = call(make_app(lambda: demo), "/settings")
        self.assertIn("ON: no new runs start", body)


class Words(unittest.TestCase):
    def test_every_state_and_flag_has_words(self):
        self.assertEqual(set(views.STATE_WORDS), set(State))
        self.assertEqual(set(views.FLAG_WORDS), set(Flag))
        for text in (*views.STATE_WORDS.values(), *views.FLAG_WORDS.values()):
            self.assertTrue(text.strip())

    def test_each_task_shows_its_state_in_words_and_attention_in_text(self):
        for e in DEMO.entries:
            _, _, body = call(APP, f"/tasks/{e.id}")
            self.assertIn(views.state_words(e.status).replace("'", "&#x27;"), body, e.id)
            for flag in e.status.flags:
                self.assertIn(views.FLAG_WORDS[flag].replace("'", "&#x27;"), body, (e.id, flag))
            self.assertEqual("Needs you:" in body, views.needs_you(e.status), e.id)

    def test_unknown_and_unsafe_are_always_alerts(self):
        for e in DEMO.entries:
            if e.status.state in (State.UNKNOWN, State.UNSAFE, State.FAILED):
                self.assertEqual(views.section(e.status), "alerts", e.id)
            if e.status.needs_attention:
                self.assertIn(views.section(e.status), ("alerts", "waiting"), e.id)
            if e.status.flags & ATTENTION_FLAGS:
                self.assertEqual(views.section(e.status), "alerts", e.id)

    def test_unknown_and_unsafe_never_read_as_passing(self):
        for e in DEMO.entries:
            if e.status.state not in (State.UNKNOWN, State.UNSAFE):
                continue
            _, _, body = call(APP, f"/tasks/{e.id}")
            self.assertNotIn("Next:", body, e.id)  # no command offered
            self.assertNotIn('[...] <span class="step">Owner', body, e.id)


class Screens(unittest.TestCase):
    def test_every_screen_renders(self):
        for path in ALL_PATHS:
            status, headers, body = call(APP, path)
            self.assertEqual(status, "200 OK", path)
            self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
            self.assertIn('name="viewport"', body)
            self.assertIn("Demo data (synthetic)", body)
            self.assertIn('href="/static/app.css"', body)

    def test_home_puts_decisions_first(self):
        _, _, body = call(APP, "/")
        waiting, running, alerts = (
            body.index('id="h-waiting"'),
            body.index('id="h-active"'),
            body.index('id="h-alerts"'),
        )
        self.assertLess(waiting, running)
        self.assertLess(running, alerts)
        self.assertIn('href="#h-alerts"', body)  # the summary jumps straight to alerts
        self.assertIn('href="/settings#h-stop"', body)  # the stop switch is one tap away
        # ...but Home never shows a stop state: the demo's read like Billy's real one (A4c).
        self.assertNotIn("runs may start", body)
        self.assertNotIn("no new runs start", body)

    def test_home_lists_every_task_but_the_done_ones(self):
        _, _, body = call(APP, "/")
        for e in DEMO.entries:
            shown = f'href="/tasks/{e.id}"' in body
            self.assertEqual(shown, views.section(e.status) != "done", e.id)

    def test_the_task_list_shows_every_task(self):
        _, _, body = call(APP, "/tasks")
        for e in DEMO.entries:
            self.assertIn(f'href="/tasks/{e.id}"', body)

    def test_github_links_use_only_validated_values(self):
        for path in ALL_PATHS:
            _, _, body = call(APP, path)
            for url in re.findall(r'href="(https?://[^"]*)"', body):
                self.assertRegex(
                    url,
                    r"^https://github\.com/example-org/[a-z-]+/(pull|issues)/\d+$",
                    path,
                )

    def test_usage_and_settings_are_placeholders(self):
        _, _, body = call(APP, "/usage")
        self.assertIn("Nothing is tracked in this demo.", body)
        _, _, body = call(APP, "/settings")
        self.assertIn("Read-only here.", body)
        self.assertIn("Nothing runs on a timer.", body)
        self.assertNotIn("<form", body)
        self.assertNotIn("<button", body)

    def test_no_screen_has_a_form_script_or_outside_resource(self):
        for path in ALL_PATHS:
            _, _, body = call(APP, path)
            self.assertNotIn("<form", body, path)
            self.assertNotIn("<script", body, path)
            self.assertNotIn("<img", body, path)
            self.assertNotIn("<iframe", body, path)
            self.assertNotRegex(body, r'(src|href)="//', path)
            for link in re.findall(r'<link[^>]*href="([^"]*)"', body):
                self.assertEqual(link, "/static/app.css", path)

    def test_the_stylesheet_is_served_and_needs_nothing_outside(self):
        status, headers, body = call(APP, "/static/app.css")
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "text/css; charset=utf-8")
        self.assertNotIn("@import", body)
        self.assertNotIn("url(", body)
        self.assertIn("user-select: all", body)
        self.assertIn("prefers-color-scheme: dark", body)
        self.assertIn("min-height: 44px", body)


class CommandHelper(unittest.TestCase):
    def test_review_command_for_a_built_commit(self):
        e = DEMO.entry("example-site-912")
        self.assertEqual(e.status.state, State.BUILT)
        command = DEMO.command(e)
        self.assertEqual(command.kind, "review")
        self.assertEqual(command.sha, e.status.head_sha)
        self.assertEqual(len(command.sha), 40)
        self.assertEqual(
            command.text, f"billy review claude/print-styles {command.sha} --repo example-site"
        )
        _, _, body = call(APP, "/tasks/example-site-912")
        self.assertIn(command.sha, body)
        self.assertIn('class="command"', body)
        self.assertIn("Mission Control runs nothing.", body)

    def test_publish_command_for_a_reviewed_commit(self):
        e = DEMO.entry("example-site-914")
        self.assertEqual(e.status.state, State.REVIEWED)
        command = DEMO.command(e)
        self.assertEqual(command.kind, "publish")
        self.assertEqual(command.sha, e.status.reviewed_sha)

    def test_no_command_in_any_other_state(self):
        for e in DEMO.entries:
            if e.status.state not in (State.BUILT, State.REVIEWED):
                self.assertIsNone(DEMO.command(e), e.id)
                _, _, body = call(APP, f"/tasks/{e.id}")
                self.assertNotIn('class="command"', body, e.id)

    def test_an_unsafe_branch_name_gets_no_command(self):
        for branch in ("claude/x y", "claude/$(id)", "-oops", "claude/{sha}", "a/../b", "c;d"):
            raw = entry("example-site-912")
            raw["task"]["branch"]["name"] = branch
            for run in raw["task"]["runs"]:
                run["branch"] = branch
            demo = load(json.dumps(with_tasks(raw)))
            self.assertEqual(demo.entries[0].status.state, State.BUILT, branch)
            self.assertIsNone(demo.command(demo.entries[0]), branch)

    def test_placeholders_are_replaced_literally(self):
        data = with_tasks(entry("example-site-912"))
        data["commands"]["review"] = "x {sha.__class__} {repo} {repo_name} {branch} {sha} {other}"
        demo = load(json.dumps(data))
        command = demo.command(demo.entries[0])
        sha = demo.entries[0].status.head_sha
        self.assertEqual(
            command.text,
            "x {sha.__class__} example-org/example-site example-site claude/print-styles "
            f"{sha} {{other}}",
        )

    def test_placeholder_set_is_documented(self):
        self.assertEqual(demo_module.PLACEHOLDERS, ("{repo}", "{repo_name}", "{branch}", "{sha}"))


def path_row(body: str, step: str) -> str | None:
    found = re.search(r'\[([^\]]*)\]</span> <span class="step">' + step + "</span>", body)
    return found.group(1) if found else None


def detail(raw: dict) -> tuple[State, str]:
    demo = load(json.dumps(with_tasks(raw)))
    e = demo.entries[0]
    return e.status.state, views.task_detail(demo, e)


class CodexReviewOfDc58125(unittest.TestCase):
    """Codex's review of dc58125 (blocking): AWAITING_OWNER from exhausted fix rounds is decided
    before review, checks or the clinician, so it never shows a clinician's approval."""

    def exhausted_clinical(self) -> dict:
        raw = entry("example-site-908")
        for run in raw["task"]["runs"]:
            run["files"] = ["evidence/ai-vs-human.json"]
        return raw

    def test_exhausted_fix_rounds_on_clinical_files_show_no_approval(self):
        state, body = detail(self.exhausted_clinical())
        self.assertEqual(state, State.AWAITING_OWNER)
        self.assertIn("Clinical files", body)
        self.assertNotEqual(path_row(body, "Clinician"), "done")
        self.assertIn("fix rounds used up", body)

    def test_even_a_later_passing_review_and_green_pr_show_no_approval(self):
        raw = self.exhausted_clinical()
        task = raw["task"]
        head = task["branch"]["head"]
        task["runs"].append(
            {
                "step": "review",
                "repo": task["repo"],
                "branch": task["branch"]["name"],
                "sha": head,
                "at": "2026-11-14T12:00:00+00:00",
                "status": "finished",
                "verdict": "no_blocking_findings",
                "findings": [],
            }
        )
        state, body = detail(raw)
        self.assertEqual(state, State.UNKNOWN)  # the head's reviews now disagree
        self.assertNotEqual(path_row(body, "Clinician"), "done")

    def test_clinician_approved_needs_the_normal_path(self):
        for e in DEMO.entries:
            if views.clinician_approved(e.status):
                self.assertIn(Flag.CLINICAL, e.status.flags, e.id)
                self.assertNotIn(Flag.FIX_ROUNDS_EXHAUSTED, e.status.flags, e.id)


class CodexReviewOfCaa5552(unittest.TestCase):
    """Codex's review of caa5552 (blocking): the path showed a clinician's approval whenever the
    warning flags were absent, though the model checks approval only after the earlier gates."""

    def clinical(self) -> dict:
        raw = entry("example-site-902")
        self.assertEqual(detail(raw)[0], State.CLINICAL_REVIEW)
        return raw

    def test_a_clinical_task_before_the_final_gate_is_not_shown_approved(self):
        built = self.clinical()
        built["task"]["runs"] = built["task"]["runs"][:1]
        built["task"]["pull_request"] = None
        reviewed = self.clinical()
        reviewed["task"]["runs"] = reviewed["task"]["runs"][:2]
        reviewed["task"]["pull_request"] = None
        pending = self.clinical()
        pending["task"]["pull_request"]["checks"][1].update(status="in_progress", conclusion=None)
        changes = self.clinical()
        changes["task"]["runs"][1].update(
            verdict="changes_needed", findings=[{"severity": "blocking"}]
        )
        changes["task"]["runs"] = changes["task"]["runs"][:2]
        changes["task"]["pull_request"] = None
        paused = self.clinical()
        paused["task"]["paused"] = True
        for raw, expected in (
            (built, State.BUILT),
            (reviewed, State.REVIEWED),
            (pending, State.PUBLISHED),
            (changes, State.CHANGES_NEEDED),
            (paused, State.PAUSED),
        ):
            state, body = detail(raw)
            self.assertEqual(state, expected)
            self.assertIn("Clinical files", body, expected)
            self.assertNotEqual(path_row(body, "Clinician"), "done", expected)
            self.assertNotIn(
                '<span class="step">Clinician</span> <span>approved this commit', body, expected
            )

    def test_a_clinicians_approval_of_the_head_is_shown_approved(self):
        raw = self.clinical()
        head = raw["task"]["pull_request"]["head_sha"]
        raw["task"]["pull_request"]["reviews"] = [
            {
                "user": "example-clinician",
                "user_type": "User",
                "state": "APPROVED",
                "commit_id": head,
                "at": "2026-11-14T10:00:00+00:00",
            }
        ]
        state, body = detail(raw)
        self.assertEqual(state, State.AWAITING_OWNER)
        self.assertEqual(path_row(body, "Clinician"), "done")

    def test_authorised_is_not_claimed_where_the_model_never_checked(self):
        paused_proposal = entry("example-site-918")
        paused_proposal["task"]["paused"] = True
        closed_unauthorised = entry("example-site-923")
        closed_unauthorised["task"]["issue"]["timeline"] = []
        for raw, expected in ((paused_proposal, State.PAUSED), (closed_unauthorised, State.CLOSED)):
            state, body = detail(raw)
            self.assertEqual(state, expected)
            self.assertNotEqual(path_row(body, "Authorised"), "done", expected)

    def test_unread_run_records_never_show_a_review_or_a_clinical_no(self):
        # Codex's review of 9537b08: a merge with no run records read, and a file list not
        # known, must show neither "review: done"/"never passed" nor "clinical: no".
        e = DEMO.entry("example-tools-60")
        body = views.task_detail(DEMO, e)
        self.assertEqual(e.status.state, State.MERGED)
        self.assertEqual(path_row(body, "Review"), "?")
        self.assertNotIn("never passed review", body)
        self.assertIn("clinical: not known", body)
        # Unverified checks are "?", never "not yet" (Codex's review of b7d568e).
        self.assertEqual(path_row(body, "Checks"), "?")

    def test_unread_reviews_never_show_a_clinician_approval(self):
        # Codex's review of 72607b3 (blocking): MERGED alone was taken as proof.
        raw = entry("example-site-919")
        raw["task"]["pull_request"]["reviews"] = None
        state, body = detail(raw)
        self.assertNotEqual(path_row(body, "Clinician"), "done")
        self.assertNotIn("approved this commit", body)

    def test_an_open_clinical_pr_with_unread_reviews_claims_nothing(self):
        # Codex's review of 9fb21c8: it said no clinician had approved.
        raw = entry("example-site-919")
        pull = raw["task"]["pull_request"]
        pull.update(state="open", merged=False, merged_by=None, reviews=None)
        pull.pop("merged_at", None)
        raw["task"]["issue"]["state"] = "open"
        state, body = detail(raw)
        self.assertEqual(path_row(body, "Clinician"), "?")
        self.assertNotIn("approval of this commit needed", body)
        # Nor does the Flags list say so (Codex's review of dc1eb14).
        self.assertNotIn("No clinician has approved", body)

    def test_unreadable_task_data_never_says_clinical_no(self):
        # Codex's review of 7faf35a.
        raw = entry("example-tools-62")
        raw["task"] = None
        state, body = detail(raw)
        self.assertEqual(state, State.UNKNOWN)
        self.assertIn("clinical: not known", body)

    def test_an_unidentifiable_merger_is_an_unsafe_merge_on_the_path(self):
        # Codex's review of 48929aa.
        e = DEMO.entry("example-tools-64")
        body = views.task_detail(DEMO, e)
        self.assertIn(Flag.MERGER_UNKNOWN, e.status.flags)
        self.assertEqual(path_row(body, "Owner"), "!")

    def test_a_merge_with_no_linked_issue_never_shows_authorisation(self):
        # Codex's review of 72607b3 (blocking): MERGED is reachable with ISSUE_NOT_LINKED.
        raw = entry("example-site-921")
        raw["task"]["issue"] = None
        raw["task"]["runs"] = None  # as the fetcher sends it
        state, body = detail(raw)
        self.assertEqual(state, State.MERGED)
        self.assertNotEqual(path_row(body, "Authorised"), "done")

    def test_an_unreviewed_merge_says_so(self):
        e = DEMO.entry("example-tools-57")
        body = views.task_detail(DEMO, e)
        self.assertEqual(path_row(body, "Review"), "!")
        self.assertIn("never passed review", body)

    def test_no_demo_task_shows_a_step_done_that_its_state_does_not_establish(self):
        for e in DEMO.entries:
            body = views.task_detail(DEMO, e)
            if path_row(body, "Clinician") == "done":
                self.assertIn(e.status.state, (State.AWAITING_OWNER, State.MERGED), e.id)
                self.assertNotIn(Flag.FIX_ROUNDS_EXHAUSTED, e.status.flags, e.id)
            if path_row(body, "Authorised") == "done":
                self.assertIn(e.status.underlying, views.AUTHORISED_STATES, e.id)
            if path_row(body, "Review") == "done":
                self.assertIsNotNone(e.status.reviewed_sha, e.id)
            if path_row(body, "Owner") == "done":
                self.assertEqual(e.status.state, State.MERGED, e.id)


HOSTILE = "<script>alert(1)</script>\"'&"


class Escaping(unittest.TestCase):
    def test_hostile_text_is_escaped_everywhere(self):
        raw = entry("example-site-903")
        raw["title"] = "Title " + HOSTILE
        raw["task"]["runs"][0]["branch"] = raw["task"]["branch"]["name"] = "claude/x"
        raw["task"]["runs"][1]["branch"] = "claude/x"
        # Text from outside also reaches the events list and the reasons.
        raw["task"]["issue"]["timeline"].append(
            {
                "event": "labeled",
                "label": HOSTILE,
                "actor": "example-owner",
                "at": "2026-11-14T09:01:00+00:00",
            }
        )
        app = app_for(with_tasks(raw))
        for path in ("/", "/tasks", "/tasks/example-site-903"):
            _, _, body = call(app, path)
            self.assertNotIn("<script", body, path)
            self.assertIn("&lt;script&gt;", body, path)
            self.assertNotIn("\"'&<", body, path)

    def test_a_hostile_command_template_is_escaped(self):
        data = with_tasks(entry("example-site-912"))
        data["commands"]["review"] = "<b>{sha}</b>"
        _, _, body = call(app_for(data), "/tasks/example-site-912")
        self.assertIn("&lt;b&gt;", body)
        self.assertNotIn("<b>", body)


class ReadOnlyAndErrors(unittest.TestCase):
    def test_every_route_refuses_writes(self):
        for path in (*ALL_PATHS, "/healthz", "/static/app.css", "/nope"):
            for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                status, headers, _ = call(APP, path, method)
                self.assertEqual(status, "405 Method Not Allowed", (path, method))
                self.assertEqual(headers["Allow"], ", ".join(READ_METHODS))

    def test_head_works_on_every_route(self):
        for path in (*ALL_PATHS, "/static/app.css"):
            status, headers, body = call(APP, path, "HEAD")
            self.assertEqual(status, "200 OK", path)
            self.assertEqual(body, "", path)
            self.assertGreater(int(headers["Content-Length"]), 0, path)

    def test_security_headers_on_every_route(self):
        for path in (*ALL_PATHS, "/healthz", "/static/app.css", "/nope", "/tasks/nope"):
            _, headers, _ = call(APP, path)
            for name, value in SECURITY_HEADERS:
                self.assertEqual(headers.get(name), value, (path, name))

    def test_unknown_tasks_and_paths_are_not_found(self):
        for path in (
            "/tasks/nope",
            "/tasks/EXAMPLE-SITE-901",
            "/tasks/example-site-901/",
            "/tasks/",
            "/tasks/../settings",
            "/task/example-site-901",
            "/static/other.css",
            "/static/../app.py",
        ):
            status, _, _ = call(APP, path)
            self.assertEqual(status, "404 Not Found", path)

    def test_unreadable_data_shows_nothing_rather_than_a_guess(self):
        def broken():
            raise DemoError("bad")

        app = make_app(broken)
        for path in PAGES:
            status, _, body = call(app, path)
            self.assertEqual(status, "503 Service Unavailable", path)
            self.assertIn("could not be read", body)
        self.assertEqual(call(app, "/healthz")[0], "200 OK")


if __name__ == "__main__":
    unittest.main()


class FableReviewOf0cf099cScreens(unittest.TestCase):
    """The view never says the opposite of the model (independent review of 0cf099c)."""

    def test_the_owner_row_matches_the_state(self):
        expected = {
            State.UNSAFE: ("!",),
            State.CLOSED: ("-",),
            State.NOT_LINKED: ("-",),
            State.UNKNOWN: ("?",),
            State.MERGED: ("done",),
        }
        for e in DEMO.entries:
            body = views.task_detail(DEMO, e)
            row = path_row(body, "Owner")
            if e.status.underlying in expected:
                self.assertIn(row, expected[e.status.underlying], e.id)
                self.assertNotIn("approve and merge, later", body, e.id)

    def test_no_file_list_is_never_clinical_no(self):
        for e in DEMO.entries:
            body = views.task_detail(DEMO, e)
            if e.status.pr is None:
                self.assertNotIn("clinical: no<", body, e.id)

    def test_unverified_states_never_read_as_a_negative(self):
        for e in DEMO.entries:
            words = views.state_words(e.status)
            if Flag.CHECKS_UNVERIFIED in e.status.flags:
                self.assertNotIn("not all passed", words, e.id)
            if Flag.RUNS_UNVERIFIED in e.status.flags:
                self.assertNotIn("waiting for review", words, e.id)
                self.assertIsNone(DEMO.command(e), e.id)

    def test_stale_or_missing_checks_are_pending_not_alarms(self):
        for e in DEMO.entries:
            body = views.task_detail(DEMO, e)
            if e.status.flags & {Flag.CHECKS_STALE, Flag.CHECKS_MISSING}:
                self.assertEqual(path_row(body, "Checks"), "...", e.id)
