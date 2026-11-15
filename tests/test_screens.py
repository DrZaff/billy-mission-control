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
            self.assertIn(views.STATE_WORDS[e.status.state].replace("'", "&#x27;"), body, e.id)
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
        self.assertIn("Stop switch:", body)

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
