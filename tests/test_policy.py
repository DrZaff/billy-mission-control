"""Repository guards: CI stays read-only and secret-free, the app makes no outbound calls, and
CODEOWNERS covers everything. A change that weakens one of these fails the tests, so it has to
be argued for in a reviewed pull request rather than slipping in."""

from __future__ import annotations

import ast
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))

# Modules the app package must not import: outbound network clients and process execution.
# (The development server's wsgiref is allowed; it only listens, on loopback.) Since A4a
# (owner decision 3), `socket` is allowed for Unix sockets only: the service listens on one and
# the web app asks the stop helper over another. Internet sockets stay forbidden (below).
FORBIDDEN_IMPORTS = {
    "urllib.request",
    "http.client",
    "ssl",
    "subprocess",
    "requests",
    "httpx",
    "aiohttp",
    "smtplib",
    "ftplib",
}


# Triggers that run on a timer, with write access, or from other workflows' events.
RISKY_TRIGGERS = ("schedule", "pull_request_target", "workflow_run", "repository_dispatch")


def imported_modules(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


class Workflows(unittest.TestCase):
    def test_there_is_a_workflow(self):
        self.assertTrue(WORKFLOWS)

    def test_read_only_and_secret_free(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertRegex(text, r"(?m)^permissions:\n  contents: read\n(?!  \S)", path.name)
            self.assertNotRegex(text, r":\s*write\b", path.name)
            self.assertNotIn("secrets.", text, path.name)
            self.assertNotIn("write-all", text, path.name)

    def test_no_schedule_or_risky_triggers(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            for trigger in RISKY_TRIGGERS:
                self.assertNotRegex(text, rf"(?m)^\s*{trigger}\s*:", (path.name, trigger))

    def test_actions_are_pinned_to_full_commits(self):
        for path in WORKFLOWS:
            for ref in re.findall(r"uses:\s*([^\s#]+)", path.read_text(encoding="utf-8")):
                self.assertRegex(ref, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", (path.name, ref))

    def test_checkout_keeps_no_token(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            checkouts = text.count("actions/checkout@")
            self.assertEqual(text.count("persist-credentials: false"), checkouts, path.name)

    def test_ci_runs_the_two_commands_as_lint_and_test_jobs(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("name: lint", text)
        self.assertIn("name: test", text)
        self.assertIn("python dev.py lint", text)
        self.assertIn("python dev.py test", text)
        self.assertIn("--require-hashes", text)

    def test_ci_installs_the_runtime_pins_and_audits_them(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("pip install --require-hashes -r requirements.txt", text)
        self.assertIn("python tools/audit_deps.py requirements.txt", text)
        self.assertLess(text.index("tools/audit_deps.py"), text.index("python dev.py test"))


class App(unittest.TestCase):
    def test_no_outbound_network_or_process_execution(self):
        for path in sorted((ROOT / "mission_control").rglob("*.py")):
            bad = {m for m in imported_modules(path) if m in FORBIDDEN_IMPORTS}
            self.assertEqual(bad, set(), path.name)

    def test_the_app_never_imports_the_fetcher(self):
        # Phase A5a (issue #16): the fetcher is the only part with network access, in its own
        # package and process. The web app reads its snapshot file and never imports it.
        for path in sorted((ROOT / "mission_control").rglob("*.py")):
            uses = {m for m in imported_modules(path) if m.split(".")[0] == "mission_fetcher"}
            self.assertEqual(uses, set(), path.name)

    def test_sockets_are_unix_only(self):
        # No internet address families, name lookups or connection helpers anywhere in the app,
        # or in the fetcher's own code (its one HTTPS client is http.client, in github.py).
        banned = {"AF_INET", "AF_INET6", "create_connection", "getaddrinfo", "gethostbyname"}
        paths = list((ROOT / "mission_control").rglob("*.py"))
        paths += list((ROOT / "mission_fetcher").rglob("*.py"))
        for path in sorted(paths):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            self.assertEqual(names & banned, set(), path.name)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "socket"
                    and node.args
                ):
                    first = node.args[0]
                    self.assertTrue(
                        isinstance(first, ast.Attribute) and first.attr == "AF_UNIX",
                        (path.name, node.lineno),
                    )

    def test_only_the_fetchers_github_module_reaches_the_network(self):
        # Owner's decision for A5a (issues #15 and #16): one module may make outbound calls,
        # with http.client and ssl only, and nothing else in the fetcher may.
        network = {"http.client", "ssl"}
        for path in sorted((ROOT / "mission_fetcher").rglob("*.py")):
            modules = imported_modules(path)
            allowed = network if path.name == "github.py" else set()
            self.assertEqual((modules & FORBIDDEN_IMPORTS) - allowed, set(), path.name)

    def test_the_fetcher_talks_to_api_github_com_only(self):
        tree = ast.parse((ROOT / "mission_fetcher" / "github.py").read_text(encoding="utf-8"))
        hosts = [
            node.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "HOST" for t in node.targets)
        ]
        self.assertEqual(hosts, ["api.github.com"])
        connections = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("HTTPSConnection", "HTTPConnection")
        ]
        self.assertEqual(len(connections), 1)
        call = connections[0]
        self.assertEqual(call.func.attr, "HTTPSConnection")
        self.assertEqual(ast.unparse(call.args[0]), "HOST")
        self.assertEqual(ast.unparse(call.args[1]), "443")
        # No redirects or proxy settings: nothing reads the environment.
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        # TLS is set up by hand: create_default_context() honours SSLKEYLOGFILE and would write
        # session secrets (Codex's review of f772122).
        self.assertNotIn("create_default_context", names)
        self.assertNotIn("environ", names)
        self.assertNotIn("getenv", names)

    def test_the_stop_helper_cannot_remove_a_marker(self):
        tree = ast.parse((ROOT / "mission_control" / "stopper.py").read_text(encoding="utf-8"))
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        removers = {"unlink", "remove", "rmdir", "rename", "replace", "truncate", "ftruncate"}
        self.assertEqual(names & (removers | {"O_TRUNC", "shutil"}), set())

    def test_one_runtime_dependency_for_sign_in_only(self):
        # A4b (issue #10, owner decision 1): python-fido2, pinned with everything it needs by
        # hash in requirements.txt. Adding another needs the owner's approval in a PR.
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(text, r'(?m)^dependencies = \["fido2==2\.2\.1"\]$')
        self.assertIn("fido2==2.2.1 \\", (ROOT / "requirements.txt").read_text(encoding="utf-8"))


# Generic shapes of a server's details: absolute system paths, privilege escalation, a Node
# version manager folder, Tailscale machine names. Deliberately generic: the guard itself must
# not name any account or path of the real server, because this repository is public.
MACHINE_DETAILS = re.compile(
    r"(?<![\w.])/(?:home|opt|srv|etc|var/lib)/[A-Za-z0-9_.-]"
    r"|\bsudo\s"
    r"|\.nvm[/\\]"
    r"|\.ts\.net\b"
)


def tracked_text_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode()
    return [ROOT / name for name in out.split("\0") if name]


class Machine(unittest.TestCase):
    def test_no_details_of_the_server_are_committed(self):
        # Codex's reviews of bb74c3c and 09fd27d (blocking): the docs, then this guard's own
        # pattern, named the server's accounts and paths. No file is exempt, this one included.
        for path in tracked_text_files():
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(text.splitlines(), 1):
                self.assertIsNone(MACHINE_DETAILS.search(line), f"{path.name}:{number}")

    def test_the_pattern_catches_each_shape(self):
        # Samples are assembled at run time so this file contains none of the shapes.
        for sample in (
            "/" + "home/someone/x",
            "/" + "opt/tool/x",
            "/" + "var/lib/thing",
            "/" + "etc/hosts",
            "/" + "srv/www",
            "su" + "do -u x id",
            "~/." + "nvm/versions",
            "box.tail0." + "ts" + ".net",
        ):
            self.assertIsNotNone(MACHINE_DETAILS.search(sample), sample)

    def test_ordinary_text_passes(self):
        for sample in (
            "docs/owner-settings.md",
            "https://github.com/DrZaff/x",
            "a/home/b",
            "pseudo code",
            "--repo billy-mission-control",
            "127.0.0.1:8765",
        ):
            self.assertIsNone(MACHINE_DETAILS.search(sample), sample)


# The task-state model (phase A2) is pure: only these modules, and no I/O, clock or code
# execution, so the same input always gives the same answer with no side effects.
TASKS_ALLOWED_IMPORTS = {
    "__future__",
    "re",
    "collections.abc",
    "dataclasses",
    "datetime",
    "enum",
    "fnmatch",
    "typing",
}
TASKS_FORBIDDEN_CALLS = {"open", "print", "input", "eval", "exec", "compile", "__import__"}
TASKS_FORBIDDEN_ATTRIBUTES = {"now", "today", "utcnow", "time", "sleep", "environ", "getenv"}


class PureTaskModel(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / "mission_control" / "tasks.py"
        self.tree = ast.parse(self.path.read_text(encoding="utf-8"))

    def test_imports_only_pure_standard_modules(self):
        self.assertLessEqual(imported_modules(self.path), TASKS_ALLOWED_IMPORTS)

    def test_no_io_clock_or_code_execution(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, TASKS_FORBIDDEN_CALLS, node.lineno)
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, TASKS_FORBIDDEN_ATTRIBUTES, node.lineno)

    def test_no_module_level_mutable_state(self):
        for node in self.tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                self.assertNotIsInstance(node.value, (ast.List, ast.Dict, ast.Set), node.lineno)


class Ownership(unittest.TestCase):
    def test_codeowners_covers_every_path(self):
        lines = [
            line.split()
            for line in (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertIn(["*", "@DrZaff"], lines)
        # No later line may hand any path to someone else (the last match wins in CODEOWNERS).
        for parts in lines:
            self.assertEqual(parts[1:], ["@DrZaff"], parts)


if __name__ == "__main__":
    unittest.main()
