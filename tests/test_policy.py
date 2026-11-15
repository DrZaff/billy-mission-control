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

# Modules the app package must not import in phase A1: outbound network clients and process
# execution. (The development server's wsgiref is allowed; it only listens, on loopback.)
FORBIDDEN_IMPORTS = {
    "urllib.request",
    "http.client",
    "socket",
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


class App(unittest.TestCase):
    def test_no_outbound_network_or_process_execution(self):
        for path in sorted((ROOT / "mission_control").rglob("*.py")):
            bad = {m for m in imported_modules(path) if m in FORBIDDEN_IMPORTS}
            self.assertEqual(bad, set(), path.name)

    def test_no_runtime_dependencies(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^dependencies = \[\]$")


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
