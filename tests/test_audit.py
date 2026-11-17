"""The pinned-requirements vulnerability check (tools/audit_deps.py). No network: PyPI's
answers are faked."""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import audit_deps  # noqa: E402

REQUIREMENTS = """# comment
fido2==2.2.1 \\
    --hash=sha256:aaaa
cryptography==50.0.2 \\
    --hash=sha256:bbbb \\
    --hash=sha256:cccc
"""


class Audit(unittest.TestCase):
    def setUp(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: [p.unlink() for p in folder.iterdir()] and folder.rmdir())
        self.path = folder / "requirements.txt"
        self.path.write_text(REQUIREMENTS)

    def run_audit(self, answers):
        asked = []

        def get(url):
            asked.append(url)
            answer = answers(url)
            if isinstance(answer, Exception):
                raise answer
            return answer

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = audit_deps.audit(self.path, get)
        return code, out.getvalue(), asked

    def test_reads_every_pin_and_asks_pypi_for_that_exact_release(self):
        code, out, asked = self.run_audit(lambda url: {"vulnerabilities": []})
        self.assertEqual(code, 0)
        self.assertEqual(
            asked,
            [
                "https://pypi.org/pypi/fido2/2.2.1/json",
                "https://pypi.org/pypi/cryptography/50.0.2/json",
            ],
        )
        self.assertIn("No known vulnerabilities in 2 pinned package(s).", out)

    def test_a_known_vulnerability_fails(self):
        def answers(url):
            if "cryptography" in url:
                return {"vulnerabilities": [{"id": "GHSA-x", "fixed_in": ["51.0.0"]}]}
            return {"vulnerabilities": []}

        code, out, _ = self.run_audit(answers)
        self.assertEqual(code, 1)
        self.assertIn("VULNERABLE: cryptography==50.0.2 GHSA-x (fixed in: 51.0.0)", out)

    def test_a_withdrawn_advisory_is_ignored(self):
        code, _, _ = self.run_audit(
            lambda url: {"vulnerabilities": [{"id": "old", "withdrawn": "2026-01-01"}]}
        )
        self.assertEqual(code, 0)

    def test_a_failed_check_never_passes(self):
        for answer in (OSError("down"), {"no": "list"}, {"vulnerabilities": "x"}):
            code, out, _ = self.run_audit(lambda url, a=answer: a)
            self.assertEqual(code, 2, answer)
            self.assertIn("could not be checked", out)
        self.path.write_text("# nothing pinned\n")
        self.assertEqual(self.run_audit(lambda url: {"vulnerabilities": []})[0], 2)

    def test_only_pypi_is_ever_fetched(self):
        with self.assertRaises(ValueError):
            audit_deps.fetch("file:///tmp/anything")
        with self.assertRaises(ValueError):
            audit_deps.fetch("https://example.invalid/x")


if __name__ == "__main__":
    unittest.main()
