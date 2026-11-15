"""The credential scanner catches each shape and never prints the matched text."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from tools import check_secrets

# Assembled at run time from harmless pieces, so this file itself contains no credential shape.
FAKES = {
    "private key": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "GitHub token": "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4",
    "API key (sk-...)": "s" + "k-" + "test0000000000000000000000",
    "AWS access key": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
    "Slack token": "xo" + "xb-" + "0000000000-abcdef",
    "JSON Web Token": "ey" + "J" + "hbGciOiJIUzI1" + "." + "eyJzdWIiOiIxMjM0" + "." + "abcdefgh",
}


class Scanner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name: str, text: str) -> Path:
        path = Path(self.dir.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_each_kind_is_found_with_its_line(self):
        for kind, fake in FAKES.items():
            path = self.write("f.txt", "first line\nvalue = " + fake + "\n")
            self.assertEqual(check_secrets.scan([path]), [(path, 2, kind)], kind)

    def test_ordinary_text_passes(self):
        path = self.write("ok.txt", "skip-this, task-1234, gh_pages, a secret word, AKIA short\n")
        self.assertEqual(check_secrets.scan([path]), [])

    def test_report_never_shows_the_secret(self):
        fake = FAKES["GitHub token"]
        path = self.write("f.txt", fake + "\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = check_secrets.main([str(path)])
        self.assertEqual(code, 1)
        self.assertNotIn(fake, out.getvalue())
        self.assertIn("text not shown", out.getvalue())

    def test_binary_files_are_skipped(self):
        path = Path(self.dir.name) / "b.bin"
        path.write_bytes(b"\xff\xfe\x00" + FAKES["private key"].encode())
        self.assertEqual(check_secrets.scan([path]), [])

    def test_this_repository_is_clean(self):
        root = Path(check_secrets.__file__).resolve().parent.parent
        self.assertEqual(check_secrets.scan(check_secrets.repository_files(root)), [])


if __name__ == "__main__":
    unittest.main()
