"""Fail if any file in the repository looks like it contains a credential.

A safety net, not a full scanner: it looks for the shapes of private keys and common tokens
(GitHub, Anthropic/OpenAI-style, AWS, Slack, JSON Web Tokens). Run by `python3 dev.py lint`.
Prints only the file and line number, never the matched text.

    python3 tools/check_secrets.py [path ...]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "API key (sk-...)": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "JSON Web Token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
}
MAX_BYTES = 2_000_000


def repository_files(root: Path) -> list[Path]:
    """Tracked files plus new, not-ignored ones (so a key is caught before it is committed)."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
    return [root / name for name in out.decode().split("\0") if name]


def scan(paths: list[Path]) -> list[tuple[Path, int, str]]:
    """Return (file, line number, kind) for every suspected credential."""
    hits = []
    for path in paths:
        try:
            if not path.is_file() or path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable: not a text credential
        for number, line in enumerate(text.splitlines(), 1):
            for kind, pattern in PATTERNS.items():
                if pattern.search(line):
                    hits.append((path, number, kind))
    return hits


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent.parent
    paths = [Path(a) for a in argv] or repository_files(root)
    hits = scan(paths)
    for path, number, kind in hits:
        print(f"{path}:{number}: looks like a {kind} (text not shown)")
    if hits:
        print("STOP: remove it, and if it was ever committed, treat it as leaked and rotate it.")
        return 1
    print(f"No credential-shaped text in {len(paths)} files.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
