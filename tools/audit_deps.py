"""Fail if any pinned runtime requirement has a known vulnerability.

    python3 tools/audit_deps.py [requirements.txt]

For each `name==version` in the file, it asks PyPI's JSON API for that exact release
(https://pypi.org/pypi/NAME/VERSION/json). Its "vulnerabilities" list is the same advisory data
pip-audit uses by default (the PyPA advisory database, through OSV). Standard library only, so
the check itself adds nothing to install or keep patched. Withdrawn advisories are ignored.

Exit codes: 0 no known vulnerabilities; 1 at least one; 2 the check could not be completed
(a network or format problem): a failed check never passes silently.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from collections.abc import Callable
from pathlib import Path

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!_-]+)\b")
API = "https://pypi.org/pypi/{name}/{version}/json"
TIMEOUT = 30


def pins(text: str) -> list[tuple[str, str]]:
    """Every `name==version` line (continuation lines and comments are skipped)."""
    found = []
    for line in text.splitlines():
        match = PIN.match(line.strip())
        if match:
            found.append((match.group(1), match.group(2)))
    return found


def fetch(url: str) -> dict:
    if not url.startswith("https://pypi.org/"):
        raise ValueError("refusing a non-PyPI address")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
    # Only https://pypi.org/ addresses reach this line (checked above).
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
        return json.load(response)


def known(data: dict) -> list[dict]:
    if "vulnerabilities" not in data or not isinstance(data["vulnerabilities"], list):
        raise ValueError("PyPI's answer has no vulnerabilities list")
    return [v for v in data["vulnerabilities"] if isinstance(v, dict) and not v.get("withdrawn")]


def audit(requirements: Path, get: Callable[[str], dict] = fetch) -> int:
    found = pins(requirements.read_text(encoding="utf-8"))
    if not found:
        print(f"STOP: no pinned requirements found in {requirements}", file=sys.stderr)
        return 2
    problems = 0
    for name, version in found:
        try:
            vulns = known(get(API.format(name=name, version=version)))
        except Exception as error:  # noqa: BLE001 - any failure means "not checked"
            print(f"STOP: {name}=={version} could not be checked ({type(error).__name__})")
            return 2
        if vulns:
            problems += 1
            for v in vulns:
                fixed = ", ".join(v.get("fixed_in") or []) or "no fix listed"
                print(f"VULNERABLE: {name}=={version} {v.get('id', '?')} (fixed in: {fixed})")
        else:
            print(f"ok: {name}=={version}")
    if problems:
        print(f"{problems} pinned package(s) have known vulnerabilities: update them in a PR.")
        return 1
    print(f"No known vulnerabilities in {len(found)} pinned package(s).")
    return 0


if __name__ == "__main__":
    sys.exit(audit(Path(sys.argv[1] if len(sys.argv) > 1 else "requirements.txt")))
