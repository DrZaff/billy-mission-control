"""The two developer commands. CI runs exactly these.

python3 dev.py lint   # ruff check, ruff format --check, credential scan
python3 dev.py test   # unit tests (standard library unittest; no install needed)
"""

from __future__ import annotations

import subprocess
import sys

PY = sys.executable

COMMANDS = {
    "lint": [
        [PY, "-m", "ruff", "check", "."],
        [PY, "-m", "ruff", "format", "--check", "."],
        [PY, "tools/check_secrets.py"],
    ],
    "test": [
        [PY, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
    ],
}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in COMMANDS:
        print("usage: python3 dev.py lint | test", file=sys.stderr)
        return 2
    for command in COMMANDS[argv[0]]:
        print("$ " + " ".join(command[1:] if command[0] == PY else command), flush=True)
        result = subprocess.run(command)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
