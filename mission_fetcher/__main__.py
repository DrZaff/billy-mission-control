"""The fetcher's commands (phase A5a, issue #16):

    python3 -m mission_fetcher serve --config FILE             from its systemd socket unit
    python3 -m mission_fetcher selfcheck [--github] --config FILE
    python3 -m mission_fetcher fetch-now --config FILE         one refresh, for installing

Each refuses to start unless every start-up check passes (checks.py). `--github` also checks
the App on GitHub: the five read-only permissions, exactly the configured repositories, and a
read-only token, which is revoked straight away. It runs like a refresh, under the same lock and
one-minute floor, and records its attempt in the status file: wait a minute before `fetch-now`.
"""

from __future__ import annotations

import argparse
import os
import pwd
import sys
from datetime import UTC, datetime
from pathlib import Path

from mission_control.checks import Check, failures, report
from mission_control.config import shown

from .checks import fetcher_checks
from .config import ConfigError, parse_fetcher
from .github import FetchError
from .snapshot import open_regular

MAX_CONFIG = 65536


def read_config(path: str) -> str:
    fd = open_regular(path)  # never a FIFO that could hang start-up (Codex, b1fef32)
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_CONFIG + 1)
    if len(data) > MAX_CONFIG:
        raise ValueError("the config file is too large")
    return data.decode("utf-8")


def _fail(message: str) -> int:
    print("STOP: " + message, file=sys.stderr)
    return 2


def github_checks(cfg, github) -> list[Check]:
    """The App on GitHub, checked the way every refresh checks it. Codes only, never a token."""
    repos = sorted(cfg.repos)
    try:
        installation = github.installation(cfg.owner, repos)
    except FetchError as error:
        return [Check("App installation: read-only, selected repositories", False, error.code)]
    results = [Check("App installation: read-only, selected repositories", True, "yes")]
    try:
        token = github.token(installation)
    except FetchError as error:
        return results + [Check("read-only token", False, error.code)]
    results.append(Check("read-only token", True, "yes"))
    try:
        github.repositories(token, repos)
        # Counted, never named: the names are the config's own text (Codex's review of 9cc8f43).
        results.append(Check(f"exactly {len(repos)} repositories", True, "yes"))
    except FetchError as error:
        results.append(Check(f"exactly {len(repos)} repositories", False, error.code))
    finally:
        revoked = github.revoke(token)
    results.append(Check("token revoked", revoked, "yes" if revoked else "expires within the hour"))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m mission_fetcher")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve").add_argument("--config", required=True)
    check = sub.add_parser("selfcheck")
    check.add_argument("--github", action="store_true", help="also check the App on GitHub")
    check.add_argument("--config", required=True)
    sub.add_parser("fetch-now").add_argument("--config", required=True)
    args = parser.parse_args(argv)

    try:
        cfg = parse_fetcher(read_config(args.config))
    except (OSError, ValueError, ConfigError) as error:
        detail = shown(error) if isinstance(error, ConfigError) else type(error).__name__
        return _fail("the config could not be read: " + detail)

    results = fetcher_checks(cfg, Path(args.config))
    if args.command == "selfcheck":
        if args.github and not failures(results):
            from .server import Refresher, github_for

            os.umask(0o077)
            refresher = Refresher(cfg)
            reply = refresher.run(lambda: github_checks(cfg, github_for(cfg))).decode().strip()
            results += refresher.results
            if not refresher.results:
                # Too soon, busy or failed before any check: said, never skipped (audits of
                # e58b933 and 24973b8).
                results.append(Check("GitHub checks", False, reply))
        print(report(results))
        failed = failures(results)
        print(f"{len(results) - len(failed)} of {len(results)} checks passed.")
        return 1 if failed else 0
    if failures(results):
        print(report(failures(results)), file=sys.stderr)
        return _fail("start-up checks failed; nothing was started")

    os.umask(0o077)
    from .server import Refresher, serve

    refresher = Refresher(cfg)
    if args.command == "fetch-now":
        reply = refresher.run().decode().strip()
        print(f"Refresh at {datetime.now(UTC).isoformat()}: {reply}")
        return 0 if reply == "ok" else 1

    from mission_control.service import systemd_socket

    try:
        listener = systemd_socket()
    except RuntimeError as error:
        return _fail(str(error))
    client_uid = pwd.getpwnam(cfg.client_account).pw_uid  # exists: checked at start-up
    print("Fetcher ready.", flush=True)
    serve(listener, refresher, client_uid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
