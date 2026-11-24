"""The fetcher's configuration. The real file lives only on the server, never here;
`fetcher.example.json` shows its shape. This module checks only the shape: whether the paths are
safe on the machine is checked at start-up (checks.py) and by `selfcheck`.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mission_control.config import (
    ConfigError,
    _account,
    _keys,
    _load,
    _path,
    _paths,
    _req,
)

# GitHub's own rules for owner and repository names, and for logins.
REPO = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}")
LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
CHECK_NAME = re.compile(r"[^\x00-\x1f\x7f]{1,100}")
MAX_REPOS = 4

__all__ = ["ConfigError", "FetcherConfig", "RepoSettings", "parse_fetcher"]


@dataclass(frozen=True)
class RepoSettings:
    required_checks: tuple[str, ...]
    clinical_paths: tuple[str, ...]


@dataclass(frozen=True)
class FetcherConfig:
    account: str
    client_account: str
    app_id: int
    key: Path
    snapshot_dir: Path
    owner: str
    clinicians: tuple[str, ...]
    repos: dict[str, RepoSettings]
    forbidden_paths: tuple[Path, ...]


def _login(value: Any, name: str) -> str:
    _req(isinstance(value, str) and bool(LOGIN.fullmatch(value)), f"{name} must be a login")
    return value


def _repo_settings(name: str, value: Any) -> RepoSettings:
    d = _keys(value, {"required_checks", "clinical_paths"}, f"repos.{name}")
    checks = d["required_checks"]
    _req(
        isinstance(checks, list)
        and 0 < len(checks) <= 20
        and all(isinstance(c, str) and CHECK_NAME.fullmatch(c) for c in checks),
        f"repos.{name}.required_checks must name at least one check",
    )
    paths = d["clinical_paths"]
    _req(
        isinstance(paths, list)
        and len(paths) <= 50
        and all(isinstance(p, str) and 0 < len(p) <= 200 and "\x00" not in p for p in paths),
        f"repos.{name}.clinical_paths must be a list of patterns (it may be empty)",
    )
    for pattern in paths:
        fnmatch.translate(pattern)  # a pattern fnmatch can't read fails here, not at runtime
    return RepoSettings(required_checks=tuple(checks), clinical_paths=tuple(paths))


def parse_fetcher(text: str) -> FetcherConfig:
    d = _keys(
        _load(text),
        {
            "account",
            "client_account",
            "app_id",
            "key",
            "snapshot_dir",
            "owner",
            "clinicians",
            "repos",
            "forbidden_paths",
        },
        "config",
    )
    account = _account(d["account"], "account")
    client = _account(d["client_account"], "client_account")
    _req(account != client, "the fetcher and the web app must be different accounts")
    app_id = d["app_id"]
    _req(
        isinstance(app_id, int) and not isinstance(app_id, bool) and 0 < app_id < 10**12,
        "app_id must be the GitHub App's number",
    )
    clinicians = d["clinicians"]
    _req(
        isinstance(clinicians, list) and 0 < len(clinicians) <= 10,
        "clinicians must list at least one login",
    )
    repos = d["repos"]
    _req(
        isinstance(repos, dict) and 0 < len(repos) <= MAX_REPOS,
        f"repos must name one to {MAX_REPOS} repositories",
    )
    settings = {}
    for name, value in repos.items():
        _req(REPO.fullmatch(name) is not None, f"repos: {name!r} is not owner/name")
        settings[name] = _repo_settings(name, value)
    return FetcherConfig(
        account=account,
        client_account=client,
        app_id=app_id,
        key=_path(d["key"], "key"),
        snapshot_dir=_path(d["snapshot_dir"], "snapshot_dir"),
        owner=_login(d["owner"], "owner"),
        clinicians=tuple(_login(c, "clinicians[]") for c in clinicians),
        repos=settings,
        forbidden_paths=_paths(d["forbidden_paths"], "forbidden_paths"),
    )
