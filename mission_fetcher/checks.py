"""The fetcher's start-up checks (phase A5a). Each fails closed; `selfcheck fetcher` prints them.

The same checks as the app's and the stop helper's (mission_control.checks), for the fetcher's
own files: it never runs as root or as the wrong account, never while it can read a forbidden
path (Billy's publisher key, the reviewer's credentials), and never with a config, key or
snapshot folder that another account could replace or read. The snapshot folder is shared with
the web app's account only, which reads the snapshot through the folder's group.

GitHub's side (read-only permissions, exactly the configured repositories) is checked on every
refresh (github.py) and by `selfcheck --github`.
"""

from __future__ import annotations

import os
import pwd
import stat
from collections.abc import Callable
from pathlib import Path

from mission_control.checks import (
    Check,
    _account_of,
    _uid_of,
    cannot_read,
    not_root,
    own_folder,
    private_file,
    protected_above,
    running_as,
)

from .config import FetcherConfig


def _primary_gid(account: str) -> int | None:
    try:
        return pwd.getpwnam(account).pw_gid
    except KeyError:
        return None


def key_file(path: Path, owner: int) -> Check:
    check = private_file(path, owner)
    return Check("reader key", check.ok, check.detail)


def shared_with_web_app(path: Path, client: str, gid_of: Callable[[str], int | None]) -> Check:
    """The snapshot folder: the web app's group may read it, nobody else may."""
    name = "snapshot folder shared with the web app only"
    gid = gid_of(client)
    try:
        info = os.lstat(path)
    except OSError:
        return Check(name, False, "missing or unreadable")
    if not stat.S_ISDIR(info.st_mode):
        return Check(name, False, "not a real folder")
    if gid is None or info.st_gid != gid:
        return Check(name, False, f"its group isn't {client}'s")
    if info.st_mode & 0o007:
        return Check(name, False, "other accounts can reach it")
    if info.st_mode & 0o050 != 0o050:
        return Check(name, False, f"{client} can't read it")
    if info.st_mode & 0o020:
        return Check(name, False, f"{client} could write to it")
    if not info.st_mode & stat.S_ISGID:
        # Without setgid, new files take the fetcher's own group and the web app can't read
        # them (Codex's review of f772122).
        return Check(name, False, "not setgid: new files wouldn't take its group (chmod 2750)")
    return Check(name, True, "yes")


def fetcher_checks(
    cfg: FetcherConfig,
    config_path: Path,
    uid: int | None = None,
    account_of: Callable[[int], str | None] = _account_of,
    opener: Callable[[str], int] | None = None,
    gid_of: Callable[[str], int | None] = _primary_gid,
) -> list[Check]:
    uid = os.geteuid() if uid is None else uid
    trusted = {0, uid}
    client = _uid_of(cfg.client_account)
    results = [
        not_root(uid),
        running_as(cfg.account, uid, account_of),
        Check(
            f"web app account {cfg.client_account}",
            client is not None and client not in (0, uid),
            "exists" if client is not None else "no such account",
        ),
        private_file(config_path, uid),
        protected_above(config_path, trusted),
        key_file(cfg.key, uid),
        protected_above(cfg.key, trusted),
        own_folder(cfg.snapshot_dir, uid, "snapshot folder"),
        shared_with_web_app(cfg.snapshot_dir, cfg.client_account, gid_of),
        protected_above(cfg.snapshot_dir, trusted),
    ]
    results += [cannot_read(p, opener) for p in cfg.forbidden_paths]
    return results
