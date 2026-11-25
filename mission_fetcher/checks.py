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

import errno
import grp
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


def _members(gid: int) -> set[str]:
    """Every account in a group: its listed members and every account whose primary group it
    is (the group file lists only the former)."""
    try:
        listed = set(grp.getgrgid(gid).gr_mem)
    except KeyError:
        listed = set()
    return listed | {p.pw_name for p in pwd.getpwall() if p.pw_gid == gid}


ACL_ATTRIBUTES = ("system.posix_acl_access", "system.posix_acl_default")


def _has_acl(path: str) -> bool:
    """Whether a POSIX ACL is (or may be) set on `path` (Linux keeps them as extended
    attributes). Only a file system without extended attributes proves there is none; any other
    failure to look counts as one, so the check fails closed (Codex's review of b24ac2d)."""
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        return error.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP)
    return any(name in ACL_ATTRIBUTES for name in names)


def no_acls(folder: Path, has_acl: Callable[[str], bool] = _has_acl) -> Check:
    """No ACL on the snapshot folder or anything in it, so its mode bits and group alone say
    who can read the snapshot (Codex's review of bf76866: a named ACL could let another
    account in, and a default one pass that on to every new snapshot)."""
    name = "no ACLs on the snapshot folder or its files"
    try:
        entries = [str(folder)] + [e.path for e in os.scandir(folder)]
    except OSError:
        return Check(name, False, "unreadable")
    found = [os.path.basename(p) or p for p in entries if has_acl(p)]
    if found:
        return Check(name, False, "ACL on " + ", ".join(found[:5]) + " (remove with setfacl -b)")
    return Check(name, True, "none")


def _groups_of(account: str) -> tuple[int, set[int]] | None:
    try:
        entry = pwd.getpwnam(account)
    except KeyError:
        return None
    return entry.pw_uid, set(os.getgrouplist(account, entry.pw_gid))


def reachable_by(
    path: Path, account: str, groups_of: Callable[[str], tuple[int, set[int]] | None] = _groups_of
) -> Check:
    """The web app's account can pass through every folder above the snapshot folder (Codex's
    review of 23bfb61: protected folders can still shut it out). The mode bits decide it, so a
    folder with an ACL, which can override them for one account and which this process can't
    evaluate for another, fails the check (Codex's review of ab64500)."""
    name = f"{account} can reach the snapshot folder"
    ids = groups_of(account)
    if ids is None:
        return Check(name, False, "no such account")
    uid, gids = ids
    for parent in path.parents:
        try:
            info = os.stat(parent)
        except OSError:
            return Check(name, False, f"{parent} is unreadable")
        if _has_acl(str(parent)):
            return Check(name, False, f"{parent} has an ACL; its access can't be checked")
        mode = info.st_mode
        if info.st_uid == uid:
            ok = mode & 0o100
        elif info.st_gid in gids:
            ok = mode & 0o010
        else:
            ok = mode & 0o001
        if not ok:
            return Check(name, False, f"it can't pass through {parent}")
    return Check(name, True, "yes")


def key_file(path: Path, owner: int) -> Check:
    check = private_file(path, owner)
    return Check("reader key", check.ok, check.detail)


def shared_with_web_app(
    path: Path,
    client: str,
    gid_of: Callable[[str], int | None],
    members_of: Callable[[int], set[str]] = _members,
) -> Check:
    """The snapshot folder: the web app's group may read it, nobody else may. The group must
    hold the web app's account alone (Codex's review of 1cc6cf8: any other member could read
    the snapshot through it)."""
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
    others = sorted(members_of(gid) - {client})
    if others:
        return Check(name, False, f"its group has other members: {', '.join(others)}")
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
    members_of: Callable[[int], set[str]] = _members,
    groups_of: Callable[[str], tuple[int, set[int]] | None] = _groups_of,
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
        shared_with_web_app(cfg.snapshot_dir, cfg.client_account, gid_of, members_of),
        no_acls(cfg.snapshot_dir),
        protected_above(cfg.snapshot_dir, trusted),
        reachable_by(cfg.snapshot_dir, cfg.client_account, groups_of),
    ]
    results += [cannot_read(p, opener) for p in cfg.forbidden_paths]
    return results
