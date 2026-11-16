"""Start-up checks for phase A4a. Each one fails closed; `selfcheck` prints them all.

The web app and the stop helper refuse to start unless every check passes: they never run as
root or as the wrong account, never while they can read a forbidden path (the publisher's key,
worker credentials), and never with a config, socket, database or control folder that another
account could replace or read. Folders above each path must be real folders, not symlinks,
owned by root or by the account itself, and not writable by others (unless sticky).
"""

from __future__ import annotations

import os
import pwd
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from .config import AppConfig, StopperConfig


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _account_of(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def not_root(uid: int) -> Check:
    return Check("not root", uid != 0, "runs as root" if uid == 0 else "runs unprivileged")


def running_as(account: str, uid: int, account_of: Callable[[int], str | None]) -> Check:
    actual = account_of(uid)
    return Check(f"runs as {account}", actual == account, f"runs as {actual or uid}")


def _writable_by_others(info: os.stat_result) -> bool:
    return bool(info.st_mode & 0o022) and not info.st_mode & stat.S_ISVTX


def protected_above(path: Path, trusted: Iterable[int]) -> Check:
    """Every folder above `path` is a real folder owned by a trusted account and not writable
    by others (a sticky folder such as /tmp is allowed: others can't replace our entries)."""
    trusted = set(trusted)
    for parent in path.parents:
        try:
            info = os.lstat(parent)
        except OSError:
            return Check(f"folders above {path.name}", False, f"{parent} is unreadable")
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return Check(f"folders above {path.name}", False, f"{parent} is not a real folder")
        if info.st_uid not in trusted or _writable_by_others(info):
            return Check(f"folders above {path.name}", False, f"{parent} is not protected")
    return Check(f"folders above {path.name}", True, "protected")


def private_file(path: Path, owner: int) -> Check:
    """A regular file (not a symlink) owned by `owner`, unreadable and unwritable by others."""
    name = f"config {path.name}"
    try:
        info = os.lstat(path)
    except OSError:
        return Check(name, False, "missing or unreadable")
    if not stat.S_ISREG(info.st_mode):
        return Check(name, False, "not a regular file (a symlink is refused)")
    if info.st_uid != owner:
        return Check(name, False, "owned by another account")
    if info.st_mode & 0o077:
        return Check(name, False, "another account (or its group) can read or write it")
    return Check(name, True, "private")


DATABASE_FILES = ("", "-journal", "-wal", "-shm")


def private_database(path: Path, owner: int) -> Check:
    """The events database and SQLite's side files, where they exist: regular files (not
    symlinks) owned by `owner` that nobody else can read or write. A missing database is fine:
    the service creates it privately."""
    for suffix in DATABASE_FILES:
        part = Path(str(path) + suffix)
        try:
            info = os.lstat(part)
        except FileNotFoundError:
            continue
        except OSError:
            return Check("events database", False, f"{part.name} is unreadable")
        if not stat.S_ISREG(info.st_mode):
            return Check("events database", False, f"{part.name} is not a regular file")
        if info.st_uid != owner or info.st_mode & 0o077:
            return Check("events database", False, f"{part.name} is not private")
    return Check("events database", True, "private, or not created yet")


def own_folder(path: Path, owner: int, label: str) -> Check:
    """A real folder owned by `owner` that nobody else can write to."""
    try:
        info = os.lstat(path)
    except OSError:
        return Check(label, False, "missing or unreadable")
    if not stat.S_ISDIR(info.st_mode):
        return Check(label, False, "not a real folder (a symlink is refused)")
    if info.st_uid != owner:
        return Check(label, False, "owned by another account")
    if info.st_mode & 0o022:
        return Check(label, False, "others can write to it")
    return Check(label, True, "protected")


def cannot_read(path: Path, opener: Callable[[str], int] | None = None) -> Check:
    """The account must not be able to open `path` at all. A path that doesn't exist fails too:
    the config should list only real paths, so a typo can't silently skip the check."""
    name = f"cannot read {path}"
    opener = opener or (lambda p: os.open(p, os.O_RDONLY))
    try:
        fd = opener(str(path))
    except PermissionError:
        return Check(name, True, "refused, as it should be")
    except FileNotFoundError:
        return Check(name, False, "does not exist: list only real paths")
    except OSError as error:
        return Check(name, False, f"could not be checked ({type(error).__name__})")
    os.close(fd)
    return Check(name, False, "READABLE: this account can read it")


def app_checks(
    cfg: AppConfig,
    config_path: Path,
    uid: int | None = None,
    account_of: Callable[[int], str | None] = _account_of,
    opener: Callable[[str], int] | None = None,
) -> list[Check]:
    uid = os.geteuid() if uid is None else uid
    trusted = {0, uid}
    results = [
        not_root(uid),
        running_as(cfg.service_account, uid, account_of),
        private_file(config_path, uid),
        protected_above(config_path, trusted),
        own_folder(cfg.events_db.parent, uid, "events folder"),
        private_database(cfg.events_db, uid),
        protected_above(cfg.events_db.parent, trusted),
        protected_above(cfg.stop_socket, trusted),
    ]
    results += [cannot_read(p, opener) for p in cfg.forbidden_paths]
    return results


def stopper_checks(
    cfg: StopperConfig,
    config_path: Path,
    uid: int | None = None,
    account_of: Callable[[int], str | None] = _account_of,
    opener: Callable[[str], int] | None = None,
) -> list[Check]:
    uid = os.geteuid() if uid is None else uid
    trusted = {0, uid}
    results = [
        not_root(uid),
        running_as(cfg.account, uid, account_of),
        private_file(config_path, uid),
        protected_above(config_path, trusted),
        own_folder(cfg.control_dir, uid, "control folder"),
        protected_above(cfg.control_dir, trusted),
    ]
    results += [cannot_read(p, opener) for p in cfg.forbidden_paths]
    return results


def failures(results: Iterable[Check]) -> list[Check]:
    return [c for c in results if not c.ok]


def report(results: Iterable[Check]) -> str:
    return "\n".join(f"{'PASS' if c.ok else 'FAIL'}: {c.name}: {c.detail}" for c in results)
