"""Server configuration for phase A4a. The real files live only on the server, never here.

Two files, one per process, each readable only by its own account:

- the web app's (`python3 -m mission_control serve --config FILE`): `config.example.json`
- the stop helper's (`python3 -m mission_control stopper --config FILE`): `stopper.example.json`

This module checks only their shape. Whether the paths are safe on the machine (owners, modes,
symlinks, the folders above them) is checked at start-up by `checks.py`, and reported by
`python3 -m mission_control selfcheck`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ORIGIN = re.compile(r"https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
# A Tailscale login: an email-like name or a GitHub-style login, nothing that needs escaping.
LOGIN = re.compile(r"[A-Za-z0-9._%+-]{1,64}(@[A-Za-z0-9.-]{1,190})?")
ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class AppConfig:
    origin: str
    owner_login: str
    service_account: str
    proxy_uids: tuple[int, ...]
    stop_socket: Path
    events_db: Path
    forbidden_paths: tuple[Path, ...]


@dataclass(frozen=True)
class StopperConfig:
    account: str
    control_dir: Path
    client_account: str
    forbidden_paths: tuple[Path, ...]


def _req(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def _keys(data: Any, expected: set[str], name: str) -> dict:
    _req(isinstance(data, dict), f"{name} must be a JSON object")
    missing, extra = expected - set(data), set(data) - expected
    _req(not missing, f"{name} is missing: {', '.join(sorted(missing))}")
    _req(not extra, f"{name} has unknown keys: {', '.join(sorted(extra))}")
    return data


def _path(value: Any, name: str) -> Path:
    _req(isinstance(value, str) and value.startswith("/"), f"{name} must be an absolute path")
    _req("\x00" not in value and len(value) <= 300, f"{name} is not a usable path")
    path = Path(value)
    _req(".." not in path.parts and str(path) == value.rstrip("/"), f"{name} must be normalised")
    return path


def _account(value: Any, name: str) -> str:
    _req(isinstance(value, str) and bool(ACCOUNT.fullmatch(value)), f"{name} must be an account")
    _req(value != "root", f"{name} must not be root")
    return value


def _paths(value: Any, name: str) -> tuple[Path, ...]:
    _req(isinstance(value, list) and len(value) > 0, f"{name} must list at least one path")
    return tuple(_path(v, f"{name}[]") for v in value)


def _load(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        raise ConfigError("the config is not valid JSON") from None


def parse_app(text: str) -> AppConfig:
    d = _keys(
        _load(text),
        {
            "origin",
            "owner_login",
            "service_account",
            "proxy_uids",
            "stop_socket",
            "events_db",
            "forbidden_paths",
        },
        "config",
    )
    origin = d["origin"]
    _req(isinstance(origin, str) and bool(ORIGIN.fullmatch(origin)), "origin must be https://host")
    login = d["owner_login"]
    _req(isinstance(login, str) and bool(LOGIN.fullmatch(login)), "owner_login is not a login")
    uids = d["proxy_uids"]
    _req(
        isinstance(uids, list)
        and 0 < len(uids) <= 4
        and all(isinstance(u, int) and not isinstance(u, bool) and u >= 0 for u in uids),
        "proxy_uids must list the accounts allowed to connect (tailscaled: 0)",
    )
    return AppConfig(
        origin=origin,
        owner_login=login,
        service_account=_account(d["service_account"], "service_account"),
        proxy_uids=tuple(uids),
        stop_socket=_path(d["stop_socket"], "stop_socket"),
        events_db=_path(d["events_db"], "events_db"),
        forbidden_paths=_paths(d["forbidden_paths"], "forbidden_paths"),
    )


def parse_stopper(text: str) -> StopperConfig:
    d = _keys(
        _load(text), {"account", "control_dir", "client_account", "forbidden_paths"}, "config"
    )
    account = _account(d["account"], "account")
    client = _account(d["client_account"], "client_account")
    _req(account != client, "the stop helper and the web app must be different accounts")
    return StopperConfig(
        account=account,
        control_dir=_path(d["control_dir"], "control_dir"),
        client_account=client,
        forbidden_paths=_paths(d["forbidden_paths"], "forbidden_paths"),
    )
