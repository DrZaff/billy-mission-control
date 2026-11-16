"""Local development server: python3 -m mission_control [--port 8765]

For development on your own machine only. It listens on an IPv4 loopback address (127.0.0.1 by
default, or localhost) and refuses any other, so it can never be reached from the network.
wsgiref's server binds IPv4 only, so the IPv6 loopback (::1) is refused rather than accepted
and then failing at start-up. Running Mission Control on the Dell over
Tailscale, with a passkey, is phase A4; nothing here installs or exposes a service.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from wsgiref.simple_server import make_server

from .app import application

LOOPBACK_NAMES = {"localhost"}


def check_host(host: str) -> str:
    """Return host if it is an IPv4 loopback address or localhost; otherwise raise ValueError."""
    if host in LOOPBACK_NAMES:
        return host
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if isinstance(address, ipaddress.IPv4Address) and address.is_loopback:
        return host
    raise ValueError(
        f"refusing to listen on {host!r}: development serving is IPv4 loopback only "
        "(127.0.0.1 or localhost) until phase A4"
    )


def build_server(host: str, port: int):
    """The development server, after the host check. Port 0 picks a free port (tests)."""
    return make_server(check_host(host), port, application)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Billy Mission Control, local development only.")
    parser.add_argument("--host", default="127.0.0.1", help="127.0.0.1 (default) or localhost")
    parser.add_argument("--port", type=int, default=8765, help="port (default 8765)")
    args = parser.parse_args(argv)
    try:
        server = build_server(args.host, args.port)
    except ValueError as error:
        print(f"STOP: {error}", file=sys.stderr)
        return 2
    with server:
        print(f"Serving on http://{args.host}:{args.port}/ (loopback only; Ctrl+C to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


# ---------------------------------------------------------------- phase A4a service commands
#
#   python3 -m mission_control serve --config FILE          the web app (systemd socket unit)
#   python3 -m mission_control stopper --config FILE        the stop helper (its own socket unit)
#   python3 -m mission_control selfcheck app|stopper --config FILE
#   python3 -m mission_control export-events --config FILE --since YYYY-MM-DD --out FILE
#
# Each refuses to start unless every start-up check passes (checks.py).

SERVICE_COMMANDS = ("serve", "stopper", "selfcheck", "export-events")
MAX_CONFIG = 65536


def read_config(path: str) -> str:
    """The config's text, read without following a symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_CONFIG + 1)
    if len(data) > MAX_CONFIG:
        raise ValueError("the config file is too large")
    return data.decode("utf-8")


def _fail(message: str) -> int:
    print("STOP: " + message, file=sys.stderr)
    return 2


def _app_config(path: str):
    from .config import parse_app

    return parse_app(read_config(path))


def _stopper_config(path: str):
    from .config import parse_stopper

    return parse_stopper(read_config(path))


def service_main(argv: list[str]) -> int:
    from . import checks
    from .config import ConfigError

    parser = argparse.ArgumentParser(prog="python3 -m mission_control")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "stopper"):
        sub.add_parser(name).add_argument("--config", required=True)
    check = sub.add_parser("selfcheck")
    check.add_argument("kind", choices=("app", "stopper"))
    check.add_argument("--config", required=True)
    export = sub.add_parser("export-events")
    export.add_argument("--config", required=True)
    export.add_argument("--since", required=True, help="YYYY-MM-DD (UTC)")
    export.add_argument("--out", required=True, help="a new file; never overwritten")
    args = parser.parse_args(argv)

    try:
        if args.command == "selfcheck":
            kind = args.kind
            cfg = _app_config(args.config) if kind == "app" else _stopper_config(args.config)
        else:
            kind = "stopper" if args.command == "stopper" else "app"
            cfg = _app_config(args.config) if kind == "app" else _stopper_config(args.config)
    except (OSError, ValueError, ConfigError) as error:
        detail = str(error) if isinstance(error, ConfigError) else type(error).__name__
        return _fail("the config could not be read: " + detail)

    from pathlib import Path

    path = Path(args.config)
    results = (checks.app_checks if kind == "app" else checks.stopper_checks)(cfg, path)
    if args.command == "selfcheck":
        print(checks.report(results))
        failed = checks.failures(results)
        print(f"{len(results) - len(failed)} of {len(results)} checks passed.")
        return 1 if failed else 0
    if checks.failures(results):
        print(checks.report(checks.failures(results)), file=sys.stderr)
        return _fail("start-up checks failed; nothing was started")

    if args.command == "export-events":
        from .events import Events

        try:
            count = Events(cfg.events_db).export(args.since, Path(args.out))
        except (OSError, ValueError) as error:
            return _fail("export failed: " + type(error).__name__)
        print(f"Exported {count} event(s) to {args.out}.")
        return 0

    from .service import systemd_socket

    try:
        listener = systemd_socket()
    except RuntimeError as error:
        return _fail(str(error))

    if args.command == "stopper":
        import pwd

        from .stopper import serve

        client_uid = pwd.getpwnam(cfg.client_account).pw_uid
        print("Stop helper ready.", flush=True)
        serve(listener, cfg.control_dir, os.geteuid(), client_uid, log=print)
        return 0

    from .app import Service, make_app
    from .events import Events
    from .service import UnixWSGIServer
    from .stopper import request_stop

    os.umask(0o077)  # SQLite's journal and any other file this process makes stay private
    events = Events(cfg.events_db)
    try:
        events.initialise()
    except Exception:  # noqa: BLE001 - a broken log never stops the service, or the stop
        print("WARNING: the events log could not be opened; pages will say so.", flush=True)
    service = Service(config=cfg, events=events, stop=lambda: request_stop(cfg.stop_socket))
    server = UnixWSGIServer(
        listener,
        make_app(service=service),
        cfg.proxy_uids,
        on_refused=lambda uid: events.append("refused-connection", detail=f"uid {uid}"),
        on_rejected=lambda code: events.append("rejected-request", status=code),
    )
    print("Mission Control ready (supervised testing only).", flush=True)
    server.serve_forever()
    return 0


def entry(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in SERVICE_COMMANDS:
        return service_main(argv)
    return main(argv)


if __name__ == "__main__":
    sys.exit(entry())
