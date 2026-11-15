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


if __name__ == "__main__":
    sys.exit(main())
