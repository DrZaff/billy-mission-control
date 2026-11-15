"""The development server listens on IPv4 loopback only. One test starts it on a free loopback
port and stops it at once; nothing else listens."""

from __future__ import annotations

import contextlib
import io
import threading
import unittest
import urllib.request

from mission_control.__main__ import build_server, check_host, main


class LoopbackOnly(unittest.TestCase):
    def test_loopback_addresses_are_allowed(self):
        for host in ("127.0.0.1", "127.0.0.2", "localhost"):
            self.assertEqual(check_host(host), host)

    def test_everything_else_is_refused(self):
        # Every interface, a Tailscale address, a home-network address, a public name.
        for host in ("0.0.0.0", "::", "100.64.0.1", "192.168.1.20", "10.0.0.5", "example.com", ""):
            with self.assertRaises(ValueError, msg=host):
                check_host(host)

    def test_ipv6_loopback_is_refused_because_the_server_cannot_bind_it(self):
        # Codex's review of f12dded (should fix): ::1 passed the check, then failed at start-up.
        for host in ("::1", "0:0:0:0:0:0:0:1"):
            with self.assertRaises(ValueError, msg=host):
                check_host(host)

    def test_an_allowed_address_really_serves(self):
        server = build_server("127.0.0.1", 0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
                self.assertEqual(r.status, 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_main_stops_before_listening_on_a_refused_address(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--host", "0.0.0.0", "--port", "8765"])
        self.assertEqual(code, 2)
        self.assertIn("IPv4 loopback only", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
