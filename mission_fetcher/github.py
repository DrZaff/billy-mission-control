"""The only module in Mission Control that talks to the network, and only to api.github.com over
HTTPS (tests/test_policy.py checks both). Everything it receives is untrusted.

- No redirects are followed and no proxy settings are read: one fixed host, one fixed port.
- Every response is capped in size and must be JSON of the expected shape.
- Errors are short reason codes (FetchError.code), never a response body, header or token.
- The App's permissions are checked on every refresh, not only at start-up: the installation
  must have exactly the five read-only permissions, on exactly the configured repositories,
  and the token GitHub returns must say the same. Anything else refuses the refresh.
"""

from __future__ import annotations

import base64
import contextvars
import http.client
import json
import os
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HOST = "api.github.com"
PORT = 443
TIMEOUT = 15.0
REQUEST_LIMIT = 60.0  # seconds for a whole request
REVOKE_LIMIT = 15.0  # the token's revocation, which runs even past a refresh's limit
# The limit for the request being made now, set by GitHub.call for the transport.
_LIMIT: contextvars.ContextVar[float] = contextvars.ContextVar("request_limit", default=60.0)
MAX_RESPONSE = 4 * 1024 * 1024
# GraphQL error types GitHub gives when a query is too costly to finish.
HEAVY_KINDS = {"RESOURCE_LIMITS_EXCEEDED", "MAX_NODE_LIMIT_EXCEEDED", "TIMEOUT"}
USER_AGENT = "billy-mission-control-fetcher"
API_VERSION = "2022-11-28"
# Exactly these, all read-only (issue #15, decision 3). Metadata is GitHub's mandatory one.
EXPECTED_PERMISSIONS = {
    "checks": "read",
    "issues": "read",
    "metadata": "read",
    "pull_requests": "read",
    "statuses": "read",
}
# Any token GitHub issues, as long as it is safe in a header: printable, no spaces, bounded. Its
# format is GitHub's to change (newer installation tokens are longer and contain dots: Codex's
# review of bf76866); what the token may do is checked from GitHub's answer, not its shape.
TOKEN_SHAPE = re.compile(r"[\x21-\x7e]{20,4096}")

Response = tuple[int, dict[str, str], bytes]
Transport = Callable[[str, str, dict[str, str], bytes | None], Response]


class FetchError(Exception):
    """A refused or failed refresh. `code` is short and safe to log or show."""

    def __init__(self, code: str, paths: tuple = (), data: dict | None = None):
        super().__init__(code)
        self.code = code
        # For a GraphQL error: where in the answer each error is, as GitHub says (each a
        # tuple, or None when an error names no place). Never shown or logged.
        self.paths = paths
        # For a GraphQL error: the partial answer GitHub gave with it, if any. GitHub sets a
        # field it couldn't read to null, so the caller may use only what no error's place
        # touches (Codex's review of c3ee86b). Never shown or logged.
        self.data = data


def tls_context() -> ssl.SSLContext:
    """Certificate and host-name checks on, TLS 1.2 or newer, and never a key log: unlike
    ssl.create_default_context(), a bare SSLContext doesn't read SSLKEYLOGFILE, which would
    write session secrets that decrypt the App's JWTs and tokens (Codex's review of
    f772122)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verifies certificates and host names
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # The system's own trust store, by its compiled-in paths: load_default_certs() also obeys
    # SSL_CERT_FILE and SSL_CERT_DIR, so one variable in the environment could swap the trusted
    # authorities and hand the App's JWT and token to another host (audit of e58b933).
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile if os.path.isfile(paths.openssl_cafile or "") else None
    capath = paths.openssl_capath if os.path.isdir(paths.openssl_capath or "") else None
    if cafile is None and capath is None:
        raise FetchError("no-trust-store")
    context.load_verify_locations(cafile=cafile, capath=capath)
    context.keylog_filename = None
    return context


class _Connection(http.client.HTTPSConnection):
    """An HTTPS connection whose socket the watchdog can reach before the TLS handshake: the
    TCP connection is made, the socket wrapped without a handshake and handed over, and only
    then the handshake run, so a peer that drips it is cut off at the limit like any other read
    (audit of e58b933: the handshake ran out of the watchdog's reach, leaking a thread and a
    socket per timed-out request)."""

    def __init__(self, held: list, expired: threading.Event, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._held = held
        self._expired = expired

    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)  # TCP only, each step bounded by the timeout
        sock = self._context.wrap_socket(
            self.sock, server_hostname=self.host, do_handshake_on_connect=False
        )
        self.sock = sock
        self._held.append(sock)
        if self._expired.is_set():
            raise TimeoutError()
        sock.do_handshake()


def https_transport(method: str, path: str, headers: dict[str, str], body: bytes | None):
    """One HTTPS request to api.github.com. The real transport; tests pass a fake one."""
    expired = threading.Event()
    # The socket, kept from the moment it connects (before the handshake), for the watchdog:
    # the connection lets go of it for a response that ends with "Connection: close", while
    # the response still reads from it (Codex's review of d75f891).
    held: list = []
    conn = _Connection(held, expired, HOST, PORT, timeout=TIMEOUT, context=tls_context())

    # A whole request has a time limit, not only each socket operation (Codex's review of
    # 9dbb868). A check between reads can't enforce it: one read, or the status line and
    # headers, can drip a byte at a time for hours (Fable's pre-review of a21bd27). So a
    # watchdog shuts the connection's socket at the limit, whatever is waiting on it.
    def stop() -> None:
        expired.set()
        for sock in list(held):
            try:
                # The plain socket's shutdown: it wakes a blocked read without touching the TLS
                # state another thread is using.
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass

    limit = _LIMIT.get()
    started = time.monotonic()
    watchdog = threading.Timer(limit, stop)
    watchdog.daemon = True
    watchdog.start()
    try:
        # Connection setup (name lookup, TCP, TLS handshake) happens in a helper thread that
        # is waited for only until the limit: the watchdog can't reach a socket that isn't
        # connected yet (Codex's review of 0cf099c). One that finishes late closes itself.
        connected = threading.Event()
        failure: list[BaseException] = []

        def connect() -> None:
            try:
                conn.connect()
            except BaseException as error:  # noqa: BLE001 - handed to the waiting thread
                failure.append(error)
            finally:
                connected.set()
                if expired.is_set():
                    conn.close()

        threading.Thread(target=connect, daemon=True).start()
        if not connected.wait(max(0.0, limit - (time.monotonic() - started))):
            expired.set()
            raise TimeoutError()
        if failure:
            raise failure[0]
        if expired.is_set():  # the limit passed just as it connected
            raise TimeoutError()
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read(MAX_RESPONSE + 1)
        if expired.is_set():
            raise TimeoutError()
        # A connection that ended early gives fewer bytes than GitHub announced, with no error:
        # never taken as the whole answer (Codex's review of df5912d).
        length = resp.getheader("Content-Length")
        if len(data) <= MAX_RESPONSE and length is not None:
            if not length.isdigit() or int(length) != len(data):
                raise FetchError("network")
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
    except TimeoutError:
        raise FetchError("timeout") from None
    except (OSError, ValueError, http.client.HTTPException):
        raise FetchError("timeout" if expired.is_set() else "network") from None
    finally:
        watchdog.cancel()
        conn.close()


# What call() returns for GitHub's 204 No Content: distinct from any JSON body, null included.
NO_CONTENT = object()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_key(pem: bytes) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError):
        raise FetchError("key-unreadable") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise FetchError("key-not-rsa")
    return key


class GitHub:
    def __init__(
        self,
        app_id: int,
        key: rsa.RSAPrivateKey,
        transport: Transport = https_transport,
        clock: Callable[[], float] = time.time,
    ):
        self.app_id = app_id
        self.key = key
        self.transport = transport
        self.clock = clock
        # A monotonic time after which no request starts (a refresh's limit), or None.
        self.deadline: float | None = None

    # ------------------------------------------------------------ requests

    def app_jwt(self) -> str:
        """A short-lived JWT for the App itself (RS256), as GitHub documents: issued a minute in
        the past for clock drift, valid for nine minutes."""
        now = int(self.clock())
        header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = {"iat": now - 60, "exp": now + 540, "iss": str(self.app_id)}
        payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = self.key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{payload}.{_b64(signature)}"

    def call(
        self, method: str, path: str, bearer: str, payload: Any = None, final: bool = False
    ) -> Any:
        """One request. Within a refresh's limit (self.deadline), it starts only if time is
        left and gets only that time; `final` (the token's revocation) always runs, with its
        own short limit."""
        if not path.startswith("/") or "//" in path or "\n" in path or "\r" in path:
            raise FetchError("bad-path")
        limit = REVOKE_LIMIT if final else REQUEST_LIMIT
        if self.deadline is not None and not final:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise FetchError("too-slow")
            limit = min(limit, left)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + bearer,
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        token = _LIMIT.set(limit)
        try:
            status, resp_headers, data = self.transport(method, path, headers, body)
        except TimeoutError:
            raise FetchError("timeout") from None
        except OSError:
            raise FetchError("network") from None
        finally:
            _LIMIT.reset(token)
        if len(data) > MAX_RESPONSE:
            raise FetchError("too-large")
        if status == 429 or (status == 403 and resp_headers.get("x-ratelimit-remaining") == "0"):
            raise FetchError("rate-limited")
        if status == 401:
            raise FetchError("unauthorised")
        if status == 204:
            return NO_CONTENT
        # Only the successes GitHub gives these calls: 200, and 201 for a new token. Any other,
        # such as 206 Partial Content or 202 Accepted, is never taken as a whole answer
        # (Codex's review of 09f37a5).
        if status not in (200, 201):
            raise FetchError(f"http-{status}" if 100 <= status < 600 else "http-bad-status")
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            # RecursionError: deeply nested JSON (Fable's pre-review of 8152df0).
            raise FetchError("bad-response") from None

    # ------------------------------------------------------------ the read-only App

    def installation(self, owner: str, repos: list[str]) -> int:
        """The one installation that covers every configured repository, checked: this App,
        not suspended, on the owner's account, selected repositories, exactly the five
        read-only permissions."""
        found = set()
        for repo in repos:
            inst = self.call("GET", f"/repos/{repo}/installation", self.app_jwt())
            inst_id = inst.get("id") if isinstance(inst, dict) else None
            if not isinstance(inst_id, int) or isinstance(inst_id, bool):
                raise FetchError("bad-response")
            if inst.get("app_id") != self.app_id:
                raise FetchError("wrong-app")
            account = inst.get("account")
            if not isinstance(account, dict) or account.get("login") != owner:
                raise FetchError("wrong-account")
            # Left out is not "not suspended": the key must be there, null (pre-review of
            # 07c3480).
            if "suspended_at" not in inst:
                raise FetchError("bad-response")
            if inst.get("suspended_at") is not None or inst.get("suspended_by") is not None:
                raise FetchError("suspended")
            if inst.get("repository_selection") != "selected":
                raise FetchError("not-selected-repositories")
            if inst.get("permissions") != EXPECTED_PERMISSIONS:
                raise FetchError("not-read-only")
            found.add(inst["id"])
        if len(found) != 1:
            raise FetchError("several-installations")
        return found.pop()

    def token(self, installation_id: int) -> str:
        """An installation token, asked for with the read-only permissions only; GitHub's
        answer must grant exactly those."""
        answer = self.call(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            self.app_jwt(),
            {"permissions": EXPECTED_PERMISSIONS},
        )
        if not isinstance(answer, dict):
            raise FetchError("bad-response")
        token = answer.get("token")
        if not isinstance(token, str) or not TOKEN_SHAPE.fullmatch(token):
            raise FetchError("bad-token")
        if answer.get("permissions") != EXPECTED_PERMISSIONS:
            # Refused, and revoked first: it must not stay valid for its hour (Codex's review
            # of f772122).
            revoked = self.revoke(token)
            raise FetchError("token-not-read-only" + ("" if revoked else "+token-not-revoked"))
        # It must also be for the selected repositories only, and last about an hour, as the
        # warnings about a token left unrevoked say (pre-review of 6b7da87).
        if answer.get("repository_selection") != "selected" or not self._expires_soon(
            answer.get("expires_at")
        ):
            revoked = self.revoke(token)
            raise FetchError("token-not-limited" + ("" if revoked else "+token-not-revoked"))
        return token

    def _expires_soon(self, value: Any) -> bool:
        """Whether a token's expires_at is a real time, about an hour away. Bounded loosely, a
        day either way: the machine's clock may be off, and an exact bound would then fail
        every refresh; a token said to last for years is still refused."""
        if not isinstance(value, str):
            return False
        try:
            left = datetime.fromisoformat(value).timestamp() - self.clock()
        except (ValueError, OverflowError):
            return False
        return -86400 < left <= 86400

    def repositories(self, token: str, repos: list[str]) -> None:
        """The installation reaches exactly the configured repositories, no more."""
        answer = self.call("GET", "/installation/repositories?per_page=100", token)
        if not isinstance(answer, dict) or not isinstance(answer.get("repositories"), list):
            raise FetchError("bad-response")
        # Every row read, as text, and each once: the list is the proof of the App's reach, so
        # an odd or repeated row is never skipped or merged (Codex's review of df5912d).
        rows = answer["repositories"]
        names = [r.get("full_name") if isinstance(r, dict) else None for r in rows]
        if not all(isinstance(n, str) for n in names):
            raise FetchError("bad-response")
        # Nor may the list say the App can write, or reach every repository (pre-review of
        # 6b7da87).
        selection = answer.get("repository_selection", "selected")
        writes = any(
            isinstance(r.get("permissions"), dict)
            and any(r["permissions"].get(k) for k in ("admin", "maintain", "push"))
            for r in rows
        )
        if selection != "selected" or writes:
            raise FetchError("not-read-only")
        exact = len(names) == len(set(names)) == len(repos) and set(names) == set(repos)
        if answer.get("total_count") != len(repos) or not exact:
            raise FetchError("wrong-repositories")

    def graphql(
        self,
        token: str,
        query: str,
        variables: dict[str, Any],
        placeable: Callable[[tuple], bool] | None = None,
    ) -> dict:
        """The query's data. With `placeable`, a cost error GitHub placed where it says yes (a
        part the caller can leave out) is a partial error like any other; anywhere else, on a
        whole pull request, on the repository, or with no place, it is too heavy, and the
        caller splits the batch (pre-review of 6b7da87)."""
        answer = self.call("POST", "/graphql", token, {"query": query, "variables": variables})
        if not isinstance(answer, dict):
            raise FetchError("bad-response")
        # A present `errors` that isn't a list is a bad answer, whatever its truth value: an
        # empty object, an empty string or false was read as "no errors" (Codex's review of
        # c3ee86b). Only an empty list is.
        errors = answer.get("errors", [])
        if not isinstance(errors, list):
            raise FetchError("bad-response")
        if errors:
            # Only plain text types: anything else is ignored rather than raising (Codex's
            # review of 7faf35a: a list or object type raised TypeError).
            kinds = {
                e.get("type")
                for e in errors
                if isinstance(e, dict) and isinstance(e.get("type"), str)
            }
            if "RATE_LIMITED" in kinds:
                raise FetchError("rate-limited")
            paths = tuple(
                tuple(e["path"])
                if isinstance(e, dict)
                and isinstance(e.get("path"), list)
                and all(isinstance(p, (str, int)) and not isinstance(p, bool) for p in e["path"])
                else None
                for e in errors
            )
            # The partial answer goes with the error, never in its place: a caller that
            # doesn't look at the places gets no data at all (Codex's review of c3ee86b).
            data = answer.get("data")
            heavy = [
                path
                for e, path in zip(errors, paths, strict=True)
                if isinstance(e, dict)
                and isinstance(e.get("type"), str)
                and e["type"] in HEAVY_KINDS
            ]
            if heavy and (
                not isinstance(data, dict)
                or placeable is None
                or not all(p is not None and placeable(p) for p in heavy)
            ):
                # GitHub stopped the query for its cost, and placed it nowhere a part can be
                # left out: too heavy. One placed on such a part, with the rest of the answer,
                # is like any other partial error (Codex's review of b1f5a1a).
                raise FetchError("too-heavy")
            raise FetchError("graphql-error", paths, data if isinstance(data, dict) else None)
        data = answer.get("data")
        if not isinstance(data, dict):
            raise FetchError("bad-response")
        return data

    def revoke(self, token: str) -> bool:
        """Revoke the installation token. Best effort: it expires within the hour anyway."""
        try:
            # Only GitHub's 204 No Content confirms it, never a body that reads as null (Codex's
            # reviews of 09f37a5 and 6e22a60).
            return self.call("DELETE", "/installation/token", token, final=True) is NO_CONTENT
        except FetchError:
            return False
