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
import http.client
import json
import re
import ssl
import time
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HOST = "api.github.com"
TIMEOUT = 15.0
REQUEST_LIMIT = 60.0  # seconds for a whole request
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
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    context.keylog_filename = None
    return context


def https_transport(method: str, path: str, headers: dict[str, str], body: bytes | None):
    """One HTTPS request to api.github.com. The real transport; tests pass a fake one."""
    conn = http.client.HTTPSConnection(HOST, 443, timeout=TIMEOUT, context=tls_context())
    try:
        # A whole request has a time limit too, not only each socket operation: a slow drip
        # could otherwise run far past the refresh's limit (Codex's review of 9dbb868).
        ends = time.monotonic() + REQUEST_LIMIT
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        chunks, size = [], 0
        while size <= MAX_RESPONSE:
            if time.monotonic() > ends:
                raise TimeoutError()
            chunk = resp.read(min(64 * 1024, MAX_RESPONSE + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        data = b"".join(chunks)
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
    except TimeoutError:
        raise FetchError("timeout") from None
    except (OSError, http.client.HTTPException):
        raise FetchError("network") from None
    finally:
        conn.close()


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

    def call(self, method: str, path: str, bearer: str, payload: Any = None) -> Any:
        if not path.startswith("/") or "//" in path or "\n" in path or "\r" in path:
            raise FetchError("bad-path")
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
        try:
            status, resp_headers, data = self.transport(method, path, headers, body)
        except TimeoutError:
            raise FetchError("timeout") from None
        except OSError:
            raise FetchError("network") from None
        if len(data) > MAX_RESPONSE:
            raise FetchError("too-large")
        if status == 429 or (status == 403 and resp_headers.get("x-ratelimit-remaining") == "0"):
            raise FetchError("rate-limited")
        if status == 401:
            raise FetchError("unauthorised")
        if status == 204:
            return None
        if not 200 <= status < 300:
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
            if not isinstance(inst, dict) or not isinstance(inst.get("id"), int):
                raise FetchError("bad-response")
            if inst.get("app_id") != self.app_id:
                raise FetchError("wrong-app")
            account = inst.get("account")
            if not isinstance(account, dict) or account.get("login") != owner:
                raise FetchError("wrong-account")
            if inst.get("suspended_at") is not None:
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
        return token

    def repositories(self, token: str, repos: list[str]) -> None:
        """The installation reaches exactly the configured repositories, no more."""
        answer = self.call("GET", "/installation/repositories?per_page=100", token)
        if not isinstance(answer, dict) or not isinstance(answer.get("repositories"), list):
            raise FetchError("bad-response")
        names = {r.get("full_name") for r in answer["repositories"] if isinstance(r, dict)}
        if answer.get("total_count") != len(repos) or names != set(repos):
            raise FetchError("wrong-repositories")

    def graphql(self, token: str, query: str, variables: dict[str, Any]) -> dict:
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
            if kinds & HEAVY_KINDS:
                raise FetchError("too-heavy")  # GitHub stopped the query for its cost
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
            raise FetchError("graphql-error", paths, data if isinstance(data, dict) else None)
        data = answer.get("data")
        if not isinstance(data, dict):
            raise FetchError("bad-response")
        return data

    def revoke(self, token: str) -> bool:
        """Revoke the installation token. Best effort: it expires within the hour anyway."""
        try:
            self.call("DELETE", "/installation/token", token)
        except FetchError:
            return False
        return True
