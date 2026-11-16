"""The one place that uses python-fido2 (a policy test enforces it). Everything WebAuthn-specific
is here, behind four small functions, so the library could be swapped without touching the
rest of the app.

python-fido2 checks, for registration and sign-in: the ceremony type, the origin (here: exactly
the configured origin), the challenge, the relying-party ID hash, user presence, user
verification (required here), and the signature. It does not check the signature counter; the
caller does (auth.Auth).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    AuthenticationResponse,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP_NAME = "Billy Mission Control"


class PasskeyError(ValueError):
    """The browser's answer failed a check, or couldn't be read."""


def _server(origin: str) -> Fido2Server:
    host = urlsplit(origin).hostname or ""
    return Fido2Server(
        PublicKeyCredentialRpEntity(name=RP_NAME, id=host),
        verify_origin=lambda candidate: candidate == origin,
    )


def _state_out(state: dict) -> str:
    return json.dumps({"challenge": state["challenge"], "uv": str(state["user_verification"])})


def _state_in(text: str) -> dict:
    data = json.loads(text)
    return {
        "challenge": data["challenge"],
        "user_verification": UserVerificationRequirement(data["uv"].split(".")[-1].lower()),
    }


def user_id(login: str) -> bytes:
    return hashlib.sha256(("mission-control:" + login).encode()).digest()[:16]


def registration_options(
    origin: str, login: str, existing: list[bytes]
) -> tuple[dict[str, Any], str]:
    """(options for navigator.credentials.create, state to keep server-side)."""
    options, state = _server(origin).register_begin(
        PublicKeyCredentialUserEntity(id=user_id(login), name=login, display_name=login),
        credentials=[AttestedCredentialData(blob) for blob in existing],
        resident_key_requirement=ResidentKeyRequirement.PREFERRED,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return dict(options)["publicKey"], _state_out(state)


def register(origin: str, state: str, response: dict) -> tuple[bytes, bytes, int]:
    """Check a registration. Returns (credential id, credential blob to store, counter)."""
    try:
        auth_data = _server(origin).register_complete(_state_in(state), response)
    except Exception as error:  # noqa: BLE001 - any failure is a refusal, never a crash
        raise PasskeyError(type(error).__name__) from None
    data = auth_data.credential_data
    if data is None:
        raise PasskeyError("no credential")
    return bytes(data.credential_id), bytes(data), int(auth_data.counter)


def authentication_options(origin: str, credentials: list[bytes]) -> tuple[dict[str, Any], str]:
    options, state = _server(origin).authenticate_begin(
        [AttestedCredentialData(blob) for blob in credentials],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return dict(options)["publicKey"], _state_out(state)


def authenticate(
    origin: str, state: str, credentials: list[bytes], response: dict
) -> tuple[bytes, int]:
    """Check a sign-in. Returns (the credential id that signed, the authenticator's counter)."""
    try:
        cred = _server(origin).authenticate_complete(
            _state_in(state), [AttestedCredentialData(blob) for blob in credentials], response
        )
        counter = AuthenticationResponse.from_dict(response).response.authenticator_data.counter
    except Exception as error:  # noqa: BLE001 - any failure is a refusal, never a crash
        raise PasskeyError(type(error).__name__) from None
    return bytes(cred.credential_id), int(counter)
