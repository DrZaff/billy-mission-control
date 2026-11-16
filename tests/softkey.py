"""A software authenticator for tests: a synthetic P-256 key that answers WebAuthn ceremonies
like a phone or a security key would, with knobs to make it misbehave. No real credential."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import Aaguid, AttestationObject, AttestedCredentialData, AuthenticatorData

FLAGS = AuthenticatorData.FLAG


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftKey:
    def __init__(self, origin: str, counter: int = 0, step: int = 1):
        self.origin = origin
        self.rp_id = urlsplit(origin).hostname
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = os.urandom(16)
        self.counter = counter
        self.step = step  # 0 makes the counter stay put, like a synced passkey

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin or self.origin}
        ).encode()

    def create(self, options: dict, *, uv=True, origin=None, rp_id=None, kind="webauthn.create"):
        flags = FLAGS.UP | FLAGS.AT | (FLAGS.UV if uv else 0)
        data = AttestedCredentialData.create(
            Aaguid(b"\0" * 16), self.id, ES256.from_cryptography_key(self.key.public_key())
        )
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        auth_data = AuthenticatorData.create(rp_hash, flags, self.counter, data)
        attestation = AttestationObject.create("none", auth_data, {})
        client = self._client_data(kind, options["challenge"], origin)
        return {
            "id": b64(self.id),
            "rawId": b64(self.id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client),
                "attestationObject": b64(bytes(attestation)),
            },
        }

    def get(self, options: dict, *, uv=True, origin=None, rp_id=None, counter=None, tamper=False):
        self.counter = self.counter + self.step if counter is None else counter
        flags = FLAGS.UP | (FLAGS.UV if uv else 0)
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        auth_data = bytes(AuthenticatorData.create(rp_hash, flags, self.counter))
        client = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.key.sign(
            auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        if tamper:
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        return {
            "id": b64(self.id),
            "rawId": b64(self.id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client),
                "authenticatorData": b64(auth_data),
                "signature": b64(signature),
                "userHandle": None,
            },
        }
