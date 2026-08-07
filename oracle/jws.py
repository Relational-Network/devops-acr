# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# oracle/jws.py
"""Compact JWS (EdDSA/Ed25519) signing and verification.

Hand-rolled to keep dependencies minimal; the enclave verifies the same
format in Rust against the pinned oracle public key.
"""
import base64
import json

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def sign_jws(payload: dict, signing_key: SigningKey, key_id: str) -> str:
    header = {"alg": "EdDSA", "typ": "JWT", "kid": key_id}
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = signing_key.sign(signing_input.encode("ascii")).signature
    return signing_input + "." + _b64url(signature)


def verify_jws(token: str, verify_key: VerifyKey) -> dict:
    """Verify a compact JWS and return its payload. Raises on any failure."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed JWS")
    header = json.loads(_b64url_decode(parts[0]))
    if header.get("alg") != "EdDSA":
        raise ValueError("unexpected JWS alg")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    try:
        verify_key.verify(signing_input, _b64url_decode(parts[2]))
    except BadSignatureError as exc:
        raise ValueError("bad JWS signature") from exc
    return json.loads(_b64url_decode(parts[1]))
