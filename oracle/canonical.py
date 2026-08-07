# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# oracle/canonical.py
"""Canonical claim encoding shared by frontend, oracle, and enclave.

A claim is a flat JSON object whose values are all strings (RFC 8785 JCS
restricted to that subset): keys sorted lexicographically, minimal separators,
standard JSON string escaping. The signed message is the UTF-8 bytes of
`relational-chain-claim:v1\n` followed by the canonical JSON. Any change here
must be mirrored in ntc-web/lib/enclaveClaim.ts and sgx-mvp/src/canonical.rs
and covered by the shared test vectors.
"""
import hashlib
import json

DOMAIN_PREFIX = "relational-chain-claim:v1\n"

CLAIM_ACTIONS = ("pool_initialize", "append", "execute_wasm", "execute_python")
COMPUTE_ACTIONS = ("execute_wasm", "execute_python")

# Fields every claim must carry; github_url/code_hash are compute-only.
REQUIRED_FIELDS = (
    "version",
    "action",
    "cluster",
    "program",
    "tx",
    "pool",
    "claimant",
    "payload_sha256",
    "nonce",
    "expiry",
)
COMPUTE_FIELDS = ("github_url", "code_hash")

SHA256_EMPTY_HEX = hashlib.sha256(b"").hexdigest()


def canonical_claim_json(claim: dict) -> str:
    """Serialize a claim dict to its canonical JSON form."""
    for key, value in claim.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(f"claim field {key!r} must be a string")
    return json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def claim_message_bytes(claim: dict) -> bytes:
    """The exact bytes the wallet signs."""
    return (DOMAIN_PREFIX + canonical_claim_json(claim)).encode("utf-8")


def claim_digest_hex(claim: dict) -> str:
    """SHA-256 of the signed message, hex encoded (the JWS request digest)."""
    return hashlib.sha256(claim_message_bytes(claim)).hexdigest()
