# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# tests/test_oracle.py
"""Oracle unit tests with mocked Solana RPC (plan.md test plan, FastAPI row).

Covers: valid events for all actions, non-finalized/failed transactions,
wrong program or event, mismatched pool/redeemer/runtime, invalid wallet
signatures, missing compute hash, tampered Pool accounts, malformed logs,
and RPC failures. Also pins the cross-language canonicalization vector.
"""
import base64
import hashlib
import struct
import time

import base58
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from nacl.signing import SigningKey, VerifyKey

from oracle import settings
from oracle.anchor import DRT_REDEEMED_DISC, POOL_ACCOUNT_DISC, POOL_CREATED_DISC
from oracle.canonical import claim_digest_hex, claim_message_bytes
from oracle.jws import verify_jws
import oracle.router as oracle_router_module
from oracle.router import router
from oracle.solana_rpc import RpcError

# ---------------------------------------------------------------------------
# Fixed identities
# ---------------------------------------------------------------------------

ORACLE_SEED = bytes(range(32))
WALLET_KEY = SigningKey(bytes([7] * 32))
CLAIMANT = base58.b58encode(bytes(WALLET_KEY.verify_key)).decode()
POOL = base58.b58encode(bytes([1] * 32)).decode()
TX_SIG = base58.b58encode(bytes([2] * 64)).decode()
PROGRAM = settings.DRT_PROGRAM_ID
GITHUB_URL = "https://github.com/nautilus-project/py_compute_median/blob/main/script.py"
CODE_HASH = "a" * 64
SHA256_EMPTY = hashlib.sha256(b"").hexdigest()

# ---------------------------------------------------------------------------
# Borsh encoding helpers (mirror the on-chain layouts)
# ---------------------------------------------------------------------------


def _string(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<I", len(raw)) + raw


def _option_string(value) -> bytes:
    return b"\x00" if value is None else b"\x01" + _string(value)


def encode_drt_redeemed(pool=POOL, drt_type="py_compute_median", execution_type="python",
                        redeemer=CLAIMANT, github_url=GITHUB_URL, code_hash=CODE_HASH) -> bytes:
    return (
        DRT_REDEEMED_DISC
        + base58.b58decode(pool)
        + _string(drt_type)
        + _string(execution_type)
        + base58.b58decode(redeemer)
        + _option_string(github_url)
        + _option_string(code_hash)
        + struct.pack("<q", 1700000000)
    )


def encode_pool_created(pool=POOL, owner=CLAIMANT, name="testpool") -> bytes:
    return (
        POOL_CREATED_DISC
        + base58.b58decode(pool)
        + base58.b58decode(owner)
        + bytes([9] * 32)
        + _string(name)
        + struct.pack("<I", 1)
        + _string("append")
        + struct.pack("<Q", 100)
    )


def encode_pool_account(owner=CLAIMANT, name="testpool", drts=None) -> bytes:
    if drts is None:
        drts = [("py_compute_median", GITHUB_URL, CODE_HASH)]
    body = b"\x01" + _string(name) + base58.b58decode(owner) + bytes([9] * 32)
    body += struct.pack("<I", len(drts))
    for drt_type, url, code_hash in drts:
        body += (
            _string(drt_type)
            + bytes([4] * 32)
            + struct.pack("<Q", 10)
            + struct.pack("<Q", 1)
            + _option_string(url)
            + _option_string(code_hash)
            + b"\x01"
        )
    return POOL_ACCOUNT_DISC + body


def tx_response(events, invoked=True, err=None, logs=None, slot=1234):
    if logs is None:
        logs = []
        if invoked:
            logs.append(f"Program {PROGRAM} invoke [1]")
        for event in events:
            logs.append("Program data: " + base64.b64encode(event).decode())
        if invoked:
            logs.append(f"Program {PROGRAM} success")
    return {"slot": slot, "meta": {"err": err, "logMessages": logs}}


def account_response(data: bytes, owner=PROGRAM):
    return {"owner": owner, "data": data}


# ---------------------------------------------------------------------------
# Fake RPC + app fixture
# ---------------------------------------------------------------------------


class FakeRpc:
    tx = None
    account = None
    tx_error = None
    account_error = None

    def __init__(self, *args, **kwargs):
        pass

    async def get_health(self):
        return True

    async def get_finalized_transaction(self, signature):
        if FakeRpc.tx_error:
            raise FakeRpc.tx_error
        return FakeRpc.tx

    async def get_account(self, pubkey):
        if FakeRpc.account_error:
            raise FakeRpc.account_error
        return FakeRpc.account


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(settings, "ORACLE_SIGNING_KEY_HEX", ORACLE_SEED.hex())
    monkeypatch.setattr(oracle_router_module, "SolanaRpc", FakeRpc)
    FakeRpc.tx = tx_response([encode_drt_redeemed()])
    FakeRpc.account = account_response(encode_pool_account())
    FakeRpc.tx_error = None
    FakeRpc.account_error = None
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def make_claim(action="execute_python", **overrides):
    claim = {
        "version": "1",
        "action": action,
        "cluster": settings.SOLANA_CLUSTER,
        "program": PROGRAM,
        "tx": TX_SIG,
        "pool": POOL,
        "claimant": CLAIMANT,
        "payload_sha256": SHA256_EMPTY,
        "nonce": "00112233445566778899aabbccddeeff",
        "expiry": str(int(time.time()) + 300),
    }
    if action in ("execute_wasm", "execute_python"):
        claim["github_url"] = GITHUB_URL
        claim["code_hash"] = CODE_HASH
    claim.update({k: v for k, v in overrides.items() if v is not None})
    for key, value in list(overrides.items()):
        if value is None:
            claim.pop(key, None)
    return claim


def sign_claim(claim, key=WALLET_KEY):
    return base58.b58encode(key.sign(claim_message_bytes(claim)).signature).decode()


def post_claim(client, claim, signature=None):
    return client.post(
        "/oracle/v1/verify-chain-claim",
        json={"claim": claim, "wallet_signature": signature or sign_claim(claim)},
    )


def error_code(response):
    return response.json()["detail"]["error_code"]


# ---------------------------------------------------------------------------
# Cross-language canonicalization vector (mirrored in the Rust and TS suites)
# ---------------------------------------------------------------------------


def test_canonical_vector_digest():
    claim = {
        "version": "1",
        "action": "execute_python",
        "cluster": "devnet",
        "program": "CME2Dg7UEW82Hf99rQetEi7Hc5Db9JQPx6Azmx1eWbEE",
        "tx": base58.b58encode(bytes([2] * 64)).decode(),
        "pool": base58.b58encode(bytes([1] * 32)).decode(),
        "claimant": base58.b58encode(bytes([3] * 32)).decode(),
        "payload_sha256": SHA256_EMPTY,
        "nonce": "00112233445566778899aabbccddeeff",
        "expiry": "1767225600",
        "github_url": GITHUB_URL,
        "code_hash": "a" * 64,
    }
    digest = claim_digest_hex(claim)
    # Pinned value; the Rust and TypeScript suites assert the same digest.
    assert digest == CANONICAL_VECTOR_DIGEST


# Computed once from the reference implementation above; do not edit.
CANONICAL_VECTOR_DIGEST = "600528edcf47bf38a4ced6da3b9565d0e43e8d408073ad38aa1eb4ee38098628"


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def assert_valid_assertion(response, claim):
    assert response.status_code == 200, response.text
    payload = verify_jws(response.json()["assertion"], SigningKey(ORACLE_SEED).verify_key)
    assert payload["claim_digest"] == claim_digest_hex(claim)
    assert payload["pool"] == claim["pool"]
    assert payload["action"] == claim["action"]
    assert payload["exp"] > time.time()
    return payload


def test_valid_execute_python(client):
    claim = make_claim()
    payload = assert_valid_assertion(post_claim(client, claim), claim)
    assert payload["execution_type"] == "python"
    assert payload["github_url"] == GITHUB_URL
    assert payload["code_hash"] == CODE_HASH


def test_valid_execute_wasm(client):
    FakeRpc.tx = tx_response(
        [encode_drt_redeemed(drt_type="w_compute_median", execution_type="wasm")]
    )
    FakeRpc.account = account_response(
        encode_pool_account(drts=[("w_compute_median", GITHUB_URL, CODE_HASH)])
    )
    claim = make_claim("execute_wasm")
    payload = assert_valid_assertion(post_claim(client, claim), claim)
    assert payload["execution_type"] == "wasm"


def test_valid_append(client):
    FakeRpc.tx = tx_response(
        [encode_drt_redeemed(drt_type="append", execution_type="append",
                             github_url=None, code_hash=None)]
    )
    claim = make_claim("append", payload_sha256=hashlib.sha256(b'{"x":1}').hexdigest())
    payload = assert_valid_assertion(post_claim(client, claim), claim)
    assert payload["execution_type"] == "append"


def test_valid_pool_initialize(client):
    FakeRpc.tx = tx_response([encode_pool_created()])
    claim = make_claim("pool_initialize", payload_sha256=hashlib.sha256(b"seed").hexdigest())
    payload = assert_valid_assertion(post_claim(client, claim), claim)
    assert payload["execution_type"] == "pool_initialize"
    assert payload["drt_type"] is None


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_tx_not_finalized(client):
    FakeRpc.tx = None
    response = post_claim(client, make_claim())
    assert response.status_code == 409
    assert error_code(response) == "tx_not_finalized"


def test_tx_failed_on_chain(client):
    FakeRpc.tx = tx_response([encode_drt_redeemed()], err={"InstructionError": [0, "Custom"]})
    response = post_claim(client, make_claim())
    assert error_code(response) == "tx_failed"


def test_wrong_program_not_invoked(client):
    other = base58.b58encode(bytes([8] * 32)).decode()
    logs = [
        f"Program {other} invoke [1]",
        "Program data: " + base64.b64encode(encode_drt_redeemed()).decode(),
        f"Program {other} success",
    ]
    FakeRpc.tx = tx_response([], logs=logs)
    response = post_claim(client, make_claim())
    assert error_code(response) == "wrong_program"


def test_wrong_event_type(client):
    FakeRpc.tx = tx_response([encode_pool_created()])
    response = post_claim(client, make_claim())  # wants DrtRedeemed
    assert error_code(response) == "event_not_found"


def test_pool_mismatch(client):
    other_pool = base58.b58encode(bytes([5] * 32)).decode()
    FakeRpc.tx = tx_response([encode_drt_redeemed(pool=other_pool)])
    response = post_claim(client, make_claim())
    assert error_code(response) == "event_mismatch"


def test_redeemer_mismatch(client):
    other = base58.b58encode(bytes([6] * 32)).decode()
    FakeRpc.tx = tx_response([encode_drt_redeemed(redeemer=other)])
    response = post_claim(client, make_claim())
    assert error_code(response) == "event_mismatch"


def test_runtime_mismatch(client):
    FakeRpc.tx = tx_response(
        [encode_drt_redeemed(drt_type="w_compute_median", execution_type="wasm")]
    )
    response = post_claim(client, make_claim("execute_python"))
    assert error_code(response) == "event_mismatch"


def test_claim_code_hash_differs_from_event(client):
    claim = make_claim(code_hash="b" * 64)
    response = post_claim(client, claim)
    assert error_code(response) == "event_mismatch"


def test_invalid_wallet_signature(client):
    claim = make_claim()
    forged = sign_claim(claim, SigningKey(bytes([9] * 32)))
    response = post_claim(client, claim, signature=forged)
    assert error_code(response) == "wallet_signature_invalid"


def test_signature_over_different_claim(client):
    claim = make_claim()
    other = make_claim(nonce="ffffffffffffffffffffffffffffffff")
    response = post_claim(client, claim, signature=sign_claim(other))
    assert error_code(response) == "wallet_signature_invalid"


def test_missing_compute_hash_on_chain(client):
    FakeRpc.tx = tx_response([encode_drt_redeemed(code_hash=None)])
    response = post_claim(client, make_claim())
    assert error_code(response) == "code_metadata_invalid"


def test_claim_missing_compute_fields(client):
    claim = make_claim(github_url=None, code_hash=None)
    response = post_claim(client, claim)
    assert error_code(response) == "invalid_claim"


def test_non_github_url_rejected(client):
    claim = make_claim(github_url="https://example.com/script.py")
    response = post_claim(client, claim)
    assert error_code(response) == "code_metadata_invalid"


def test_expired_claim(client):
    claim = make_claim(expiry=str(int(time.time()) - 10))
    response = post_claim(client, claim)
    assert error_code(response) == "claim_expired"


def test_tampered_pool_account_owner(client):
    FakeRpc.account = account_response(encode_pool_account(), owner=base58.b58encode(bytes([8] * 32)).decode())
    response = post_claim(client, make_claim())
    assert error_code(response) == "pool_account_invalid"


def test_pool_account_metadata_drift(client):
    FakeRpc.account = account_response(
        encode_pool_account(drts=[("py_compute_median", GITHUB_URL, "c" * 64)])
    )
    response = post_claim(client, make_claim())
    assert error_code(response) == "pool_account_invalid"


def test_missing_pool_account(client):
    FakeRpc.account = None
    response = post_claim(client, make_claim())
    assert error_code(response) == "pool_account_invalid"


def test_malformed_logs_fail_closed(client):
    logs = [f"Program {PROGRAM} invoke [1]", "Program data: !!!not-base64!!!"]
    FakeRpc.tx = tx_response([], logs=logs)
    response = post_claim(client, make_claim())
    assert error_code(response) == "event_malformed"


def test_logs_unavailable_fail_closed(client):
    FakeRpc.tx = {"slot": 1, "meta": {"err": None, "logMessages": None}}
    response = post_claim(client, make_claim())
    assert error_code(response) == "logs_unavailable"


def test_rpc_failure(client):
    FakeRpc.tx_error = RpcError("boom")
    response = post_claim(client, make_claim())
    assert response.status_code == 502
    assert error_code(response) == "rpc_error"


def test_signing_key_missing(client, monkeypatch):
    monkeypatch.setattr(settings, "ORACLE_SIGNING_KEY_HEX", "")
    response = post_claim(client, make_claim())
    assert response.status_code == 503
    assert error_code(response) == "oracle_unavailable"


def test_health_reports_key_and_rpc(client):
    response = client.get("/oracle/v1/health")
    body = response.json()
    assert body["rpc_ok"] is True
    assert body["signing_key_ok"] is True
    assert body["oracle_pubkey"] == bytes(SigningKey(ORACLE_SEED).verify_key).hex()
