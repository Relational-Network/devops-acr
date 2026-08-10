# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# tests/test_oracle.py
"""Oracle unit tests with mocked Solana RPC.

Covers: valid events for all actions, non-finalized/failed transactions,
wrong program or event, ambiguous events, stale transactions, missing compute
hash, tampered Pool accounts, malformed logs, and RPC failures.

The oracle no longer sees a claim or a wallet signature: the redeemer's
authorization is a commitment in the transaction memo that the enclave
verifies for itself. What is tested here is strictly "did this transaction
finalize, and what did it emit".
"""
import base64
import hashlib
import struct
import time

import base58
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from oracle import settings
from oracle.anchor import DRT_REDEEMED_DISC, POOL_ACCOUNT_DISC, POOL_CREATED_DISC
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
CURRENT_SLOT = 100_000

# ---------------------------------------------------------------------------
# The commitment scheme, reimplemented here from the specification so the
# vector below is an independent check rather than a copy of the Rust code.
# Mirrored in sgx-mvp/oracle-verify/src/tests.rs and ntc-web.
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def code_digest(code) -> bytes:
    if code is None:
        return _sha256(b"")
    url, code_hash = code
    return _sha256(url.encode() + b"\x00" + code_hash.encode())


def memo_for(ephemeral_pubkey: bytes, payload: bytes, code) -> str:
    commitment = _sha256(ephemeral_pubkey + _sha256(payload) + code_digest(code))
    return "rcc1:" + commitment.hex()


def test_commitment_vector():
    eph = bytes([3] * 32)
    assert (
        memo_for(eph, b"", (GITHUB_URL, CODE_HASH))
        == "rcc1:a62f64638528d12d6b6e20f785527768ea6d8d5dbe4c3b0fd8e0b9196ced408c"
    )
    assert (
        memo_for(eph, b'{"a":1}', None)
        == "rcc1:14952fb6c44231bde18f203a7cde30edbc3ae553bca48dea64dc651905f35c0c"
    )


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


def tx_response(events, invoked=True, err=None, logs=None, slot=CURRENT_SLOT - 10):
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
    slot_error = None
    slot = CURRENT_SLOT

    def __init__(self, *args, **kwargs):
        pass

    async def get_health(self):
        return True

    async def get_slot(self):
        if FakeRpc.slot_error:
            raise FakeRpc.slot_error
        return FakeRpc.slot

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
    FakeRpc.slot_error = None
    FakeRpc.slot = CURRENT_SLOT
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def post_tx(client, tx=TX_SIG):
    return client.post("/oracle/v1/verify-transaction", json={"tx": tx})


def error_code(response):
    return response.json()["detail"]["error_code"]


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def assert_valid_assertion(response):
    assert response.status_code == 200, response.text
    payload = verify_jws(response.json()["assertion"], SigningKey(ORACLE_SEED).verify_key)
    assert payload["tx"] == TX_SIG
    assert payload["pool"] == POOL
    assert payload["cluster"] == settings.SOLANA_CLUSTER
    assert payload["program"] == PROGRAM
    assert payload["exp"] > time.time()
    return payload


def test_valid_execute_python(client):
    payload = assert_valid_assertion(post_tx(client))
    assert payload["execution_type"] == "python"
    assert payload["claimant"] == CLAIMANT
    assert payload["github_url"] == GITHUB_URL
    assert payload["code_hash"] == CODE_HASH


def test_valid_execute_wasm(client):
    FakeRpc.tx = tx_response(
        [encode_drt_redeemed(drt_type="w_compute_median", execution_type="wasm")]
    )
    FakeRpc.account = account_response(
        encode_pool_account(drts=[("w_compute_median", GITHUB_URL, CODE_HASH)])
    )
    payload = assert_valid_assertion(post_tx(client))
    assert payload["execution_type"] == "wasm"


def test_valid_append(client):
    FakeRpc.tx = tx_response(
        [encode_drt_redeemed(drt_type="append", execution_type="append",
                             github_url=None, code_hash=None)]
    )
    payload = assert_valid_assertion(post_tx(client))
    assert payload["execution_type"] == "append"
    assert payload["github_url"] is None


def test_valid_pool_initialize(client):
    FakeRpc.tx = tx_response([encode_pool_created()])
    payload = assert_valid_assertion(post_tx(client))
    assert payload["execution_type"] == "pool_initialize"
    assert payload["drt_type"] is None
    assert payload["claimant"] == CLAIMANT


def test_assertion_reports_the_redeemer_not_the_caller(client):
    """The enclave matches this against the transaction's fee payer."""
    other = base58.b58encode(bytes([6] * 32)).decode()
    FakeRpc.tx = tx_response([encode_drt_redeemed(redeemer=other)])
    payload = assert_valid_assertion(post_tx(client))
    assert payload["claimant"] == other


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_malformed_signature_rejected(client):
    response = post_tx(client, tx="not-base58!!")
    assert response.status_code == 400
    assert error_code(response) == "invalid_request"


def test_short_signature_rejected(client):
    response = post_tx(client, tx=base58.b58encode(bytes([1] * 32)).decode())
    assert error_code(response) == "invalid_request"


def test_tx_not_finalized(client):
    FakeRpc.tx = None
    response = post_tx(client)
    assert response.status_code == 409
    assert error_code(response) == "tx_not_finalized"


def test_tx_failed_on_chain(client):
    FakeRpc.tx = tx_response([encode_drt_redeemed()], err={"InstructionError": [0, "Custom"]})
    assert error_code(post_tx(client)) == "tx_failed"


def test_stale_transaction_rejected(client):
    FakeRpc.tx = tx_response([encode_drt_redeemed()], slot=1)
    FakeRpc.slot = settings.ORACLE_MAX_SLOT_AGE + 1000
    assert error_code(post_tx(client)) == "tx_too_old"


def test_transaction_within_the_slot_window_accepted(client):
    FakeRpc.tx = tx_response([encode_drt_redeemed()], slot=CURRENT_SLOT - settings.ORACLE_MAX_SLOT_AGE)
    assert post_tx(client).status_code == 200


def test_wrong_program_not_invoked(client):
    other = base58.b58encode(bytes([8] * 32)).decode()
    logs = [
        f"Program {other} invoke [1]",
        "Program data: " + base64.b64encode(encode_drt_redeemed()).decode(),
        f"Program {other} success",
    ]
    FakeRpc.tx = tx_response([], logs=logs)
    assert error_code(post_tx(client)) == "wrong_program"


def test_no_authorizing_event(client):
    FakeRpc.tx = tx_response([])
    assert error_code(post_tx(client)) == "event_not_found"


def test_two_authorizing_events_rejected(client):
    """Ambiguous about what is being authorized: fail closed."""
    FakeRpc.tx = tx_response([encode_drt_redeemed(), encode_drt_redeemed()])
    assert error_code(post_tx(client)) == "event_ambiguous"


def test_missing_compute_hash_on_chain(client):
    FakeRpc.tx = tx_response([encode_drt_redeemed(code_hash=None)])
    assert error_code(post_tx(client)) == "code_metadata_invalid"


def test_non_github_url_on_chain_rejected(client):
    FakeRpc.tx = tx_response([encode_drt_redeemed(github_url="https://example.com/x.py")])
    assert error_code(post_tx(client)) == "code_metadata_invalid"


def test_tampered_pool_account_owner(client):
    FakeRpc.account = account_response(
        encode_pool_account(), owner=base58.b58encode(bytes([8] * 32)).decode()
    )
    assert error_code(post_tx(client)) == "pool_account_invalid"


def test_pool_account_metadata_drift(client):
    FakeRpc.account = account_response(
        encode_pool_account(drts=[("py_compute_median", GITHUB_URL, "c" * 64)])
    )
    assert error_code(post_tx(client)) == "pool_account_invalid"


def test_pool_account_missing_drt_type(client):
    FakeRpc.account = account_response(
        encode_pool_account(drts=[("append", None, None)])
    )
    assert error_code(post_tx(client)) == "pool_account_invalid"


def test_missing_pool_account(client):
    FakeRpc.account = None
    assert error_code(post_tx(client)) == "pool_account_invalid"


def test_pool_created_owner_drift(client):
    FakeRpc.tx = tx_response([encode_pool_created(owner=base58.b58encode(bytes([6] * 32)).decode())])
    assert error_code(post_tx(client)) == "pool_account_invalid"


def test_malformed_logs_fail_closed(client):
    logs = [f"Program {PROGRAM} invoke [1]", "Program data: !!!not-base64!!!"]
    FakeRpc.tx = tx_response([], logs=logs)
    assert error_code(post_tx(client)) == "event_malformed"


def test_logs_unavailable_fail_closed(client):
    FakeRpc.tx = {"slot": CURRENT_SLOT, "meta": {"err": None, "logMessages": None}}
    assert error_code(post_tx(client)) == "logs_unavailable"


def test_rpc_failure(client):
    FakeRpc.tx_error = RpcError("boom")
    response = post_tx(client)
    assert response.status_code == 502
    assert error_code(response) == "rpc_error"


def test_slot_rpc_failure(client):
    FakeRpc.slot_error = RpcError("boom")
    response = post_tx(client)
    assert response.status_code == 502
    assert error_code(response) == "rpc_error"


def test_account_rpc_failure(client):
    FakeRpc.account_error = RpcError("boom")
    response = post_tx(client)
    assert response.status_code == 502
    assert error_code(response) == "rpc_error"


def test_signing_key_missing(client, monkeypatch):
    monkeypatch.setattr(settings, "ORACLE_SIGNING_KEY_HEX", "")
    response = post_tx(client)
    assert response.status_code == 503
    assert error_code(response) == "oracle_unavailable"


def test_health_reports_key_and_rpc(client):
    body = client.get("/oracle/v1/health").json()
    assert body["rpc_ok"] is True
    assert body["signing_key_ok"] is True
    assert body["oracle_pubkey"] == bytes(SigningKey(ORACLE_SEED).verify_key).hex()
