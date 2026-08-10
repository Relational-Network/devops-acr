# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# oracle/router.py
"""POST /oracle/v1/verify-transaction and GET /oracle/v1/health.

The oracle answers one question, on demand, for the enclave: *did this
transaction signature finalize, and what did it emit?* It returns a
short-lived compact JWS describing the event.

It is deliberately not trusted for anything the redeemer authorised. The
payload, the code reference, and the ephemeral key are bound by a commitment
in the transaction's memo, which the enclave verifies against the wallet's
own transaction signature. A compromised oracle can therefore delay or
refuse a redemption, but cannot substitute one (paper Appendix C1).

Stateless by design; every check fails closed.
"""
import logging
import re
import time
from typing import Optional

import base58
from fastapi import APIRouter, HTTPException
from nacl.signing import SigningKey
from pydantic import BaseModel, Field

from oracle import settings
from oracle.anchor import (
    DecodeError,
    DrtRedeemedEvent,
    PoolCreatedEvent,
    decode_pool_account,
    extract_program_events,
)
from oracle.jws import sign_jws
from oracle.solana_rpc import RpcError, SolanaRpc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oracle/v1", tags=["Oracle"])

GITHUB_URL_RE = re.compile(r"^https://github\.com/[^\s]+$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_GITHUB_URL_LENGTH = 200

# DrtRedeemed execution types that carry a code reference.
COMPUTE_EXECUTION_TYPES = ("wasm", "python")


class VerifyTransactionRequest(BaseModel):
    tx: str = Field(description="Base58 transaction signature to verify")


class VerifyTransactionResponse(BaseModel):
    assertion: str = Field(description="Compact JWS signed by the oracle")


def _oracle_signing_key() -> Optional[SigningKey]:
    key_hex = settings.ORACLE_SIGNING_KEY_HEX
    if not key_hex:
        return None
    try:
        seed = bytes.fromhex(key_hex)
        if len(seed) != 32:
            return None
        return SigningKey(seed)
    except ValueError:
        return None


def _reject(status_code: int, error_code: str, detail: str):
    raise HTTPException(status_code=status_code, detail={"error_code": error_code, "detail": detail})


def _validate_signature(tx: str) -> None:
    try:
        if len(base58.b58decode(tx)) != 64:
            raise ValueError
    except ValueError:
        _reject(400, "invalid_request", "tx is not a valid transaction signature")


def _authorizing_event(events: list):
    """Pick the single event that authorizes an enclave operation.

    A transaction is expected to carry exactly one: either the pool was
    created, or one DRT was redeemed. Anything else is ambiguous about what
    is being authorized, so it fails closed rather than guessing.
    """
    relevant = [e for e in events if isinstance(e, (PoolCreatedEvent, DrtRedeemedEvent))]
    if not relevant:
        _reject(409, "event_not_found", "transaction emitted no PoolCreated or DrtRedeemed event")
    if len(relevant) > 1:
        _reject(
            409,
            "event_ambiguous",
            "transaction emitted more than one authorizing event; refusing to guess",
        )
    event = relevant[0]

    if isinstance(event, DrtRedeemedEvent) and event.execution_type in COMPUTE_EXECUTION_TYPES:
        # Fail closed on malformed code metadata: an HTTPS GitHub reference
        # and a 64-char SHA-256 are mandatory for compute.
        if not event.github_url or not event.code_hash:
            _reject(409, "code_metadata_invalid", "on-chain DRT has no code reference/hash; refusing")
        if (
            not GITHUB_URL_RE.match(event.github_url)
            or len(event.github_url) > MAX_GITHUB_URL_LENGTH
            or not SHA256_HEX_RE.match(event.code_hash)
        ):
            _reject(409, "code_metadata_invalid", "on-chain code metadata is malformed")
    return event


async def _verify_pool_account(rpc: SolanaRpc, event) -> None:
    """Cross-check the event against current Pool account state."""
    account = await rpc.get_account(event.pool)
    if account is None:
        _reject(409, "pool_account_invalid", "pool account does not exist")
    if account["owner"] != settings.DRT_PROGRAM_ID:
        _reject(409, "pool_account_invalid", "pool account is not owned by the DRT program")
    try:
        pool = decode_pool_account(account["data"])
    except DecodeError as exc:
        _reject(409, "pool_account_invalid", f"pool account failed to decode: {exc}")
        return

    if isinstance(event, PoolCreatedEvent):
        if pool.owner != event.owner or pool.name != event.name:
            _reject(409, "pool_account_invalid", "pool account state does not match event")
        return

    if event.execution_type in COMPUTE_EXECUTION_TYPES:
        config = next((d for d in pool.drts if d.drt_type == event.drt_type), None)
        if config is None:
            _reject(409, "pool_account_invalid", "redeemed DRT type is not configured on the pool")
        if config.github_url != event.github_url or config.code_hash != event.code_hash:
            _reject(409, "pool_account_invalid", "pool DRT code metadata does not match the event")


@router.get("/health")
async def oracle_health():
    rpc_ok = await SolanaRpc().get_health()
    signing_key = _oracle_signing_key()
    return {
        "rpc_ok": rpc_ok,
        "signing_key_ok": signing_key is not None,
        "oracle_pubkey": signing_key.verify_key.encode().hex() if signing_key else None,
        "cluster": settings.SOLANA_CLUSTER,
        "program": settings.DRT_PROGRAM_ID,
        "issuer": settings.ORACLE_ISSUER,
    }


@router.post("/verify-transaction", response_model=VerifyTransactionResponse)
async def verify_transaction(request: VerifyTransactionRequest):
    signing_key = _oracle_signing_key()
    if signing_key is None:
        _reject(503, "oracle_unavailable", "oracle signing key is not configured")

    _validate_signature(request.tx)

    rpc = SolanaRpc()
    try:
        tx = await rpc.get_finalized_transaction(request.tx)
    except RpcError as exc:
        logger.error("RPC failure fetching transaction: %s", exc)
        _reject(502, "rpc_error", "could not read transaction from Solana RPC")
        return

    if tx is None:
        _reject(409, "tx_not_finalized", "transaction not found at finalized commitment")
    meta = tx.get("meta") or {}
    if meta.get("err") is not None:
        _reject(409, "tx_failed", "transaction failed on-chain")
    log_messages = meta.get("logMessages")
    if not log_messages:
        # Fail closed when the provider withholds or truncates logs. Anchor
        # events ride in program logs, so without them there is nothing to
        # verify and guessing is not an option.
        _reject(409, "logs_unavailable", "transaction logs unavailable; cannot verify event")

    slot = tx.get("slot")
    try:
        current_slot = await rpc.get_slot()
    except RpcError as exc:
        logger.error("RPC failure fetching current slot: %s", exc)
        _reject(502, "rpc_error", "could not read the current slot from Solana RPC")
        return
    if slot is None or current_slot - int(slot) > settings.ORACLE_MAX_SLOT_AGE:
        _reject(409, "tx_too_old", "transaction is older than this oracle will verify")

    try:
        invoked, events = extract_program_events(log_messages, settings.DRT_PROGRAM_ID)
    except DecodeError as exc:
        _reject(409, "event_malformed", f"could not decode program event: {exc}")
        return
    if not invoked:
        _reject(409, "wrong_program", "transaction did not invoke the DRT program")

    event = _authorizing_event(events)
    try:
        await _verify_pool_account(rpc, event)
    except RpcError as exc:
        logger.error("RPC failure fetching pool account: %s", exc)
        _reject(502, "rpc_error", "could not read pool account from Solana RPC")

    now = int(time.time())
    is_redemption = isinstance(event, DrtRedeemedEvent)
    payload = {
        "iss": settings.ORACLE_ISSUER,
        "iat": now,
        "exp": now + settings.ORACLE_ASSERTION_TTL,
        "cluster": settings.SOLANA_CLUSTER,
        "program": settings.DRT_PROGRAM_ID,
        "tx": request.tx,
        "slot": slot,
        "pool": event.pool,
        "claimant": event.redeemer if is_redemption else event.owner,
        "drt_type": event.drt_type if is_redemption else None,
        "execution_type": event.execution_type if is_redemption else "pool_initialize",
        "github_url": event.github_url if is_redemption else None,
        "code_hash": event.code_hash if is_redemption else None,
    }
    return VerifyTransactionResponse(
        assertion=sign_jws(payload, signing_key, settings.ORACLE_KEY_ID)
    )
