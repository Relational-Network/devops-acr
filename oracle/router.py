# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# oracle/router.py
"""POST /oracle/v1/verify-chain-claim and GET /oracle/v1/health.

Verifies a wallet-signed chain claim against finalized Solana state and
returns a short-lived compact JWS assertion. Stateless by design; every
check fails closed. See plan.md "FastAPI oracle".
"""
import logging
import re
import time
from typing import Optional

import base58
from fastapi import APIRouter, HTTPException
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, Field

from oracle import settings
from oracle.anchor import (
    DecodeError,
    DrtRedeemedEvent,
    PoolCreatedEvent,
    decode_pool_account,
    extract_program_events,
)
from oracle.canonical import (
    CLAIM_ACTIONS,
    COMPUTE_ACTIONS,
    COMPUTE_FIELDS,
    REQUIRED_FIELDS,
    SHA256_EMPTY_HEX,
    claim_digest_hex,
    claim_message_bytes,
)
from oracle.jws import sign_jws
from oracle.solana_rpc import RpcError, SolanaRpc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oracle/v1", tags=["Oracle"])

GITHUB_URL_RE = re.compile(r"^https://github\.com/[^\s]+$")
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[0-9a-f]{16,64}$")
MAX_GITHUB_URL_LENGTH = 200

# Map claim action -> expected DrtRedeemed execution_type
ACTION_EXECUTION_TYPE = {
    "append": "append",
    "execute_wasm": "wasm",
    "execute_python": "python",
}


class VerifyChainClaimRequest(BaseModel):
    claim: dict = Field(description="Flat string-valued claim object")
    wallet_signature: str = Field(description="Base58 Ed25519 signature over the canonical claim message")


class VerifyChainClaimResponse(BaseModel):
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


def _is_base58_of_length(value: str, length: int) -> bool:
    try:
        return len(base58.b58decode(value)) == length
    except ValueError:
        return False


def _validate_claim_shape(claim: dict) -> None:
    action = claim.get("action")
    if action not in CLAIM_ACTIONS:
        _reject(400, "invalid_claim", f"unsupported action {action!r}")

    expected_fields = set(REQUIRED_FIELDS)
    if action in COMPUTE_ACTIONS:
        expected_fields |= set(COMPUTE_FIELDS)
    if set(claim.keys()) != expected_fields:
        _reject(400, "invalid_claim", "claim fields do not match the v1 schema")
    if any(not isinstance(v, str) for v in claim.values()):
        _reject(400, "invalid_claim", "all claim values must be strings")

    if claim["version"] != "1":
        _reject(400, "invalid_claim", "unsupported claim version")
    if claim["cluster"] != settings.SOLANA_CLUSTER:
        _reject(400, "invalid_claim", "claim cluster does not match this oracle")
    if claim["program"] != settings.DRT_PROGRAM_ID:
        _reject(400, "invalid_claim", "claim program does not match this oracle")
    if not _is_base58_of_length(claim["pool"], 32):
        _reject(400, "invalid_claim", "pool is not a valid address")
    if not _is_base58_of_length(claim["claimant"], 32):
        _reject(400, "invalid_claim", "claimant is not a valid address")
    if not SHA256_HEX_RE.match(claim["payload_sha256"]):
        _reject(400, "invalid_claim", "payload_sha256 must be 64 lowercase hex chars")
    if not NONCE_RE.match(claim["nonce"]):
        _reject(400, "invalid_claim", "nonce must be 16-64 lowercase hex chars")
    try:
        tx_bytes = base58.b58decode(claim["tx"])
        if len(tx_bytes) != 64:
            raise ValueError
    except ValueError:
        _reject(400, "invalid_claim", "tx is not a valid transaction signature")

    try:
        expiry = int(claim["expiry"])
    except ValueError:
        _reject(400, "invalid_claim", "expiry must be a decimal unix timestamp")
        return
    now = int(time.time())
    if expiry <= now:
        _reject(400, "claim_expired", "claim has expired")
    if expiry > now + settings.ORACLE_MAX_CLAIM_TTL:
        _reject(400, "invalid_claim", "claim expiry too far in the future")

    if action in COMPUTE_ACTIONS:
        # Fail closed on malformed code metadata (plan.md: HTTPS GitHub
        # reference and 64-char SHA-256 are mandatory for compute).
        url = claim["github_url"]
        if not GITHUB_URL_RE.match(url) or len(url) > MAX_GITHUB_URL_LENGTH:
            _reject(400, "code_metadata_invalid", "github_url must be a https://github.com/ URL")
        if not SHA256_HEX_RE.match(claim["code_hash"]):
            _reject(400, "code_metadata_invalid", "code_hash must be 64 lowercase hex chars")
        if claim["payload_sha256"] != SHA256_EMPTY_HEX:
            _reject(400, "invalid_claim", "compute claims carry no payload")


def _verify_wallet_signature(claim: dict, wallet_signature: str) -> None:
    try:
        signature = base58.b58decode(wallet_signature)
        pubkey = base58.b58decode(claim["claimant"])
        if len(signature) != 64 or len(pubkey) != 32:
            raise ValueError
    except ValueError:
        _reject(400, "wallet_signature_invalid", "signature or claimant key malformed")
        return
    try:
        VerifyKey(pubkey).verify(claim_message_bytes(claim), signature)
    except BadSignatureError:
        _reject(400, "wallet_signature_invalid", "wallet signature does not verify")


def _matching_event(events: list, claim: dict):
    """Pick the event authorizing this claim, enforcing field equality."""
    action = claim["action"]
    if action == "pool_initialize":
        candidates = [e for e in events if isinstance(e, PoolCreatedEvent)]
        if not candidates:
            _reject(409, "event_not_found", "transaction emitted no PoolCreated event")
        event = candidates[0]
        if event.pool != claim["pool"]:
            _reject(409, "event_mismatch", "event pool does not match claim")
        if event.owner != claim["claimant"]:
            _reject(409, "event_mismatch", "claimant is not the pool owner")
        return event

    expected_execution = ACTION_EXECUTION_TYPE[action]
    candidates = [e for e in events if isinstance(e, DrtRedeemedEvent)]
    if not candidates:
        _reject(409, "event_not_found", "transaction emitted no DrtRedeemed event")
    event = candidates[0]
    if event.pool != claim["pool"]:
        _reject(409, "event_mismatch", "event pool does not match claim")
    if event.redeemer != claim["claimant"]:
        _reject(409, "event_mismatch", "claimant is not the redeemer")
    if event.execution_type != expected_execution:
        _reject(409, "event_mismatch", f"redeemed DRT is {event.execution_type!r}, claim wants {expected_execution!r}")

    if action in COMPUTE_ACTIONS:
        if not event.github_url or not event.code_hash:
            _reject(409, "code_metadata_invalid", "on-chain DRT has no code reference/hash; refusing")
        if not GITHUB_URL_RE.match(event.github_url) or not SHA256_HEX_RE.match(event.code_hash):
            _reject(409, "code_metadata_invalid", "on-chain code metadata is malformed")
        if event.github_url != claim["github_url"] or event.code_hash != claim["code_hash"]:
            _reject(409, "event_mismatch", "claim code metadata does not match the redeemed DRT")
    return event


async def _verify_pool_account(rpc: SolanaRpc, claim: dict, event) -> None:
    account = await rpc.get_account(claim["pool"])
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
        if pool.owner != claim["claimant"] or pool.name != event.name:
            _reject(409, "pool_account_invalid", "pool account state does not match event")
        return

    if claim["action"] in COMPUTE_ACTIONS:
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


@router.post("/verify-chain-claim", response_model=VerifyChainClaimResponse)
async def verify_chain_claim(request: VerifyChainClaimRequest):
    signing_key = _oracle_signing_key()
    if signing_key is None:
        _reject(503, "oracle_unavailable", "oracle signing key is not configured")

    claim = request.claim
    _validate_claim_shape(claim)
    _verify_wallet_signature(claim, request.wallet_signature)

    rpc = SolanaRpc()
    try:
        tx = await rpc.get_finalized_transaction(claim["tx"])
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
        # Fail closed when the provider withholds/truncates logs (plan.md).
        _reject(409, "logs_unavailable", "transaction logs unavailable; cannot verify event")

    try:
        invoked, events = extract_program_events(log_messages, settings.DRT_PROGRAM_ID)
    except DecodeError as exc:
        _reject(409, "event_malformed", f"could not decode program event: {exc}")
        return
    if not invoked:
        _reject(409, "wrong_program", "transaction did not invoke the DRT program")

    event = _matching_event(events, claim)
    try:
        await _verify_pool_account(rpc, claim, event)
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
        "tx": claim["tx"],
        "slot": tx.get("slot"),
        "action": claim["action"],
        "pool": claim["pool"],
        "claimant": claim["claimant"],
        "drt_type": event.drt_type if is_redemption else None,
        "execution_type": event.execution_type if is_redemption else "pool_initialize",
        "github_url": event.github_url if is_redemption else None,
        "code_hash": event.code_hash if is_redemption else None,
        "payload_sha256": claim["payload_sha256"],
        "claim_digest": claim_digest_hex(claim),
    }
    return VerifyChainClaimResponse(
        assertion=sign_jws(payload, signing_key, settings.ORACLE_KEY_ID)
    )
