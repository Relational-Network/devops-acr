# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# oracle/solana_rpc.py
"""Thin async Solana JSON-RPC client used by the oracle.

Only the two calls the oracle needs. Kept as a class so tests can inject a
fake, and so the router never talks to httpx directly.
"""
import base64
from typing import Any, Dict, Optional

import httpx

from oracle import settings


class RpcError(RuntimeError):
    pass


class SolanaRpc:
    def __init__(self, url: str = None, timeout: float = None):
        self.url = url or settings.SOLANA_RPC_URL
        self.timeout = timeout or settings.RPC_TIMEOUT_SECONDS

    async def _call(self, method: str, params: list) -> Any:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(self.url, json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:
            raise RpcError(f"RPC transport failure: {exc}") from exc
        if "error" in body:
            raise RpcError(f"RPC error: {body['error']}")
        return body.get("result")

    async def get_health(self) -> bool:
        try:
            return await self._call("getHealth", []) == "ok"
        except RpcError:
            return False

    async def get_slot(self) -> int:
        """Current finalized slot, for the redemption age bound."""
        return int(await self._call("getSlot", [{"commitment": "finalized"}]))

    async def get_finalized_transaction(self, signature: str) -> Optional[Dict[str, Any]]:
        """Return the transaction response, or None if not finalized/found."""
        return await self._call(
            "getTransaction",
            [
                signature,
                {
                    "commitment": "finalized",
                    "encoding": "json",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
        )

    async def get_account(self, pubkey: str) -> Optional[Dict[str, Any]]:
        """Return {owner, data(bytes)} for an account, or None if missing."""
        result = await self._call(
            "getAccountInfo",
            [pubkey, {"commitment": "finalized", "encoding": "base64"}],
        )
        value = (result or {}).get("value")
        if value is None:
            return None
        data_field = value.get("data")
        if not (isinstance(data_field, list) and len(data_field) == 2 and data_field[1] == "base64"):
            raise RpcError("unexpected account data encoding")
        return {"owner": value.get("owner"), "data": base64.b64decode(data_field[0])}
