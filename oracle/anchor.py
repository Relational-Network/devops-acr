# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# oracle/anchor.py
"""Minimal Anchor/Borsh decoding for the unchanged drt-manager program.

Decodes the `PoolCreated` and `DrtRedeemed` events carried in transaction
logs (`Program data: <base64>` lines emitted by Anchor's `emit!`) and the
`Pool` account, without pulling in a full Anchor client. Layouts mirror
trusted-compute-MVP/drt-manager/programs/drt-manager/src/lib.rs and must not
drift from it (no contract changes are made by this work).
"""
import base64
import hashlib
from dataclasses import dataclass
from typing import List, Optional, Tuple

import base58


def _event_discriminator(name: str) -> bytes:
    return hashlib.sha256(f"event:{name}".encode()).digest()[:8]


def _account_discriminator(name: str) -> bytes:
    return hashlib.sha256(f"account:{name}".encode()).digest()[:8]


POOL_CREATED_DISC = _event_discriminator("PoolCreated")
DRT_REDEEMED_DISC = _event_discriminator("DrtRedeemed")
POOL_ACCOUNT_DISC = _account_discriminator("Pool")


class DecodeError(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("unexpected end of data")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def i64(self) -> int:
        return int.from_bytes(self.take(8), "little", signed=True)

    def string(self) -> str:
        length = self.u32()
        return self.take(length).decode("utf-8")

    def pubkey(self) -> str:
        return base58.b58encode(self.take(32)).decode("ascii")

    def option_string(self) -> Optional[str]:
        tag = self.u8()
        if tag == 0:
            return None
        if tag == 1:
            return self.string()
        raise DecodeError(f"invalid Option tag {tag}")

    def boolean(self) -> bool:
        tag = self.u8()
        if tag not in (0, 1):
            raise DecodeError(f"invalid bool {tag}")
        return tag == 1


@dataclass
class PoolCreatedEvent:
    pool: str
    owner: str
    ownership_mint: str
    name: str
    drt_types: List[str]
    ownership_supply: int


@dataclass
class DrtRedeemedEvent:
    pool: str
    drt_type: str
    execution_type: str
    redeemer: str
    github_url: Optional[str]
    code_hash: Optional[str]
    timestamp: int


@dataclass
class DrtConfig:
    drt_type: str
    mint: str
    supply: int
    cost: int
    github_url: Optional[str]
    code_hash: Optional[str]
    is_minted: bool


@dataclass
class PoolAccount:
    bump: int
    name: str
    owner: str
    ownership_mint: str
    drts: List[DrtConfig]


def decode_event(data: bytes):
    """Decode one `Program data:` payload into a known event, or None."""
    if len(data) < 8:
        raise DecodeError("event payload too short")
    disc, body = data[:8], data[8:]
    r = _Reader(body)
    if disc == POOL_CREATED_DISC:
        event = PoolCreatedEvent(
            pool=r.pubkey(),
            owner=r.pubkey(),
            ownership_mint=r.pubkey(),
            name=r.string(),
            drt_types=[r.string() for _ in range(r.u32())],
            ownership_supply=r.u64(),
        )
    elif disc == DRT_REDEEMED_DISC:
        event = DrtRedeemedEvent(
            pool=r.pubkey(),
            drt_type=r.string(),
            execution_type=r.string(),
            redeemer=r.pubkey(),
            github_url=r.option_string(),
            code_hash=r.option_string(),
            timestamp=r.i64(),
        )
    else:
        return None
    if r.pos != len(body):
        raise DecodeError("trailing bytes after event body")
    return event


def extract_program_events(log_messages: List[str], program_id: str) -> Tuple[bool, list]:
    """Walk transaction logs, returning (program_invoked, events).

    Tracks the invoke stack so `Program data:` lines are attributed to the
    program that actually emitted them; events from other programs are
    ignored. Raises DecodeError on malformed base64/Borsh from our program
    (fail closed rather than skipping).
    """
    stack: List[str] = []
    invoked = False
    events = []
    for line in log_messages:
        parts = line.split(" ")
        if len(parts) >= 3 and parts[0] == "Program" and parts[2].startswith("invoke"):
            stack.append(parts[1])
            if parts[1] == program_id:
                invoked = True
        elif len(parts) >= 3 and parts[0] == "Program" and parts[2] in ("success", "failed:"):
            if stack:
                stack.pop()
        elif line.startswith("Program data: "):
            if stack and stack[-1] == program_id:
                try:
                    raw = base64.b64decode(line[len("Program data: ") :], validate=True)
                except Exception as exc:
                    raise DecodeError(f"invalid event base64: {exc}") from exc
                event = decode_event(raw)
                if event is not None:
                    events.append(event)
    return invoked, events


def decode_pool_account(data: bytes) -> PoolAccount:
    if len(data) < 8 or data[:8] != POOL_ACCOUNT_DISC:
        raise DecodeError("not a Pool account")
    r = _Reader(data[8:])
    bump = r.u8()
    name = r.string()
    owner = r.pubkey()
    ownership_mint = r.pubkey()
    drts = []
    for _ in range(r.u32()):
        drts.append(
            DrtConfig(
                drt_type=r.string(),
                mint=r.pubkey(),
                supply=r.u64(),
                cost=r.u64(),
                github_url=r.option_string(),
                code_hash=r.option_string(),
                is_minted=r.boolean(),
            )
        )
    return PoolAccount(bump=bump, name=name, owner=owner, ownership_mint=ownership_mint, drts=drts)
