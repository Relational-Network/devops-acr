# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# oracle/settings.py
"""Oracle-specific configuration.

Kept separate from config/settings.py so the oracle router stays
self-contained and can be lifted into its own service without change.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Solana RPC / chain configuration
SOLANA_RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com")
SOLANA_CLUSTER = os.getenv("SOLANA_CLUSTER", "devnet")
DRT_PROGRAM_ID = os.getenv(
    "DRT_PROGRAM_ID", "CME2Dg7UEW82Hf99rQetEi7Hc5Db9JQPx6Azmx1eWbEE"
)

# Oracle identity. 32-byte Ed25519 seed, hex encoded. Provisioned as an Azure
# Container App secret in deployment; never baked into the image.
ORACLE_SIGNING_KEY_HEX = os.getenv("ORACLE_SIGNING_KEY_HEX", "")

# Assertion lifetime (seconds). The enclave rejects anything older.
ORACLE_ASSERTION_TTL = int(os.getenv("ORACLE_ASSERTION_TTL", "300"))

# How far back a redemption may be presented, in slots (~400ms each, so the
# default is roughly 24 hours). This is a bound on how much RPC history the
# oracle will look through, not the anti-replay control -- that is the
# enclave's sealed ledger. Raising it lets a redeemer come back to an
# unredeemed burn later; lowering it shortens the window in which a leaked
# ephemeral key could collect someone else's result.
ORACLE_MAX_SLOT_AGE = int(os.getenv("ORACLE_MAX_SLOT_AGE", "216000"))

ORACLE_ISSUER = os.getenv("ORACLE_ISSUER", "relational-oracle-1")
ORACLE_KEY_ID = os.getenv("ORACLE_KEY_ID", "oracle-1")

RPC_TIMEOUT_SECONDS = float(os.getenv("ORACLE_RPC_TIMEOUT_SECONDS", "15"))
