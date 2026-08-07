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

# Assertion / claim lifetimes (seconds)
ORACLE_ASSERTION_TTL = int(os.getenv("ORACLE_ASSERTION_TTL", "300"))
ORACLE_MAX_CLAIM_TTL = int(os.getenv("ORACLE_MAX_CLAIM_TTL", "900"))

ORACLE_ISSUER = os.getenv("ORACLE_ISSUER", "relational-oracle-1")
ORACLE_KEY_ID = os.getenv("ORACLE_KEY_ID", "oracle-1")

RPC_TIMEOUT_SECONDS = float(os.getenv("ORACLE_RPC_TIMEOUT_SECONDS", "15"))
