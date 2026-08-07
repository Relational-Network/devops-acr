# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

"""Single-oracle chain-claim verification service.

Self-contained router so the oracle can be split into its own service later
(see plan.md, "Assumptions and Scope"). The oracle is stateless: it verifies a
wallet-signed chain claim against finalized Solana state and returns a
short-lived compact JWS assertion signed with the oracle's Ed25519 key.
"""
