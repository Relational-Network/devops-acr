# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

"""Single-oracle transaction verification service.

Self-contained router so the oracle can be split into its own service later,
if the prototype outgrows co-hosting it. The oracle is stateless: given a
transaction signature it confirms the transaction finalized and reports the
event it emitted, as a short-lived compact JWS signed with the oracle's
Ed25519 key. It is never trusted for what the redeemer authorised -- that is
bound by an on-chain memo commitment the enclave verifies for itself.
"""
