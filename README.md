<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Relational Network -->

# Relational DevOps

A FastAPI application for deploying and managing Azure Trusted Execution Environment (TEE) VMs.

## Features

- Deploy Azure TEE VMs with pre-configured security settings
- Manage VM lifecycle (create, list, inspect, delete)
- Async operations with background task processing
- RESTful API with OpenAPI documentation
- Containerized deployment with auto-scaling support

## Architecture

This application is designed to run as a containerized service in Azure Container Apps with:

- Automatic scaling based on HTTP traffic and CPU usage
- Managed identity for secure Azure authentication
- Health and readiness probes for robust orchestration
- Rolling updates with zero downtime

## Local Development

### Prerequisites

- Python 3.11+
- Azure account with subscription
- Azure CLI installed and configured

### Setup

1. Clone the repository

2. Create and activate a virtual environment
```bash
python -m venv venv
source venv/bin/activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Create a `.env` file from the template
```bash
cp .env.example .env
```

5. Edit `.env`. Only `ORACLE_SIGNING_KEY_HEX` is required — the oracle routes
   need nothing else, and the public protocol constants (Solana cluster,
   program ID, TTLs) have committed defaults in `oracle/settings.py`. The Azure
   values are needed only for the VM deployment endpoints.

   Generate a signing key with:
```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

   The service **refuses to start** without a valid key, and logs the derived
   public key on startup. That public key is what gets pinned into the measured
   enclave image as `ORACLE_PUBKEY_HEX`.

6. Run the application
```bash
python run.py --reload
```

The API will be available at http://localhost:8000

## Deployment to Azure Container Apps

Deployment is automated: pushing to `main` runs
[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml), which tests,
builds, pushes to ACR, provisions the oracle key as a Container App secret,
deploys, and then asserts the running oracle is healthy and signing with the
key the enclave expects.

There is no supported manual path. Building by hand skips the post-deploy
assertion that the oracle public key matches the one measured into the
enclave's MRENCLAVE — the failure that mismatch causes (every protected enclave
request failing authorisation) is otherwise very hard to trace.

### One-time setup

Azure authentication uses **GitHub OIDC federated credentials**, so no
long-lived Azure secret is stored. See
[`docs/deployment/keys-and-secrets.md`](../trusted-compute-MVP/docs/deployment/keys-and-secrets.md)
in the trusted-compute-MVP repo for the `az ad app federated-credential`
commands and the full key inventory.

Repository **secrets**:

| Secret | What it is |
|---|---|
| `ORACLE_SIGNING_KEY_HEX` | 32-byte Ed25519 seed, hex. The only true secret this service holds. |
| `SSH_PUBLIC_KEY` | Public half of the SGX VM SSH key. |

Repository **variables** (non-secret):

| Variable | What it is |
|---|---|
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | OIDC federated identity |
| `AZURE_VNET_NAME`, `AZURE_SUBNET_NAME` | Network for the SGX VMs |
| `ORACLE_PUBKEY_HEX` | Oracle public key measured into the enclave; asserted after deploy |
| `SGX_IMAGE` | Enclave image the deployer runs on the SGX VM (prefer a digest) |

## Scaling Configuration

The Container App is pinned to **exactly one replica**
(`--min-replicas 1 --max-replicas 1`).

This is not a capacity decision. The oracle is a single signing identity whose
public key is measured into the enclave's MRENCLAVE, so horizontal scaling buys
nothing: a second replica holding the same key adds no authority, and one
holding a different key would be rejected by the enclave outright. Multi-oracle
consensus is explicitly future work.

## API Documentation

When the application is running, visit `/docs` for the interactive OpenAPI documentation.

## Authentication

The application uses Azure Managed Identity when deployed to Container Apps. For local development, it falls back to DefaultAzureCredential which tries multiple authentication methods.

## Environment Variables

See [`.env.example`](.env.example). The short version:

- **`ORACLE_SIGNING_KEY_HEX` is the only secret**, and the only variable the
  oracle routes require. The service will not start without it.
- Azure values (`AZURE_*`, `SSH_PUBLIC_KEY`, `SGX_IMAGE`) are deployment
  identity, needed only for the VM endpoints. They are supplied by CI in Azure
  and are not committed.
- Public protocol constants (`SOLANA_CLUSTER`, `DRT_PROGRAM_ID`,
  `SOLANA_RPC_URL`, the TTLs) have committed defaults in `oracle/settings.py`
  and only need setting to override them.
