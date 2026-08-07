# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# config/settings.py
from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Base project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Azure Configuration
AZURE_SUBSCRIPTION_ID = os.getenv('AZURE_SUBSCRIPTION_ID')
AZURE_RESOURCE_GROUP = os.getenv('AZURE_RESOURCE_GROUP')
AZURE_LOCATION = os.getenv('AZURE_LOCATION', 'westeurope')  # Default location

# VM Configuration
VM_SIZE = 'Standard_DC1s_v3'  # Default size for confidential computing
VM_IMAGE = {
    'publisher': 'canonical',
    'offer': '0001-com-ubuntu-minimal-focal',
    'sku': 'minimal-20_04-lts-gen2',
    'version': 'latest'
}

# Network Configuration
VNET_NAME = os.getenv('AZURE_VNET_NAME')
SUBNET_NAME = os.getenv('AZURE_SUBNET_NAME')

# Security Configuration
ENABLE_SECURE_BOOT = True
ENABLE_VTPM = True
SECURITY_TYPE = 'TrustedLaunch'

# SSH Configuration
SSH_PUBLIC_KEY = os.getenv('SSH_PUBLIC_KEY')
ADMIN_USERNAME = 'azureuser'  # Default username

# SGX enclave image deployed to the VM. Built and signed by the
# trusted-compute-MVP enclave CI, which prints the digest for each build.
#
# Prefer a digest (repo@sha256:...) over a tag: MRENCLAVE is only meaningful
# alongside the exact image content that produced it, and a mutable tag can be
# repointed underneath a recorded measurement.
SGX_IMAGE = os.getenv('SGX_IMAGE', 'ghcr.io/relational-network/sgx-mvp:main-latest')

# Host path on the SGX VM backing the enclave's encrypted /data mount. Without
# a volume, sealed pool identity and the replay ledger are lost whenever the
# container is replaced rather than merely restarted.
SGX_DATA_DIR = os.getenv('SGX_DATA_DIR', '/opt/sgx-mvp/data')

# Logging Configuration
LOGGING_LEVEL = os.getenv('LOGGING_LEVEL', 'INFO')  # Options: DEBUG, INFO, WARNING, ERROR