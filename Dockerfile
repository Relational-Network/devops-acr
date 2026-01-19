# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Use Ubuntu 20.04 as base image
FROM ubuntu:20.04

# ARGs cannot be grouped since each FROM in a Dockerfile initiates a new build
# stage, resulting in the loss of ARG values from earlier stages.
ARG UBUNTU_CODENAME=focal

# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install basic dependencies (including software-properties-common)
RUN apt-get update && \
    apt-get install -y curl gnupg2 binutils python3-minimal python3-pip ca-certificates wget gcc pkg-config software-properties-common && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Add Gramine repo
RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ ${UBUNTU_CODENAME} main" > /etc/apt/sources.list.d/gramine.list

# Add Intel SGX repo (for DCAP verification libraries)
RUN curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] https://download.01.org/intel-sgx/sgx_repo/ubuntu ${UBUNTU_CODENAME} main" > /etc/apt/sources.list.d/intel-sgx.list

# Install Azure DCAP client
RUN wget -qO- https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    DEBIAN_FRONTEND=noninteractive add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y az-dcap-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Gramine and minimal DCAP dependencies
RUN apt-get update && \
    apt-get install -y \
    gramine \
    libsgx-dcap-quote-verify \
    libsgx-urts \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Build attest binary with mbedtls_gramine
WORKDIR /app/attestation
COPY attestation/attest.c .
RUN wget https://github.com/ARMmbed/mbedtls/archive/mbedtls-3.3.0.tar.gz -O mbedtls.tgz && \
    mkdir mbedtls && tar -xvzf mbedtls.tgz -C mbedtls --strip-components 1 && rm mbedtls.tgz && \
    CC=gcc C_INCLUDE_PATH=mbedtls/include \
    gcc attest.c $(pkg-config --cflags mbedtls_gramine) \
    -ldl -Wl,--enable-new-dtags $(pkg-config --libs mbedtls_gramine) -o attest && \
    cp attest /usr/local/bin/

# Set environment variables for RA-TLS
ENV RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1
ENV RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1
ENV RA_TLS_ALLOW_HW_CONFIG_NEEDED=1
ENV RA_TLS_ALLOW_SW_HARDENING_NEEDED=1
ENV AZDCAP_DEBUG_LOG_LEVEL=ERROR

# Copy application code
COPY . /app
WORKDIR /app

# Expose port
EXPOSE 8000

# Run the application
ENTRYPOINT ["/bin/bash", "-c", "exec python3 run.py --host 0.0.0.0 --port 8000 --reload"]