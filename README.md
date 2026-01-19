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
cp env-template .env
```

5. Edit the `.env` file with your Azure credentials and settings

6. Run the application
```bash
python run.py --reload
```

The API will be available at http://localhost:8000

## Deployment to Azure Container Apps

### Prerequisites

- Azure subscription
- Azure Container Registry (ACR)
- Azure Key Vault (for storing secrets)
- GitHub repository (for CI/CD)

### Manual Deployment

1. Build the Docker image
```bash
docker build -t yourregistry.azurecr.io/relational-devops:latest .
```

2. Push the image to ACR
```bash
az acr login --name yourregistry
docker push yourregistry.azurecr.io/relational-devops:latest
```

3. Deploy the Container App using ARM template
```bash
az deployment group create \
  --resource-group your-resource-group \
  --template-file deployment/container-app-template.json \
  --parameters containerImage=yourregistry.azurecr.io/relational-devops:latest
```

### CI/CD with GitHub Actions

1. Store the following secrets in your GitHub repository:
   - `AZURE_CREDENTIALS` - Service principal credentials
   - `AZURE_SUBSCRIPTION_ID` - Your Azure subscription ID
   - `AZURE_RESOURCE_GROUP` - Resource group name
   - `ACR_LOGIN_SERVER` - ACR login server URL
   - `ACR_USERNAME` - ACR username
   - `ACR_PASSWORD` - ACR password

2. Push to the main branch to trigger deployment

## Scaling Configuration

The application will automatically scale based on:
- HTTP request concurrency (10 concurrent requests per instance)
- CPU utilization (80% threshold)
- Min replicas: 1 (configurable)
- Max replicas: 10 (configurable)

## API Documentation

When the application is running, visit `/docs` for the interactive OpenAPI documentation.

## Authentication

The application uses Azure Managed Identity when deployed to Container Apps. For local development, it falls back to DefaultAzureCredential which tries multiple authentication methods.

## Environment Variables

See `env-template` for required environment variables.
