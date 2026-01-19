# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# app.py
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import logging
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime
import asyncio
import sys
from pathlib import Path

# Add project root to sys.path to allow imports
sys.path.append(str(Path(__file__).resolve().parent))

from scripts.azure_deployer import AzureVMDeployer
from attestation.attestation_client import AttestationClient
from config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress excessive Azure SDK logs
azure_logger = logging.getLogger("azure")
azure_logger.setLevel(logging.WARNING)
http_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
http_logger.setLevel(logging.WARNING)

app = FastAPI(
    title="Relational Azure TEE DevOps Runner",
    description="API for deploying and managing Azure TEE VM instances",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for tracking deployments
# TODO: Replace with persistent storage in production.
# TODO: Add concurrency protection (lock) or switch to an external store for multi-worker deployments.
deployment_store = {}

# Models for response
class DeploymentResponse(BaseModel):
    request_id: str
    vm_name: str
    status: str
    created_at: datetime

class DeploymentStatus(BaseModel):
    request_id: str
    vm_name: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    public_ip: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class VMListResponse(BaseModel):
    vms: List[Dict[str, Any]]

class AttestationRequest(BaseModel):
    vm_name: str
    mrenclave: str
    mrsigner: str
    port: int = Field(default=443, description="Port to connect to for attestation")
    isvprodid: str = Field(default="0", description="ISV product ID")
    isvsvn: str = Field(default="0", description="ISV SVN")

class AttestationResponse(BaseModel):
    success: bool
    vm_name: str
    host: Optional[str] = None
    details: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.now)

# Helper functions
def get_deployer():
    """Dependency to get a configured AzureVMDeployer instance"""
    try:
        return AzureVMDeployer()
    except Exception as e:
        # TODO: Add structured error codes to help clients distinguish config/auth failures.
        logger.error(f"Failed to initialize AzureVMDeployer: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize Azure connection: {str(e)}"
        )

# Deployment task
async def deploy_vm_task(
    request_id: str,
    vm_name: str,
):
    """Background task to deploy a VM and run the setup script"""
    deployer = AzureVMDeployer()
    # TODO: Add retry/backoff for transient Azure API failures.
    
    # Update deployment status
    deployment_store[request_id]["vm_name"] = vm_name
    deployment_store[request_id]["status"] = "provisioning"
    
    try:
        # Step 1: Create NSG with both SSH and HTTPS rules
        nsg_name = f"{vm_name}-nsg"
        logger.info(f"Creating Network Security Group: {nsg_name}")
        nsg = deployer.create_network_security_group(nsg_name)
        
        # Step 2: Get subnet ID
        subnet_id = f"/subscriptions/{deployer.subscription_id}/resourceGroups/{deployer.resource_group}/providers/Microsoft.Network/virtualNetworks/{settings.VNET_NAME}/subnets/{settings.SUBNET_NAME}"
        
        # Step 3: Create Network Interface
        nic_name = f"{vm_name}-nic"
        logger.info(f"Creating network interface: {nic_name}")
        nic = deployer.create_network_interface(nic_name, subnet_id, nsg.id)
        
        # Step 4: Create VM using environment settings
        logger.info(f"Creating VM: {vm_name}")
        vm = deployer.create_vm(vm_name, nic.id)
        
        # Update deployment status to indicate VM is provisioned but script is pending
        deployment_store[request_id]["status"] = "vm_provisioned"
        deployment_store[request_id]["details"] = {
            "resource_group": deployer.resource_group,
            "location": deployer.location,
            "vm_size": settings.VM_SIZE
        }
        
        # Step 5: Wait for VM to be fully ready
        logger.info(f"Waiting for VM {vm_name} to be ready before running setup script...")
        vm_ready = await deployer.wait_for_vm_ready(vm_name)
        if not vm_ready:
            raise Exception(f"VM {vm_name} failed to reach running state within timeout.")

        # Step 6: Run setup script on the VM
        logger.info(f"Running setup script on VM: {vm_name}")
        deployment_store[request_id]["status"] = "configuring"
        script_success, sigstruct_data = deployer.run_setup_script_on_vm(vm_name)
        
        # Step 7: Get public IP
        public_ip = deployer.get_vm_public_ip(vm_name)
        # TODO: Consider waiting for public IP allocation to avoid returning None.
        
        # Update deployment status
        if script_success:
            # Include sigstruct data in the details if available
            details = {
                "resource_group": deployer.resource_group,
                "location": deployer.location,
                "vm_size": settings.VM_SIZE,
                "setup_script": "succeeded"
            }
            
            if sigstruct_data:
                details["sigstruct"] = sigstruct_data
            
            deployment_store[request_id].update({
                "status": "completed",
                "completed_at": datetime.now(),
                "public_ip": public_ip,
                "details": details
            })
            logger.info(f"Successfully deployed and configured VM: {vm_name}")
            if sigstruct_data:
                logger.info(f"Sigstruct data: {sigstruct_data}")
        else:
            deployment_store[request_id].update({
                "status": "partial_success",
                "completed_at": datetime.now(),
                "public_ip": public_ip,
                "details": {
                    "resource_group": deployer.resource_group,
                    "location": deployer.location,
                    "vm_size": settings.VM_SIZE,
                    "setup_script": "failed"
                },
                "error": "VM deployed successfully but setup script failed"
            })
            logger.warning(f"VM {vm_name} deployed but setup script failed")
        
    except Exception as e:
        logger.error(f"Deployment of {vm_name} failed: {str(e)}")
        # Update deployment status with error
        deployment_store[request_id].update({
            "status": "failed",
            "completed_at": datetime.now(),
            "error": str(e)
        })

# Routes
@app.get("/", tags=["Status"])
async def root():
    """API root - returns basic status information"""
    return {
        "status": "operational",
        "api_version": "1.0.0",
        "service": "Relational Azure TEE DevOps Runner"
    }

@app.post(
    "/deployments", 
    response_model=DeploymentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Deployments"]
)
async def create_deployment(
    name_prefix: str = Query("relational-tee", description="Prefix for the VM name"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    deployer: AzureVMDeployer = Depends(get_deployer)
):
    """
    Deploy a new TEE instance on Azure.
    Simply provide a name prefix, and a unique VM name will be generated.
    All settings are loaded from environment variables.
    This is an asynchronous operation - check the status endpoint for results.
    """
    # Generate a unique request ID
    request_id = str(uuid.uuid4())[:8]
    created_at = datetime.now()
    name_prefix = name_prefix.replace(" ", "-")
    
    # Generate VM name with request ID for uniqueness
    vm_name = f"{name_prefix}-{request_id}"
    
    # Initialize deployment tracking
    deployment_store[request_id] = {
        "request_id": request_id,
        "vm_name": vm_name,
        "status": "pending",
        "created_at": created_at
    }
    
    # Start deployment in background
    background_tasks.add_task(
        deploy_vm_task,
        request_id=request_id,
        vm_name=vm_name
    )
    
    return DeploymentResponse(
        request_id=request_id,
        vm_name=vm_name,
        status="pending",
        created_at=created_at
    )

@app.get(
    "/deployments/{request_id}",
    response_model=DeploymentStatus,
    tags=["Deployments"]
)
async def get_deployment_status(request_id: str):
    """
    Get the status of a deployment by request ID
    """
    if request_id not in deployment_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Deployment with ID {request_id} not found"
        )
    
    return deployment_store[request_id]

@app.get(
    "/vms",
    response_model=VMListResponse,
    tags=["VMs"]
)
async def list_vms(deployer: AzureVMDeployer = Depends(get_deployer)):
    """
    List all VMs in the resource group
    """
    try:
        vms = deployer.list_vms()
        # TODO: Paginate or filter results for large resource groups.
        vm_list = []
        
        for vm in vms:
            status = deployer.get_vm_status(vm.name)
            public_ip = deployer.get_vm_public_ip(vm.name)
            
            vm_info = {
                "name": vm.name,
                "status": status,
                "size": vm.hardware_profile.vm_size,
                "location": vm.location,
                "os_type": vm.storage_profile.os_disk.os_type,
                "public_ip": public_ip,
                "tags": vm.tags
            }
            vm_list.append(vm_info)
            
        return {"vms": vm_list}
    except Exception as e:
        logger.error(f"Failed to list VMs: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list VMs: {str(e)}"
        )

@app.get(
    "/vms/{vm_name}",
    tags=["VMs"]
)
async def get_vm_details(
    vm_name: str,
    deployer: AzureVMDeployer = Depends(get_deployer)
):
    """
    Get detailed information about a specific VM
    """
    try:
        # Get VM instance
        vm = deployer.compute_client.virtual_machines.get(
            deployer.resource_group,
            vm_name
        )
        
        # Get status and IP
        vm_status = deployer.get_vm_status(vm_name)
        public_ip = deployer.get_vm_public_ip(vm_name)
        
        return {
            "name": vm.name,
            "id": vm.id,
            "status": vm_status,
            "size": vm.hardware_profile.vm_size,
            "location": vm.location,
            "os_type": vm.storage_profile.os_disk.os_type,
            "public_ip": public_ip,
            "security_profile": {
                "security_type": vm.security_profile.security_type if vm.security_profile else None,
                "secure_boot": vm.security_profile.uefi_settings.secure_boot_enabled if vm.security_profile and vm.security_profile.uefi_settings else None,
                "vtpm": vm.security_profile.uefi_settings.v_tpm_enabled if vm.security_profile and vm.security_profile.uefi_settings else None
            },
            "tags": vm.tags
        }
    except Exception as e:
        # Check if it's a ResourceNotFound error (VM doesn't exist or was deleted)
        if "ResourceNotFound" in str(e):
            logger.info(f"VM {vm_name} not found - it may have been deleted")
            raise HTTPException(
                status_code=404,
                detail=f"VM {vm_name} not found or has been deleted"
            )
        else:
            # For other errors, log the full exception and return a 500
            logger.error(f"Failed to get VM details for {vm_name}: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Error retrieving VM details: {str(e)}"
            )
@app.post(
    "/attestation",
    response_model=AttestationResponse,
    tags=["Attestation"]
)
async def run_attestation(
    request: AttestationRequest,
    deployer: AzureVMDeployer = Depends(get_deployer)
):
    """
    Run remote attestation on a VM with the provided measurements
    
    This endpoint:
    1. Retrieves the VM's public IP using the existing API
    2. Runs the attestation client with the provided measurements
    3. Verifies that every expected step completed successfully by checking the stdout.
    4. Returns the attestation result
    """
    vm_name = request.vm_name
    
    # Check if VM exists and get its IP
    try:
        vm = deployer.compute_client.virtual_machines.get(
            deployer.resource_group,
            vm_name
        )
    except Exception as e:
        if "ResourceNotFound" in str(e):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"VM {vm_name} not found"
            )
        else:
            logger.error(f"Error retrieving VM {vm_name}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error retrieving VM details: {str(e)}"
            )
    
    # Get the public IP
    public_ip = deployer.get_vm_public_ip(vm_name)
    if not public_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"VM {vm_name} does not have a public IP address"
        )
    
    # Run attestation
    attestation_client = AttestationClient()
    success, details = attestation_client.verify_attestation(
        host=public_ip,
        port=request.port,
        mrenclave=request.mrenclave,
        mrsigner=request.mrsigner,
        isvprodid=request.isvprodid,
        isvsvn=request.isvsvn
    )

    # Basic validations for required fields
    required_keys = ["success", "host", "port", "mrenclave", "mrsigner", "stdout", "duration_seconds"]
    if not all(key in details for key in required_keys):
        logger.error("Attestation details missing required fields")
        success = False
        details["error"] = "Incomplete attestation details: missing one or more required fields"
    elif details.get("host") != public_ip:
        logger.error("Attestation host mismatch")
        success = False
        details["error"] = "Attestation reported host does not match VM public IP"
    
    # Verify the stdout output sequentially
    stdout = details.get("stdout", "")
    # TODO: Consider a more robust attestation verification method than stdout parsing.
    # Define the expected steps along with an error message for each if missing.
    expected_steps = [
        ("Seeding the random number generator... ok", "Error: Seeding the random number generator failed."),
        (f"Connecting to tcp/{public_ip}/{request.port}... ok", f"Error: Connecting to tcp/{public_ip}/{request.port} failed."),
        ("Setting up the SSL/TLS structure... ok", "Error: Setting up the SSL/TLS structure failed."),
        ("Setting certificate verification mode for RA-TLS... ok", "Error: Setting certificate verification mode for RA-TLS failed."),
        ("Installing RA-TLS callback ... ok", "Error: Installing RA-TLS callback failed."),
        ("Performing the SSL/TLS handshake...", "Error: Performing the SSL/TLS handshake failed."),
        ("Handshake completed... ok", "Error: Handshake did not complete successfully."),
        ("Verifying peer X.509 certificate... ok", "Error: Peer X.509 certificate verification failed."),
        ("GET /health HTTP/1.1", "Error: GET /health HTTP/1.1 request not found."),
        (f"Host: {public_ip}:{request.port}", f"Error: Host header does not match expected value: Host: {public_ip}:{request.port}."),
        ("HTTP/1.1 200 OK", "Error: HTTP/1.1 200 OK response not received."),
        ("Server is running", "Error: Server is not running as expected.")
    ]

    # Check each expected step sequentially; if one fails, stop checking further.
    current_index = 0
    for expected, err_msg in expected_steps:
        pos = stdout.find(expected, current_index)
        if pos == -1:
            success = False
            details["error"] = err_msg
            logger.error(err_msg)
            break
        # Move current index forward so subsequent steps are expected to appear later.
        current_index = pos + len(expected)
    
    
    return AttestationResponse(
        success=success,
        vm_name=vm_name,
        host=public_ip,
        details=details
    )        

# @app.delete(
#     "/vms/{vm_name}",
#     status_code=status.HTTP_202_ACCEPTED,
#     tags=["VMs"]
# )
# async def delete_vm(
#     vm_name: str,
#     background_tasks: BackgroundTasks,
#     deployer: AzureVMDeployer = Depends(get_deployer)
# ):
#     """
#     Delete a VM and its associated resources
#     """
#     # First check if VM exists
#     try:
#         deployer.compute_client.virtual_machines.get(
#             deployer.resource_group,
#             vm_name
#         )
#     except Exception:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail=f"VM {vm_name} not found"
#         )
    
#     # Delete in background task
#     async def delete_vm_task():
#         try:
#             logger.info(f"Deleting VM: {vm_name}")
#             deployer.delete_vm(vm_name)
#             logger.info(f"Successfully deleted VM: {vm_name}")
#         except Exception as e:
#             logger.error(f"Failed to delete VM {vm_name}: {str(e)}")
    
#     background_tasks.add_task(delete_vm_task)
    
#     return {
#         "status": "deletion_initiated",
#         "message": f"Deletion of VM {vm_name} has been initiated"
#     }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
