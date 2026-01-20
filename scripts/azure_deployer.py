# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# scripts/azure_deployer.py
import sys
import logging
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from datetime import datetime
import uuid
from typing import Optional, Dict, Any, List
import asyncio

from config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AzureVMDeployer:
    def __init__(self):
        self.credential = DefaultAzureCredential()
        self.subscription_id = settings.AZURE_SUBSCRIPTION_ID
        self.resource_group = settings.AZURE_RESOURCE_GROUP
        self.location = settings.AZURE_LOCATION
        
        # Initialize clients
        self.resource_client = ResourceManagementClient(
            self.credential, self.subscription_id)
        self.network_client = NetworkManagementClient(
            self.credential, self.subscription_id)
        self.compute_client = ComputeManagementClient(
            self.credential, self.subscription_id)
        
        logger.info(f"Initialized AzureVMDeployer with resource group: {self.resource_group}")

    def generate_unique_name(self, base_name="relational-dev"):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        return f"{base_name}-{timestamp}-{unique_id}"

    def create_network_security_group(self, nsg_name):
        """
        Create and configure a Network Security Group (NSG) with SSH and HTTPS rules.
        """
        logger.info(f"Creating Network Security Group: {nsg_name}")
        try:
            # Define NSG parameters
            nsg_params = {
                "location": self.location,
                "security_rules": [
                    {
                        "name": "AllowSSH",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source_port_range": "*",
                        "destination_port_range": "22",
                        "source_address_prefix": "*",
                        "destination_address_prefix": "*"
                    },
                    {
                        "name": "AllowAnyHTTPSInbound",
                        "priority": 110,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source_port_range": "*",
                        "destination_port_range": "443",
                        "source_address_prefix": "*",
                        "destination_address_prefix": "*"
                    }
                ]
            }

            # Create or update the NSG
            poller = self.network_client.network_security_groups.begin_create_or_update(
                self.resource_group,
                nsg_name,
                nsg_params
            )
            nsg = poller.result()
            logger.info(f"Successfully created NSG: {nsg_name}")
            return nsg
        except Exception as e:
            logger.error(f"Failed to create Network Security Group: {str(e)}")
            raise

    def create_network_interface(self, name, subnet_id, nsg_id=None):
        logger.info(f"Creating network interface: {name}")
        try:
            # Create public IP address first
            public_ip_name = f"{name}-ip"
            logger.info(f"Creating public IP: {public_ip_name}")
            public_ip_parameters = {
                'location': self.location,
                'sku': {
                    'name': 'Standard'
                },
                'public_ip_allocation_method': 'Static',
                'public_ip_address_version': 'IPv4'
            }
            
            poller = self.network_client.public_ip_addresses.begin_create_or_update(
                self.resource_group,
                public_ip_name,
                public_ip_parameters
            )
            public_ip = poller.result()

            # Create NIC with the public IP and NSG
            nic_params = {
                'location': self.location,
                'ip_configurations': [{
                    'name': f'{name}-ipconfig',
                    'subnet': {
                        'id': subnet_id
                    },
                    'public_ip_address': {
                        'id': public_ip.id
                    }
                }]
            }
            
            # Add NSG if provided
            if nsg_id:
                nic_params['network_security_group'] = {
                    'id': nsg_id
                }
            
            poller = self.network_client.network_interfaces.begin_create_or_update(
                self.resource_group,
                name,
                nic_params
            )
            return poller.result()
        except Exception as e:
            logger.error(f"Failed to create network interface: {str(e)}")
            raise

    def create_vm(self, vm_name, nic_id, vm_size=None, location=None, tags=None):
        logger.info(f"Creating VM: {vm_name}")
        try:
            # Use provided values or defaults from settings
            actual_location = location or self.location
            actual_vm_size = vm_size or settings.VM_SIZE
            actual_tags = tags or {}
            
            vm_parameters = {
                'location': actual_location,
                'tags': actual_tags,
                'properties': {
                    'hardwareProfile': {
                        'vmSize': actual_vm_size
                    },
                    'storageProfile': {
                        'imageReference': settings.VM_IMAGE,
                        'osDisk': {
                            'createOption': 'FromImage',
                            'managedDisk': {
                                'storageAccountType': 'StandardSSD_LRS'
                            }
                        }
                    },
                    'networkProfile': {
                        'networkInterfaces': [{
                            'id': nic_id,
                            'properties': {
                                'deleteOption': 'Delete'
                            }
                        }]
                    },
                    'osProfile': {
                        'computerName': vm_name,
                        'adminUsername': settings.ADMIN_USERNAME,
                        'linuxConfiguration': {
                            'disablePasswordAuthentication': True,
                            'ssh': {
                                'publicKeys': [{
                                    'path': f'/home/{settings.ADMIN_USERNAME}/.ssh/authorized_keys',
                                    'keyData': settings.SSH_PUBLIC_KEY
                                }]
                            }
                        }
                    },
                    'securityProfile': {
                        'uefiSettings': {
                            'secureBootEnabled': settings.ENABLE_SECURE_BOOT,
                            'vTpmEnabled': settings.ENABLE_VTPM
                        },
                        'securityType': settings.SECURITY_TYPE
                    }
                }
            }

            poller = self.compute_client.virtual_machines.begin_create_or_update(
                self.resource_group,
                vm_name,
                vm_parameters
            )
            return poller.result()
        except Exception as e:
            logger.error(f"Failed to create VM: {str(e)}")
            raise

    def list_vms(self):
        """List all VMs in the resource group"""
        try:
            logger.info(f"Listing VMs in resource group: {self.resource_group}")
            vms = self.compute_client.virtual_machines.list(self.resource_group)
            return list(vms)  # Convert generator to list
        except Exception as e:
            logger.error(f"Failed to list VMs: {str(e)}")
            raise

    def get_vm_status(self, vm_name):
        """Get the status of a specific VM"""
        try:
            logger.info(f"Getting status for VM: {vm_name}")
            instance_view = self.compute_client.virtual_machines.instance_view(
                self.resource_group,
                vm_name
            )
            if instance_view.statuses:
                # Usually the last status is the most relevant
                return instance_view.statuses[-1].display_status
            return "Unknown"
        except Exception as e:
            logger.error(f"Failed to get VM status: {str(e)}")
            raise

    def get_vm_public_ip(self, vm_name):
        """Get the public IP address of a VM"""
        try:
            logger.info(f"Getting public IP for VM: {vm_name}")
            vm = self.compute_client.virtual_machines.get(
                self.resource_group,
                vm_name
            )
            nic_id = vm.network_profile.network_interfaces[0].id
            nic_name = nic_id.split('/')[-1]
            
            nic = self.network_client.network_interfaces.get(
                self.resource_group,
                nic_name
            )
            
            if nic.ip_configurations[0].public_ip_address:
                public_ip_id = nic.ip_configurations[0].public_ip_address.id
                public_ip_name = public_ip_id.split('/')[-1]
                public_ip = self.network_client.public_ip_addresses.get(
                    self.resource_group,
                    public_ip_name
                )
                return public_ip.ip_address
            return None
        except Exception as e:
            logger.error(f"Failed to get VM public IP: {str(e)}")
            raise

    # Disable this method for now
    # def delete_vm(self, vm_name):
    #     """Delete a VM and its associated resources, including disks."""
    #     try:
    #         logger.info(f"Deleting VM: {vm_name}")

    #         # Attempt to get VM details
    #         try:
    #             vm = self.compute_client.virtual_machines.get(
    #                 self.resource_group,
    #                 vm_name
    #             )
    #         except Exception as e:
    #             logger.warning(f"VM {vm_name} not found: {str(e)}")
    #             vm = None

    #         # Delete the VM
    #         if vm:
    #             logger.info(f"Deleting virtual machine: {vm_name}")
    #             poller = self.compute_client.virtual_machines.begin_delete(
    #                 self.resource_group,
    #                 vm_name
    #             )
    #             poller.result()

    #         # Delete NIC and Public IP if they exist
    #         if vm and vm.network_profile.network_interfaces:
    #             for nic_ref in vm.network_profile.network_interfaces:
    #                 nic_id = nic_ref.id
    #                 nic_name = nic_id.split('/')[-1]

    #                 # Attempt to delete NIC
    #                 try:
    #                     logger.info(f"Deleting network interface: {nic_name}")
    #                     nic = self.network_client.network_interfaces.get(
    #                         self.resource_group,
    #                         nic_name
    #                     )

    #                     # Delete public IP if associated with NIC
    #                     if nic.ip_configurations[0].public_ip_address:
    #                         public_ip_id = nic.ip_configurations[0].public_ip_address.id
    #                         public_ip_name = public_ip_id.split('/')[-1]
    #                         logger.info(f"Deleting public IP: {public_ip_name}")
    #                         self.network_client.public_ip_addresses.begin_delete(
    #                             self.resource_group,
    #                             public_ip_name
    #                         ).result()
    #                         logger.info(f"Deleted public IP: {public_ip_name}")

    #                     # Delete NIC
    #                     self.network_client.network_interfaces.begin_delete(
    #                         self.resource_group,
    #                         nic_name
    #                     ).result()
    #                     logger.info(f"Deleted network interface: {nic_name}")
    #                 except Exception as e:
    #                     logger.warning(f"Network interface {nic_name} not found or already deleted: {str(e)}")

    #         # Delete OS Disk and Data Disks
    #         if vm and vm.storage_profile.os_disk:
    #             os_disk_name = vm.storage_profile.os_disk.name
    #             try:
    #                 logger.info(f"Deleting OS disk: {os_disk_name}")
    #                 self.compute_client.disks.begin_delete(
    #                     self.resource_group,
    #                     os_disk_name
    #                 ).result()
    #                 logger.info(f"Deleted OS disk: {os_disk_name}")
    #             except Exception as e:
    #                 logger.warning(f"OS disk {os_disk_name} not found or already deleted: {str(e)}")

    #         if vm and vm.storage_profile.data_disks:
    #             for data_disk in vm.storage_profile.data_disks:
    #                 data_disk_name = data_disk.name
    #                 try:
    #                     logger.info(f"Deleting data disk: {data_disk_name}")
    #                     self.compute_client.disks.begin_delete(
    #                         self.resource_group,
    #                         data_disk_name
    #                     ).result()
    #                     logger.info(f"Deleted data disk: {data_disk_name}")
    #                 except Exception as e:
    #                     logger.warning(f"Data disk {data_disk_name} not found or already deleted: {str(e)}")

    #         logger.info(f"Successfully deleted VM and associated resources: {vm_name}")
    #     except Exception as e:
    #         logger.error(f"Failed to delete VM: {str(e)}")
    #         raise

    def run_setup_script_on_vm(self, vm_name):
        """
        Run the setup script on a VM using the custom script extension.
        Returns the sigstruct data if successful.
        """
        logger.info(f"Running setup script on VM: {vm_name}")
        try:
            # First, create the bash script as a multiline string
            script_content = '''#!/bin/bash
    set -e

    echo "Starting VM setup for SGX Docker container..."

    # Update system
    echo "Updating system packages..."
    sudo apt-get update
    sudo apt-get upgrade -y

    # Install Docker
    echo "Installing Docker..."
    sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    sudo apt-get update
    sudo apt-get install -y docker-ce

    # Pull Docker image
    echo "Pulling Docker image..."
    sudo docker pull binglekruger/ntls-ntc:v2

    # Verify image installation
    echo "Verifying Docker image installation..."
    sudo docker images

    # Run a temporary container to execute the command and save output
    echo "Running temporary container to get sigstruct data..."
    TEMP_CONTAINER_ID=$(sudo docker run -d --name temp-container \\
        --device=/dev/sgx_enclave \\
        --device=/dev/sgx_provision \\
        binglekruger/ntls-ntc:v2)

    # Wait for container to initialize
    echo "Waiting for container to initialize..."
    sleep 5

    # Execute command in Docker container and save output (without -it flags)
    echo "Executing sgx-sigstruct-view command in container..."
    echo "--- SIGSTRUCT_DATA_START ---"
    sudo docker exec $TEMP_CONTAINER_ID /bin/bash -c "gramine-sgx-sigstruct-view sgx-mvp.sig"
    echo "--- SIGSTRUCT_DATA_END ---"

    # Stop and remove the temporary container
    echo "Stopping and removing temporary container..."
    sudo docker stop $TEMP_CONTAINER_ID
    sudo docker rm $TEMP_CONTAINER_ID

    # Remove any existing container with the same name
    echo "Checking for existing containers with the same name..."
    if sudo docker ps -a | grep -q ntls-server; then
        echo "Removing existing ntls-server container..."
        sudo docker rm -f ntls-server
    fi

    # Run the final container with the HTTPS port (443)
    echo "Running final Docker container on HTTPS port..."
    sudo docker run -d -p 443:8081 \\
        --restart=unless-stopped \\
        --name ntls-server \\
        --device=/dev/sgx_enclave \\
        --device=/dev/sgx_provision \\
        binglekruger/ntls-ntc:v2

    # Check if container is running
    echo "Checking container status..."
    if sudo docker ps | grep -q ntls-server; then
        echo "Container 'ntls-server' is running successfully!"
        echo "The HTTPS server is now accessible at https://$(hostname -I | awk '{print $1}')/health"
    else
        echo "WARNING: Container appears to have stopped. Checking logs for errors..."
        sudo docker logs ntls-server
    fi

    echo "Setup completed successfully!"
    '''

            # The script extension needs to be base64-encoded
            import base64
            encoded_script = base64.b64encode(script_content.encode()).decode()

            # Set up the custom script extension parameters
            extension_name = f"{vm_name}-setup-script"
            extension_params = {
                'location': self.location,
                'publisher': 'Microsoft.Azure.Extensions',
                'type': 'CustomScript',
                'type_handler_version': '2.1',
                'auto_upgrade_minor_version': True,
                'settings': {
                    'script': encoded_script
                },
                'protected_settings': {}
            }

            # Deploy the extension to run the script
            poller = self.compute_client.virtual_machine_extensions.begin_create_or_update(
                self.resource_group,
                vm_name,
                extension_name,
                extension_params
            )
            
            # Wait for the extension to complete
            extension_result = poller.result()
            
            # Check if the extension was successfully deployed
            provisioning_state = extension_result.provisioning_state
            if provisioning_state == 'Succeeded':
                logger.info(f"Setup script executed successfully on VM: {vm_name}")
                
                # Get the output of the extension to extract the sigstruct data
                output = self.compute_client.virtual_machine_extensions.get(
                    self.resource_group,
                    vm_name,
                    extension_name,
                    expand="instanceView"
                )
                
                # Parse the output to extract the sigstruct data
                sigstruct_data = None
                if output.instance_view and output.instance_view.statuses:
                    for status in output.instance_view.statuses:
                        if status.message:
                            # Look for the sigstruct data in the output
                            start_marker = "--- SIGSTRUCT_DATA_START ---"
                            end_marker = "--- SIGSTRUCT_DATA_END ---"
                            start_index = status.message.find(start_marker)
                            end_index = status.message.find(end_marker)
                            
                            if start_index != -1 and end_index != -1:
                                # Extract the raw output
                                raw_output = status.message[start_index + len(start_marker):end_index].strip()
                                logger.info(f"Raw output: {raw_output}")
                                
                                # Parse the output to extract the values we want
                                sigstruct_data = {}
                                
                                for line in raw_output.splitlines():
                                    line = line.strip()
                                    if line.startswith("mr_signer:"):
                                        sigstruct_data["mr_signer"] = line.split(":", 1)[1].strip()
                                    elif line.startswith("mr_enclave:"):
                                        sigstruct_data["mr_enclave"] = line.split(":", 1)[1].strip()
                                    elif line.startswith("isv_prod_id:"):
                                        sigstruct_data["isv_prod_id"] = line.split(":", 1)[1].strip()
                                    elif line.startswith("isv_svn:"):
                                        sigstruct_data["isv_svn"] = line.split(":", 1)[1].strip()
                                
                                if sigstruct_data:
                                    logger.info(f"Successfully extracted sigstruct data: {sigstruct_data}")
                
                return True, sigstruct_data
            else:
                logger.error(f"Setup script execution failed on VM: {vm_name}. Status: {provisioning_state}")
                return False, None
                
        except Exception as e:
            logger.error(f"Failed to run setup script on VM {vm_name}: {str(e)}")
            raise

    # Inside the AzureVMDeployer class, add this method
    async def wait_for_vm_ready(self, vm_name: str, timeout: int = 300, poll_interval: int = 10) -> bool:
        """
        Wait until the VM is fully provisioned and running.

        Args:
            vm_name (str): Name of the VM to check.
            timeout (int): Maximum time to wait in seconds (default: 300).
            poll_interval (int): Time between status checks in seconds (default: 10).

        Returns:
            bool: True if VM is ready, False if timeout occurs.
        """
        import time
        logger.info(f"Waiting for VM {vm_name} to be ready...")

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                instance_view = self.compute_client.virtual_machines.instance_view(
                    self.resource_group,
                    vm_name
                )
                statuses = instance_view.statuses

                # Check provisioning state and power state
                provisioning_state = None
                power_state = None
                for status in statuses:
                    if status.code.startswith("ProvisioningState/"):
                        provisioning_state = status.display_status
                    if status.code.startswith("PowerState/"):
                        power_state = status.display_status

                logger.debug(f"VM {vm_name} - Provisioning: {provisioning_state}, Power: {power_state}")

                # VM is ready when provisioning is succeeded and power state is running
                if (provisioning_state == "Provisioning succeeded" and 
                    power_state == "VM running"):
                    logger.info(f"VM {vm_name} is fully provisioned and running.")
                    return True

                # Wait before polling again
                await asyncio.sleep(poll_interval)

            except Exception as e:
                logger.error(f"Error checking VM status for {vm_name}: {str(e)}")
                await asyncio.sleep(poll_interval)  # Retry after delay

        logger.error(f"Timeout waiting for VM {vm_name} to be ready after {timeout} seconds.")
        return False


def main():
    try:
        deployer = AzureVMDeployer()
        vm_name = deployer.generate_unique_name(base_name="january-2025")
        nic_name = f"{vm_name}-nic"
        nsg_name = f"{vm_name}-nsg"
        
        # Get subnet ID - you might want to create this if it doesn't exist
        subnet_id = f"/subscriptions/{deployer.subscription_id}/resourceGroups/{deployer.resource_group}/providers/Microsoft.Network/virtualNetworks/{settings.VNET_NAME}/subnets/{settings.SUBNET_NAME}"
        
        logger.info(f"Starting deployment for VM: {vm_name}")

        # Step 1: Create NSG
        nsg = deployer.create_network_security_group(nsg_name)

        # Step 2: Create Network Interface with NSG
        nic = deployer.create_network_interface(nic_name, subnet_id, nsg.id)

        # Step 3: Create VM
        vm = deployer.create_vm(vm_name, nic.id)

        # Step 4: Get public IP
        public_ip = deployer.get_vm_public_ip(vm_name)
        
        logger.info(f"Successfully deployed VM: {vm_name}")
        if public_ip:
            logger.info(f"Public IP address: {public_ip}")
        
        return vm_name
    
    except Exception as e:
        logger.error(f"Deployment failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()