# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

"""Regression tests for the ARM request bodies in scripts/azure_deployer.py.

These exist because of a production failure that no unit test could have caught
by mocking the Azure clients: the bodies were plain snake_case dicts, and
azure-mgmt-network 31.x serializes a dict to JSON *verbatim* rather than mapping
it through the model's attribute names. Every deployment died with

    (InvalidRequestContent) The request content was invalid and could not be
    deserialized: 'Could not find member 'security_rules' on object of type
    'ResourceDefinition''

So these tests assert on the bytes that actually reach ARM: the body must nest
under `properties` and use camelCase. They serialize with the same encoder the
SDK's own operations use, so they fail if a future SDK bump changes the
contract, not merely if someone renames a Python attribute.
"""

import json

import pytest

from azure.mgmt.compute._utils.model_base import SdkJSONEncoder as ComputeEncoder
from azure.mgmt.network._utils.model_base import SdkJSONEncoder as NetworkEncoder


def _wire(body, encoder):
    """The exact JSON the SDK operation would put on the wire."""
    return json.loads(json.dumps(body, cls=encoder, exclude_readonly=True))


def test_network_security_group_body_is_arm_shaped():
    from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule

    body = _wire(
        NetworkSecurityGroup(
            location="westeurope",
            security_rules=[
                SecurityRule(
                    name="AllowSSH",
                    priority=100,
                    direction="Inbound",
                    access="Allow",
                    protocol="Tcp",
                    source_port_range="*",
                    destination_port_range="22",
                    source_address_prefix="*",
                    destination_address_prefix="*",
                )
            ],
        ),
        NetworkEncoder,
    )

    # The exact key that ARM rejected.
    assert "security_rules" not in body
    assert body["properties"]["securityRules"][0]["name"] == "AllowSSH"
    assert body["properties"]["securityRules"][0]["properties"]["destinationPortRange"] == "22"


def test_a_plain_dict_body_would_still_be_rejected():
    """Guards the reason the models are mandatory, not stylistic.

    If this ever starts failing, the SDK has gone back to mapping dict keys and
    the constraint documented in azure_deployer.py no longer holds.
    """
    body = _wire({"location": "westeurope", "security_rules": []}, NetworkEncoder)
    assert body == {"location": "westeurope", "security_rules": []}
    assert "properties" not in body


def test_public_ip_and_nic_bodies_are_arm_shaped():
    from azure.mgmt.network.models import (
        NetworkInterface,
        NetworkInterfaceIPConfiguration,
        NetworkInterfaceIPConfigurationPropertiesFormat,
        NetworkInterfacePropertiesFormat,
        NetworkSecurityGroup,
        PublicIPAddress,
        PublicIPAddressPropertiesFormat,
        PublicIPAddressSku,
        Subnet,
    )

    pip = _wire(
        PublicIPAddress(
            location="westeurope",
            sku=PublicIPAddressSku(name="Standard"),
            properties=PublicIPAddressPropertiesFormat(
                public_ip_allocation_method="Static",
                public_ip_address_version="IPv4",
            ),
        ),
        NetworkEncoder,
    )
    assert pip["sku"]["name"] == "Standard"
    assert pip["properties"]["publicIPAllocationMethod"] == "Static"

    props = NetworkInterfacePropertiesFormat(
        ip_configurations=[
            NetworkInterfaceIPConfiguration(
                name="nic-ipconfig",
                properties=NetworkInterfaceIPConfigurationPropertiesFormat(
                    subnet=Subnet(id="/subnets/default"),
                    public_ip_address=PublicIPAddress(id="/publicIPAddresses/pip"),
                ),
            )
        ]
    )
    props.network_security_group = NetworkSecurityGroup(id="/networkSecurityGroups/nsg")
    nic = _wire(NetworkInterface(location="westeurope", properties=props), NetworkEncoder)

    ip_config = nic["properties"]["ipConfigurations"][0]
    assert ip_config["properties"]["subnet"]["id"] == "/subnets/default"
    assert ip_config["properties"]["publicIPAddress"]["id"] == "/publicIPAddresses/pip"
    # Attached to the NIC, not to the ip configuration.
    assert nic["properties"]["networkSecurityGroup"]["id"] == "/networkSecurityGroups/nsg"


def test_custom_script_extension_body_is_arm_shaped():
    from azure.mgmt.compute.models import (
        VirtualMachineExtension,
        VirtualMachineExtensionProperties,
    )

    body = _wire(
        VirtualMachineExtension(
            location="westeurope",
            properties=VirtualMachineExtensionProperties(
                publisher="Microsoft.Azure.Extensions",
                type="CustomScript",
                type_handler_version="2.1",
                auto_upgrade_minor_version=True,
                settings={"script": "BASE64"},
                protected_settings={},
            ),
        ),
        ComputeEncoder,
    )

    assert body["properties"]["type"] == "CustomScript"
    assert body["properties"]["typeHandlerVersion"] == "2.1"
    assert body["properties"]["autoUpgradeMinorVersion"] is True
    assert body["properties"]["settings"] == {"script": "BASE64"}


def test_vm_body_matches_the_hand_written_arm_json_it_replaced():
    """The VM body was already valid ARM JSON, so the model rewrite must be a
    byte-for-byte no-op. This pins that equivalence."""
    from azure.mgmt.compute.models import (
        HardwareProfile,
        ImageReference,
        LinuxConfiguration,
        ManagedDiskParameters,
        NetworkInterfaceReference,
        NetworkProfile,
        OSDisk,
        OSProfile,
        SecurityProfile,
        SshConfiguration,
        SshPublicKey,
        StorageProfile,
        UefiSettings,
        VirtualMachine,
        VirtualMachineProperties,
    )

    image = {
        "publisher": "canonical",
        "offer": "0001-com-ubuntu-minimal-focal",
        "sku": "minimal-20_04-lts-gen2",
        "version": "latest",
    }

    built = _wire(
        VirtualMachine(
            location="westeurope",
            tags={"pool": "test"},
            properties=VirtualMachineProperties(
                hardware_profile=HardwareProfile(vm_size="Standard_DC1s_v3"),
                storage_profile=StorageProfile(
                    image_reference=ImageReference(**image),
                    os_disk=OSDisk(
                        create_option="FromImage",
                        managed_disk=ManagedDiskParameters(
                            storage_account_type="StandardSSD_LRS"
                        ),
                    ),
                ),
                network_profile=NetworkProfile(
                    network_interfaces=[
                        NetworkInterfaceReference(id="/nic", delete_option="Delete")
                    ]
                ),
                os_profile=OSProfile(
                    computer_name="vm1",
                    admin_username="azureuser",
                    linux_configuration=LinuxConfiguration(
                        disable_password_authentication=True,
                        ssh=SshConfiguration(
                            public_keys=[
                                SshPublicKey(
                                    path="/home/azureuser/.ssh/authorized_keys",
                                    key_data="ssh-rsa AAAA",
                                )
                            ]
                        ),
                    ),
                ),
                security_profile=SecurityProfile(
                    uefi_settings=UefiSettings(
                        secure_boot_enabled=True, v_tpm_enabled=True
                    ),
                    security_type="TrustedLaunch",
                ),
            ),
        ),
        ComputeEncoder,
    )

    assert built == {
        "location": "westeurope",
        "tags": {"pool": "test"},
        "properties": {
            "hardwareProfile": {"vmSize": "Standard_DC1s_v3"},
            "storageProfile": {
                "imageReference": image,
                "osDisk": {
                    "createOption": "FromImage",
                    "managedDisk": {"storageAccountType": "StandardSSD_LRS"},
                },
            },
            "networkProfile": {
                "networkInterfaces": [
                    {"id": "/nic", "properties": {"deleteOption": "Delete"}}
                ]
            },
            "osProfile": {
                "computerName": "vm1",
                "adminUsername": "azureuser",
                "linuxConfiguration": {
                    "disablePasswordAuthentication": True,
                    "ssh": {
                        "publicKeys": [
                            {
                                "path": "/home/azureuser/.ssh/authorized_keys",
                                "keyData": "ssh-rsa AAAA",
                            }
                        ]
                    },
                },
            },
            "securityProfile": {
                "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True},
                "securityType": "TrustedLaunch",
            },
        },
    }


def test_sgx_image_default_points_at_a_tag_ci_publishes():
    """CI publishes `main-latest`; `staging-latest` was never created and would
    fail the pull on a freshly provisioned VM."""
    from config import settings

    assert settings.SGX_IMAGE.startswith("ghcr.io/relational-network/sgx-mvp")
    assert "staging-latest" not in settings.SGX_IMAGE
