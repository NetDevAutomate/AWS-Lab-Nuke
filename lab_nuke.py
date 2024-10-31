#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS Resource Cleanup Script
===========================

Refactored version of the AWS resource cleanup script with improved structure and reduced redundancy.
Handles cleanup of VPCs, Network Firewalls, CloudWAN, and related resources.

Author: Andy Taylor
Date: 2024-10-26
License: MIT License
Version: 1.1
"""

import argparse
import logging
import time
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Callable, Set

import boto3
from botocore.exceptions import WaiterError, ClientError
from botocore.paginate import Paginator

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AWSResource:
    """Base class for AWS resources with common deletion patterns"""

    resource_id: str
    region: str
    client: Any

    def delete(self) -> bool:
        """Template method for resource deletion"""
        try:
            self._pre_delete()
            self._perform_delete()
            self._post_delete()
            logger.info(
                f"Successfully deleted {self.__class__.__name__} {self.resource_id}"
            )
            return True
        except ClientError as e:
            logger.error(
                f"Failed to delete {self.__class__.__name__} {self.resource_id}: {e}"
            )
            return False

    def _pre_delete(self):
        """Hook for pre-deletion tasks"""
        pass

    def _perform_delete(self):
        """Main deletion logic - must be implemented by subclasses"""
        raise NotImplementedError

    def _post_delete(self):
        """Hook for post-deletion tasks"""
        pass


class ResourceManager:
    """Base class for AWS resource management operations"""

    def __init__(self, region: str, dry_run: bool = False):
        self.region = region
        self.dry_run = dry_run
        self.ec2_client = boto3.client("ec2", region_name=region)
        self.nfw_client = boto3.client("network-firewall", region_name=region)
        self.networkmanager_client = boto3.client("networkmanager", region_name=region)
        self.directconnect_client = boto3.client("directconnect", region_name=region)

    def paginate(self, client: Any, operation: str, **kwargs) -> List[Dict]:
        """Generic pagination helper"""
        paginator = client.get_paginator(operation)
        items = []
        for page in paginator.paginate(**kwargs):
            items.extend(page.get(self._get_result_key(operation), []))
        return items

    @staticmethod
    def _get_result_key(operation: str) -> str:
        """Map operations to their result keys"""
        key_mapping = {
            "describe_vpcs": "Vpcs",
            "describe_instances": "Reservations",
            "describe_subnets": "Subnets",
            "describe_security_groups": "SecurityGroups",
            "describe_nat_gateways": "NatGateways",
            "describe_internet_gateways": "InternetGateways",
            "describe_vpc_endpoints": "VpcEndpoints",
            "describe_network_interfaces": "NetworkInterfaces",
            "describe_route_tables": "RouteTables",
            "list_firewalls": "Firewalls",
            "list_core_networks": "CoreNetworks",
            "describe_transit_gateways": "TransitGateways",
            "describe_direct_connect_gateways": "directConnectGateways",
            "describe_transit_gateway_attachments": "TransitGatewayAttachments",
            "describe_transit_gateway_vpc_attachments": "TransitGatewayVpcAttachments",
            "describe_transit_gateway_peering_attachments": "TransitGatewayPeeringAttachments",
            "describe_vpn_connections": "VpnConnections",
            "describe_direct_connect_gateway_attachments": "directConnectGatewayAttachments",
            "describe_direct_connect_gateway_associations": "directConnectGatewayAssociations",
        }
        return key_mapping.get(operation, "")

    def wait_for_deletion(
        self, check_func: Callable[[], bool], timeout: int = 600, interval: int = 30
    ) -> bool:
        """Generic waiter for resource deletion"""
        end_time = time.time() + timeout
        while time.time() < end_time:
            if check_func():
                return True
            time.sleep(interval)
        return False


class SecurityGroupManager:
    """Handles security group operations"""

    def __init__(self, ec2_client, dry_run: bool = False):
        self.ec2_client = ec2_client
        self.dry_run = dry_run

    def remove_all_rules(self, sg_id: str) -> None:
        """Remove all rules from a security group"""
        try:
            sg = self.ec2_client.describe_security_groups(GroupIds=[sg_id])[
                "SecurityGroups"
            ][0]

            if sg["IpPermissions"]:
                self.ec2_client.revoke_security_group_ingress(
                    GroupId=sg_id, IpPermissions=sg["IpPermissions"]
                )

            if sg["IpPermissionsEgress"]:
                self.ec2_client.revoke_security_group_egress(
                    GroupId=sg_id, IpPermissions=sg["IpPermissionsEgress"]
                )

        except ClientError as e:
            logger.error(f"Error removing rules from security group {sg_id}: {e}")

    def remove_references(self, vpc_id: str, target_sg_id: str) -> None:
        """Remove references to a security group from other groups"""
        security_groups = self.ec2_client.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]

        for sg in security_groups:
            if sg["GroupId"] == target_sg_id:
                continue

            self._remove_sg_references(sg["GroupId"], target_sg_id)

    def _remove_sg_references(self, sg_id: str, target_sg_id: str) -> None:
        """Remove references to target_sg_id from specified security group"""
        try:
            sg = self.ec2_client.describe_security_groups(GroupIds=[sg_id])[
                "SecurityGroups"
            ][0]

            # Handle ingress rules
            ingress_rules = [
                rule
                for rule in sg["IpPermissions"]
                if any(
                    pair["GroupId"] == target_sg_id
                    for pair in rule.get("UserIdGroupPairs", [])
                )
            ]
            if ingress_rules:
                self.ec2_client.revoke_security_group_ingress(
                    GroupId=sg_id, IpPermissions=ingress_rules
                )

            # Handle egress rules
            egress_rules = [
                rule
                for rule in sg["IpPermissionsEgress"]
                if any(
                    pair["GroupId"] == target_sg_id
                    for pair in rule.get("UserIdGroupPairs", [])
                )
            ]
            if egress_rules:
                self.ec2_client.revoke_security_group_egress(
                    GroupId=sg_id, IpPermissions=egress_rules
                )

        except ClientError as e:
            logger.error(
                f"Error removing references to {target_sg_id} from {sg_id}: {e}"
            )


class VPCCleaner(ResourceManager):
    """Handles VPC and related resource cleanup"""

    def __init__(self, region: str, dry_run: bool = False):
        super().__init__(region, dry_run)
        self.gwlb_only_vpcs: Set[str] = set()
        self.sg_manager = SecurityGroupManager(self.ec2_client, dry_run)

    def cleanup_vpc(self, vpc_id: str) -> None:
        """Main VPC cleanup sequence"""
        if self._is_default_vpc(vpc_id):
            logger.info(f"Skipping default VPC: {vpc_id}")
            return

        cleanup_sequence = [
            self._cleanup_instances,
            self._cleanup_endpoints,
            self._cleanup_nat_gateways,
            self._cleanup_network_interfaces,
            self._cleanup_security_groups,
            self._cleanup_route_tables,
            self._cleanup_subnets,
            self._cleanup_internet_gateways,
        ]

        if self.dry_run:
            logger.info(
                f"[DRY RUN] Would clean up VPC {vpc_id} with the following sequence:"
            )
            for cleanup_step in cleanup_sequence:
                logger.info(f"[DRY RUN] - {cleanup_step.__name__}")

        for cleanup_step in cleanup_sequence:
            try:
                cleanup_step(vpc_id)
            except Exception as e:
                logger.error(f"Error in {cleanup_step.__name__} for VPC {vpc_id}: {e}")
                if self._has_gwlb_resources(vpc_id):
                    self.gwlb_only_vpcs.add(vpc_id)
                    logger.info(
                        f"Added VPC {vpc_id} to GWLB-only list for later deletion"
                    )
                return

        self._delete_vpc(vpc_id)

    def _is_default_vpc(self, vpc_id: str) -> bool:
        """Check if VPC is default"""
        vpc = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        return vpc.get("IsDefault", False)

    def _has_gwlb_resources(self, vpc_id: str) -> bool:
        """Check if VPC has GWLB resources"""
        endpoints = self.paginate(
            self.ec2_client,
            "describe_vpc_endpoints",
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "vpc-endpoint-type", "Values": ["GatewayLoadBalancer"]},
            ],
        )
        return bool(endpoints)

    def _cleanup_instances(self, vpc_id: str) -> None:
        """Terminate EC2 instances in VPC"""
        instances = self.paginate(
            self.ec2_client,
            "describe_instances",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        instance_ids = [
            instance["InstanceId"]
            for reservation in instances
            for instance in reservation["Instances"]
            if instance["State"]["Name"] not in ("terminated", "shutting-down")
        ]

        if instance_ids:
            if self.dry_run:
                logger.info(f"[DRY RUN] Would terminate instances: {instance_ids}")
                return

            try:
                self.ec2_client.terminate_instances(InstanceIds=instance_ids)
                logger.info(f"Initiated termination of instances: {instance_ids}")

                waiter = self.ec2_client.get_waiter("instance_terminated")
                waiter.wait(InstanceIds=instance_ids)
                logger.info(f"Successfully terminated instances: {instance_ids}")
            except WaiterError as e:
                logger.error(f"Error waiting for instances to terminate: {e}")

    def _cleanup_endpoints(self, vpc_id: str) -> None:
        """Clean up VPC endpoints"""
        endpoints = self.paginate(
            self.ec2_client,
            "describe_vpc_endpoints",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        for endpoint in endpoints:
            if endpoint["VpcEndpointType"] != "GatewayLoadBalancer":
                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would delete VPC endpoint: {endpoint['VpcEndpointId']}"
                    )
                    continue

                try:
                    self.ec2_client.delete_vpc_endpoints(
                        VpcEndpointIds=[endpoint["VpcEndpointId"]]
                    )
                    logger.info(f"Deleted VPC endpoint: {endpoint['VpcEndpointId']}")
                except ClientError as e:
                    logger.error(
                        f"Failed to delete VPC endpoint {endpoint['VpcEndpointId']}: {e}"
                    )

    def _cleanup_nat_gateways(self, vpc_id: str) -> None:
        """Delete NAT Gateways"""
        nat_gateways = self.paginate(
            self.ec2_client,
            "describe_nat_gateways",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        for nat_gateway in nat_gateways:
            if self.dry_run:
                logger.info(
                    f"[DRY RUN] Would delete NAT Gateway: {nat_gateway['NatGatewayId']}"
                )
                continue

            try:
                self.ec2_client.delete_nat_gateway(
                    NatGatewayId=nat_gateway["NatGatewayId"]
                )
                logger.info(
                    f"Initiated deletion of NAT Gateway: {nat_gateway['NatGatewayId']}"
                )

                # Add waiting for NAT Gateway deletion
                def is_nat_deleted():
                    response = self.ec2_client.describe_nat_gateways(
                        NatGatewayIds=[nat_gateway["NatGatewayId"]]
                    )
                    return response["NatGateways"][0]["State"] == "deleted"

                if self.wait_for_deletion(is_nat_deleted):
                    logger.info(
                        f"NAT Gateway {nat_gateway['NatGatewayId']} deleted successfully"
                    )
                else:
                    logger.error(
                        f"Timeout waiting for NAT Gateway {nat_gateway['NatGatewayId']} deletion"
                    )

            except ClientError as e:
                logger.error(
                    f"Failed to delete NAT Gateway {nat_gateway['NatGatewayId']}: {e}"
                )

    def _cleanup_network_interfaces(self, vpc_id: str) -> None:
        """Delete network interfaces"""
        interfaces = self.paginate(
            self.ec2_client,
            "describe_network_interfaces",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        for interface in interfaces:
            if interface["InterfaceType"] != "gateway_load_balancer_endpoint":
                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would delete network interface: {interface['NetworkInterfaceId']}"
                    )
                    continue

                try:
                    self.ec2_client.delete_network_interface(
                        NetworkInterfaceId=interface["NetworkInterfaceId"]
                    )
                    logger.info(
                        f"Deleted network interface: {interface['NetworkInterfaceId']}"
                    )
                except ClientError as e:
                    logger.error(
                        f"Failed to delete network interface {interface['NetworkInterfaceId']}: {e}"
                    )

    def _cleanup_security_groups(self, vpc_id: str) -> None:
        """Delete non-default security groups"""
        security_groups = self.paginate(
            self.ec2_client,
            "describe_security_groups",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        for sg in security_groups:
            if sg["GroupName"] != "default":
                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would delete security group: {sg['GroupId']}"
                    )
                    continue

                self.sg_manager.remove_all_rules(sg["GroupId"])
                self.sg_manager.remove_references(vpc_id, sg["GroupId"])
                try:
                    self.ec2_client.delete_security_group(GroupId=sg["GroupId"])
                    logger.info(f"Deleted security group: {sg['GroupId']}")
                except ClientError as e:
                    logger.error(
                        f"Failed to delete security group {sg['GroupId']}: {e}"
                    )

    def _cleanup_route_tables(self, vpc_id: str) -> None:
        """Delete route tables"""
        route_tables = self.paginate(
            self.ec2_client,
            "describe_route_tables",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        for rt in route_tables:
            # Skip main route table
            if any(assoc.get("Main", False) for assoc in rt.get("Associations", [])):
                continue

            if self.dry_run:
                logger.info(f"[DRY RUN] Would delete route table: {rt['RouteTableId']}")
                continue

            # First disassociate any subnet associations
            for assoc in rt.get("Associations", []):
                if not assoc.get("Main", False):
                    try:
                        self.ec2_client.disassociate_route_table(
                            AssociationId=assoc["RouteTableAssociationId"]
                        )
                        logger.info(
                            f"Disassociated route table {rt['RouteTableId']} from subnet"
                        )
                    except ClientError:
                        pass

            # Then remove non-local routes
            for route in rt.get("Routes", []):
                if route.get("GatewayId") != "local":
                    try:
                        if "DestinationCidrBlock" in route:
                            self.ec2_client.delete_route(
                                RouteTableId=rt["RouteTableId"],
                                DestinationCidrBlock=route["DestinationCidrBlock"],
                            )
                            logger.info(
                                f"Deleted route {route['DestinationCidrBlock']} from {rt['RouteTableId']}"
                            )
                    except ClientError:
                        pass

            # Finally delete the route table
            try:
                self.ec2_client.delete_route_table(RouteTableId=rt["RouteTableId"])
                logger.info(f"Deleted route table: {rt['RouteTableId']}")
            except ClientError as e:
                logger.error(f"Failed to delete route table {rt['RouteTableId']}: {e}")

    def _cleanup_subnets(self, vpc_id: str) -> None:
        """Delete subnets"""
        subnets = self.paginate(
            self.ec2_client,
            "describe_subnets",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        for subnet in subnets:
            if self.dry_run:
                logger.info(f"[DRY RUN] Would delete subnet: {subnet['SubnetId']}")
                continue

            try:
                self.ec2_client.delete_subnet(SubnetId=subnet["SubnetId"])
                logger.info(f"Deleted subnet: {subnet['SubnetId']}")
            except ClientError as e:
                logger.error(f"Failed to delete subnet {subnet['SubnetId']}: {e}")

    def _cleanup_internet_gateways(self, vpc_id: str) -> None:
        """Delete Internet Gateways"""
        igws = self.paginate(
            self.ec2_client,
            "describe_internet_gateways",
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}],
        )

        for igw in igws:
            if self.dry_run:
                logger.info(
                    f"[DRY RUN] Would delete Internet Gateway: {igw['InternetGatewayId']}"
                )
                continue

            try:
                self.ec2_client.detach_internet_gateway(
                    InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id
                )
                logger.info(f"Detached Internet Gateway: {igw['InternetGatewayId']}")

                self.ec2_client.delete_internet_gateway(
                    InternetGatewayId=igw["InternetGatewayId"]
                )
                logger.info(f"Deleted Internet Gateway: {igw['InternetGatewayId']}")
            except ClientError as e:
                logger.error(
                    f"Failed to delete Internet Gateway {igw['InternetGatewayId']}: {e}"
                )

    def _delete_vpc(self, vpc_id: str) -> None:
        """Delete the VPC itself"""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete VPC: {vpc_id}")
            return

        try:
            self.ec2_client.delete_vpc(VpcId=vpc_id)
            logger.info(f"Deleted VPC: {vpc_id}")
        except ClientError as e:
            logger.error(f"Failed to delete VPC {vpc_id}: {e}")


class NetworkFirewallCleaner(ResourceManager):
    """Handles AWS Network Firewall cleanup"""

    def cleanup_firewalls(self, vpc_id: Optional[str] = None) -> None:
        """Clean up Network Firewalls"""
        filters = {"VpcIds": [vpc_id]} if vpc_id else {}
        firewalls = self.paginate(self.nfw_client, "list_firewalls", **filters)

        for firewall in firewalls:
            self._disable_protection(firewall)
            self._remove_logging(firewall)
            self._delete_firewall(firewall)

    def _disable_protection(self, firewall: Dict) -> None:
        """Disable firewall protection"""
        try:
            firewall_config = self.nfw_client.describe_firewall(
                FirewallName=firewall["FirewallName"]
            )
            if firewall_config["Firewall"]["DeleteProtection"]:
                self.nfw_client.update_firewall_delete_protection(
                    FirewallArn=firewall["FirewallArn"], DeleteProtection=False
                )
                logger.info(
                    f"Disabled delete protection for firewall {firewall['FirewallName']}"
                )
        except ClientError as e:
            logger.error(
                f"Error disabling protection for firewall {firewall['FirewallName']}: {e}"
            )

    def _remove_logging(self, firewall: Dict) -> None:
        """Remove firewall logging configuration"""
        try:
            if self.dry_run:
                logger.info(
                    f"[DRY RUN] Would remove logging from firewall: {firewall['FirewallName']}"
                )
                return

            logging_config = self.nfw_client.describe_logging_configuration(
                FirewallArn=firewall["FirewallArn"]
            )
            if "LoggingConfiguration" in logging_config:
                # Clear all logging configurations at once
                self.nfw_client.update_logging_configuration(
                    FirewallArn=firewall["FirewallArn"],
                    LoggingConfiguration={"LogDestinationConfigs": []},
                )
                logger.info(
                    f"Removed logging configuration for firewall {firewall['FirewallName']}"
                )
        except ClientError as e:
            if "InvalidRequestException" in str(e):
                # Handle multiple log destinations by removing them one by one
                try:
                    logging_config = self.nfw_client.describe_logging_configuration(
                        FirewallArn=firewall["FirewallArn"]
                    )
                    current_configs = logging_config.get(
                        "LoggingConfiguration", {}
                    ).get("LogDestinationConfigs", [])

                    for config in current_configs:
                        remaining_configs = [c for c in current_configs if c != config]
                        self.nfw_client.update_logging_configuration(
                            FirewallArn=firewall["FirewallArn"],
                            LoggingConfiguration={
                                "LogDestinationConfigs": remaining_configs
                            },
                        )
                    logger.info(
                        f"Removed all logging configurations for firewall {firewall['FirewallName']}"
                    )
                except ClientError as inner_e:
                    logger.error(
                        f"Error removing individual logging configs for firewall {firewall['FirewallName']}: {inner_e}"
                    )
            else:
                logger.error(
                    f"Error removing logging for firewall {firewall['FirewallName']}: {e}"
                )


class CloudWANCleaner(ResourceManager):
    """Handles CloudWAN resource cleanup"""

    def cleanup_cloudwan(self) -> None:
        """Clean up CloudWAN resources"""
        if self.dry_run:
            logger.info("[DRY RUN] Would clean up CloudWAN resources")
            self._list_resources_to_delete()
            return

        self._cleanup_core_networks()  # Changed to match the call
        self._cleanup_global_networks()

    def _cleanup_core_networks(self) -> None:  # Changed from _delete_core_network
        """Clean up Core Networks"""
        try:
            core_networks = self.paginate(
                self.networkmanager_client, "list_core_networks"
            )

            for network in core_networks:
                core_network_id = network["CoreNetworkId"]
                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would delete Core Network {core_network_id}"
                    )
                    continue

                self._delete_core_network(core_network_id)
        except ClientError as e:
            logger.error(f"Error cleaning up Core Networks: {e}")

    def _delete_core_network(self, core_network_id: str) -> None:
        """Delete a single Core Network and its dependencies"""
        try:
            # Delete peerings first
            peerings = self.networkmanager_client.list_peerings(
                CoreNetworkId=core_network_id
            )["Peerings"]

            for peering in peerings:
                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would delete peering: {peering['PeeringId']}"
                    )
                    continue

                self.networkmanager_client.delete_peering(
                    PeeringId=peering["PeeringId"]
                )
                logger.info(f"Deleted peering {peering['PeeringId']}")

            # Delete the core network
            if not self.dry_run:
                self.networkmanager_client.delete_core_network(
                    CoreNetworkId=core_network_id
                )
                logger.info(f"Deleted Core Network {core_network_id}")
        except ClientError as e:
            logger.error(f"Error deleting Core Network {core_network_id}: {e}")

    def _cleanup_global_networks(self) -> None:
        """Clean up Global Networks"""
        try:
            # Use paginator for describe_global_networks
            paginator = self.networkmanager_client.get_paginator(
                "describe_global_networks"
            )
            global_networks = []
            for page in paginator.paginate():
                global_networks.extend(page["GlobalNetworks"])

            for network in global_networks:
                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] Would delete Global Network: {network['GlobalNetworkId']}"
                    )
                    continue

                self._delete_global_network(network["GlobalNetworkId"])
        except ClientError as e:
            logger.error(f"Error cleaning up Global Networks: {e}")

    def _delete_global_network(self, global_network_id: str) -> None:
        """Delete a Global Network and its dependencies"""
        try:
            # Delete sites first
            sites = self.paginate(
                self.networkmanager_client,
                "get_sites",
                GlobalNetworkId=global_network_id,
            )
            for site in sites:
                if not self.dry_run:
                    self.networkmanager_client.delete_site(
                        GlobalNetworkId=global_network_id, SiteId=site["SiteId"]
                    )
                    logger.info(f"Deleted site {site['SiteId']}")

            # Delete devices
            devices = self.paginate(
                self.networkmanager_client,
                "get_devices",
                GlobalNetworkId=global_network_id,
            )
            for device in devices:
                if not self.dry_run:
                    self.networkmanager_client.delete_device(
                        GlobalNetworkId=global_network_id, DeviceId=device["DeviceId"]
                    )
                    logger.info(f"Deleted device {device['DeviceId']}")

            # Delete the global network
            if not self.dry_run:
                self.networkmanager_client.delete_global_network(
                    GlobalNetworkId=global_network_id
                )
                logger.info(f"Deleted Global Network {global_network_id}")
        except ClientError as e:
            logger.error(f"Error deleting Global Network {global_network_id}: {e}")

    def _list_resources_to_delete(self) -> None:
        """List all CloudWAN resources that would be deleted in dry-run mode"""
        try:
            # List Core Networks
            core_networks = self.paginate(
                self.networkmanager_client, "list_core_networks"
            )
            for network in core_networks:
                logger.info(
                    f"[DRY RUN] Would delete Core Network: {network['CoreNetworkId']}"
                )

                # List peerings
                peerings = self.networkmanager_client.list_peerings(
                    CoreNetworkId=network["CoreNetworkId"]
                )["Peerings"]
                for peering in peerings:
                    logger.info(
                        f"[DRY RUN] Would delete peering: {peering['PeeringId']}"
                    )

            # List Global Networks
            global_networks = self.networkmanager_client.describe_global_networks()[
                "GlobalNetworks"
            ]
            for network in global_networks:
                logger.info(
                    f"[DRY RUN] Would delete Global Network: {network['GlobalNetworkId']}"
                )

                # List sites
                sites = self.paginate(
                    self.networkmanager_client,
                    "get_sites",
                    GlobalNetworkId=network["GlobalNetworkId"],
                )
                for site in sites:
                    logger.info(f"[DRY RUN] Would delete site: {site['SiteId']}")

                # List devices
                devices = self.paginate(
                    self.networkmanager_client,
                    "get_devices",
                    GlobalNetworkId=network["GlobalNetworkId"],
                )
                for device in devices:
                    logger.info(f"[DRY RUN] Would delete device: {device['DeviceId']}")

        except ClientError as e:
            logger.error(f"Error listing CloudWAN resources: {e}")


class TransitGatewayManager(ResourceManager):
    """Handles AWS Transit Gateway cleanup operations"""

    def __init__(self, region: str, dry_run: bool = False):
        super().__init__(region, dry_run)
        # Additional client for Connect attachments
        self.networkmanager_client = boto3.client("networkmanager", region_name=region)

    def cleanup_transit_gateways(self) -> None:
        """Clean up all Transit Gateways in the region"""
        transit_gateways = self._list_transit_gateways()

        for tgw in transit_gateways:
            tgw_id = tgw["TransitGatewayId"]
            if self.dry_run:
                logger.info(f"[DRY RUN] Would process Transit Gateway: {tgw_id}")
                self._list_tgw_dependencies(tgw_id)
                continue

            logger.info(f"Processing Transit Gateway: {tgw_id}")
            self._cleanup_vpc_attachments(tgw_id)
            self._cleanup_vpn_attachments(tgw_id)
            self._cleanup_connect_peer_attachments(tgw_id)
            self._cleanup_peering_attachments(tgw_id)
            self._delete_transit_gateway(tgw_id)

    def _list_transit_gateways(self) -> List[Dict]:
        """List all Transit Gateways in the region"""
        try:
            return self.paginate(self.ec2_client, "describe_transit_gateways")
        except ClientError as e:
            logger.error(f"Error listing Transit Gateways: {e}")
            return []

    def _list_tgw_dependencies(self, tgw_id: str) -> None:
        """List all dependencies of a Transit Gateway"""
        try:
            # List VPC attachments
            vpc_attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_vpc_attachments",
                Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}],
            )
            for attachment in vpc_attachments:
                logger.info(
                    f"[DRY RUN] Would remove VPC attachment: {attachment['TransitGatewayAttachmentId']}"
                )
                logger.info(f"[DRY RUN] - VPC ID: {attachment.get('VpcId', 'Unknown')}")
                logger.info(f"[DRY RUN] - State: {attachment.get('State', 'Unknown')}")

            # List VPN attachments
            vpn_attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_attachments",
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {"Name": "resource-type", "Values": ["vpn"]},
                ],
            )
            for attachment in vpn_attachments:
                logger.info(
                    f"[DRY RUN] Would remove VPN attachment: {attachment['TransitGatewayAttachmentId']}"
                )
                logger.info(
                    f"[DRY RUN] - Resource ID: {attachment.get('ResourceId', 'Unknown')}"
                )

            # List Connect peer attachments
            connect_attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_attachments",
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {"Name": "resource-type", "Values": ["connect"]},
                ],
            )
            for attachment in connect_attachments:
                logger.info(
                    f"[DRY RUN] Would remove Connect peer attachment: {attachment['TransitGatewayAttachmentId']}"
                )

            # List peering attachments
            peering_attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_peering_attachments",
                Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}],
            )
            for attachment in peering_attachments:
                logger.info(
                    f"[DRY RUN] Would remove peering attachment: {attachment['TransitGatewayAttachmentId']}"
                )

        except ClientError as e:
            logger.error(
                f"Error listing dependencies for Transit Gateway {tgw_id}: {e}"
            )

    def _cleanup_vpc_attachments(self, tgw_id: str) -> None:
        """Remove all VPC attachments from a Transit Gateway"""
        try:
            attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_vpc_attachments",
                Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}],
            )

            for attachment in attachments:
                attachment_id = attachment["TransitGatewayAttachmentId"]
                if attachment["State"] not in ["deleting", "deleted"]:
                    if self.dry_run:
                        logger.info(
                            f"[DRY RUN] Would delete VPC attachment: {attachment_id}"
                        )
                        continue

                    try:
                        self.ec2_client.delete_transit_gateway_vpc_attachment(
                            TransitGatewayAttachmentId=attachment_id
                        )
                        self._wait_for_attachment_deletion(attachment_id)
                    except ClientError as e:
                        logger.error(
                            f"Error deleting VPC attachment {attachment_id}: {e}"
                        )

        except ClientError as e:
            logger.error(
                f"Error cleaning up VPC attachments for Transit Gateway {tgw_id}: {e}"
            )

    def _cleanup_vpn_attachments(self, tgw_id: str) -> None:
        """Remove all VPN attachments from a Transit Gateway"""
        try:
            attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_attachments",
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {"Name": "resource-type", "Values": ["vpn"]},
                ],
            )

            for attachment in attachments:
                vpn_connection_id = attachment["ResourceId"]
                if attachment["State"] not in ["deleting", "deleted"]:
                    if self.dry_run:
                        logger.info(
                            f"[DRY RUN] Would delete VPN connection: {vpn_connection_id}"
                        )
                        continue

                    try:
                        self.ec2_client.delete_vpn_connection(
                            VpnConnectionId=vpn_connection_id
                        )
                        self._wait_for_vpn_deletion(vpn_connection_id)
                    except ClientError as e:
                        logger.error(
                            f"Error deleting VPN connection {vpn_connection_id}: {e}"
                        )

        except ClientError as e:
            logger.error(
                f"Error cleaning up VPN attachments for Transit Gateway {tgw_id}: {e}"
            )

    def _cleanup_connect_peer_attachments(self, tgw_id: str) -> None:
        """Remove all Connect peer attachments from a Transit Gateway"""
        try:
            attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_attachments",
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {"Name": "resource-type", "Values": ["connect"]},
                ],
            )

            for attachment in attachments:
                attachment_id = attachment["TransitGatewayAttachmentId"]
                if attachment["State"] not in ["deleting", "deleted"]:
                    if self.dry_run:
                        logger.info(
                            f"[DRY RUN] Would delete Connect peer attachment: {attachment_id}"
                        )
                        continue

                    try:
                        self.ec2_client.delete_transit_gateway_connect(
                            TransitGatewayAttachmentId=attachment_id
                        )
                        self._wait_for_attachment_deletion(attachment_id)
                    except ClientError as e:
                        logger.error(
                            f"Error deleting Connect peer attachment {attachment_id}: {e}"
                        )

        except ClientError as e:
            logger.error(
                f"Error cleaning up Connect peer attachments for Transit Gateway {tgw_id}: {e}"
            )

    def _cleanup_peering_attachments(self, tgw_id: str) -> None:
        """Remove all peering attachments from a Transit Gateway"""
        try:
            attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_peering_attachments",
                Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}],
            )

            for attachment in attachments:
                attachment_id = attachment["TransitGatewayAttachmentId"]
                if attachment["State"] not in ["deleting", "deleted"]:
                    if self.dry_run:
                        logger.info(
                            f"[DRY RUN] Would delete peering attachment: {attachment_id}"
                        )
                        continue

                    try:
                        self.ec2_client.delete_transit_gateway_peering_attachment(
                            TransitGatewayAttachmentId=attachment_id
                        )
                        self._wait_for_attachment_deletion(attachment_id)
                    except ClientError as e:
                        logger.error(
                            f"Error deleting peering attachment {attachment_id}: {e}"
                        )

        except ClientError as e:
            logger.error(
                f"Error cleaning up peering attachments for Transit Gateway {tgw_id}: {e}"
            )

    def _delete_transit_gateway(self, tgw_id: str) -> None:
        """Delete the Transit Gateway itself"""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete Transit Gateway: {tgw_id}")
            return

        try:
            logger.info(f"Deleting Transit Gateway: {tgw_id}")
            self.ec2_client.delete_transit_gateway(TransitGatewayId=tgw_id)
            self._wait_for_tgw_deletion(tgw_id)
        except ClientError as e:
            logger.error(f"Error deleting Transit Gateway {tgw_id}: {e}")

    def _wait_for_attachment_deletion(
        self, attachment_id: str, timeout: int = 600
    ) -> None:
        """Wait for a Transit Gateway attachment to be fully deleted"""
        if self.dry_run:
            return

        def is_deleted():
            try:
                response = self.ec2_client.describe_transit_gateway_attachments(
                    TransitGatewayAttachmentIds=[attachment_id]
                )
                if not response["TransitGatewayAttachments"]:
                    return True
                state = response["TransitGatewayAttachments"][0]["State"]
                logger.info(f"Attachment {attachment_id} state: {state}")
                return state == "deleted"
            except ClientError as e:
                if "InvalidTransitGatewayAttachmentID.NotFound" in str(e):
                    return True
                raise e

        if self.wait_for_deletion(is_deleted, timeout=timeout):
            logger.info(f"Attachment {attachment_id} successfully deleted")
        else:
            logger.error(
                f"Timeout waiting for attachment {attachment_id} to be deleted"
            )

    def _wait_for_vpn_deletion(
        self, vpn_connection_id: str, timeout: int = 600
    ) -> None:
        """Wait for a VPN connection to be fully deleted"""
        if self.dry_run:
            return

        def is_deleted():
            try:
                response = self.ec2_client.describe_vpn_connections(
                    VpnConnectionIds=[vpn_connection_id]
                )
                if not response["VpnConnections"]:
                    return True
                state = response["VpnConnections"][0]["State"]
                logger.info(f"VPN connection {vpn_connection_id} state: {state}")
                return state == "deleted"
            except ClientError as e:
                if "InvalidVpnConnectionID.NotFound" in str(e):
                    return True
                raise e

        if self.wait_for_deletion(is_deleted, timeout=timeout):
            logger.info(f"VPN connection {vpn_connection_id} successfully deleted")
        else:
            logger.error(
                f"Timeout waiting for VPN connection {vpn_connection_id} to be deleted"
            )

    def _wait_for_tgw_deletion(self, tgw_id: str, timeout: int = 600) -> None:
        """Wait for a Transit Gateway to be fully deleted"""
        if self.dry_run:
            return

        def is_deleted():
            try:
                response = self.ec2_client.describe_transit_gateways(
                    TransitGatewayIds=[tgw_id]
                )
                if not response["TransitGateways"]:
                    return True
                state = response["TransitGateways"][0]["State"]
                logger.info(f"Transit Gateway {tgw_id} state: {state}")
                return state == "deleted"
            except ClientError as e:
                if "InvalidTransitGatewayID.NotFound" in str(e):
                    return True
                raise e

        if self.wait_for_deletion(is_deleted, timeout=timeout):
            logger.info(f"Transit Gateway {tgw_id} successfully deleted")
        else:
            logger.error(f"Timeout waiting for Transit Gateway {tgw_id} to be deleted")


class DirectConnectGatewayManager(ResourceManager):
    """Handles AWS Direct Connect Gateway cleanup operations"""

    def __init__(self, region: str, dry_run: bool = False):
        super().__init__(region, dry_run)
        self.dx_client = boto3.client("directconnect", region_name=region)

    def cleanup_direct_connect_gateways(self) -> None:
        """Clean up all Direct Connect Gateways in the account"""
        dx_gateways = self._list_direct_connect_gateways()

        for gateway in dx_gateways:
            gateway_id = gateway["directConnectGatewayId"]

            if self.dry_run:
                logger.info(
                    f"[DRY RUN] Would process Direct Connect Gateway: {gateway_id}"
                )
                self._list_gateway_dependencies(gateway_id)
                continue

            logger.info(f"Processing Direct Connect Gateway: {gateway_id}")
            self._cleanup_transit_gateway_associations(gateway_id)
            self._cleanup_virtual_interfaces(gateway_id)
            self._delete_direct_connect_gateway(gateway_id)

    def _list_direct_connect_gateways(self) -> List[Dict]:
        """List all Direct Connect Gateways in the account"""
        try:
            return self.paginate(self.dx_client, "describe_direct_connect_gateways")
        except ClientError as e:
            logger.error(f"Error listing Direct Connect Gateways: {e}")
            return []

    def _list_gateway_dependencies(self, gateway_id: str) -> None:
        """List all dependencies of a Direct Connect Gateway"""
        try:
            # List TGW associations
            associations_response = (
                self.dx_client.describe_direct_connect_gateway_associations(
                    directConnectGatewayId=gateway_id
                )
            )
            associations = associations_response.get(
                "directConnectGatewayAssociations", []
            )

            for assoc in associations:
                logger.info(
                    f"[DRY RUN] Would remove TGW association: {assoc.get('associationId')}"
                )
                logger.info(
                    f"[DRY RUN] - Association State: {assoc.get('associationState', 'Unknown')}"
                )
                if "associatedGateway" in assoc:
                    logger.info(
                        f"[DRY RUN] - Associated Gateway: {assoc['associatedGateway'].get('id', 'Unknown')}"
                    )

            # List virtual interfaces
            attachments_response = (
                self.dx_client.describe_direct_connect_gateway_attachments(
                    directConnectGatewayId=gateway_id
                )
            )
            attachments = attachments_response.get(
                "directConnectGatewayAttachments", []
            )

            for attachment in attachments:
                logger.info(
                    f"[DRY RUN] Would remove virtual interface attachment: {attachment.get('virtualInterfaceId', 'Unknown')}"
                )
                logger.info(
                    f"[DRY RUN] - Attachment State: {attachment.get('attachmentState', 'Unknown')}"
                )

        except ClientError as e:
            logger.error(f"Error listing dependencies for gateway {gateway_id}: {e}")

    def _cleanup_transit_gateway_associations(self, gateway_id: str) -> None:
        """Remove all Transit Gateway associations"""
        try:
            associations_response = (
                self.dx_client.describe_direct_connect_gateway_associations(
                    directConnectGatewayId=gateway_id
                )
            )
            associations = associations_response.get(
                "directConnectGatewayAssociations", []
            )

            for association in associations:
                association_id = association.get("associationId")
                if not association_id:
                    continue

                if association.get("associationState") not in [
                    "disassociated",
                    "disassociating",
                ]:
                    if self.dry_run:
                        logger.info(
                            f"[DRY RUN] Would disassociate TGW association: {association_id}"
                        )
                        continue

                    try:
                        self.dx_client.delete_direct_connect_gateway_association(
                            associationId=association_id
                        )
                        logger.info(
                            f"Initiated disassociation of TGW association {association_id}"
                        )
                        self._wait_for_association_deletion(association_id)
                    except ClientError as e:
                        logger.error(
                            f"Error disassociating TGW association {association_id}: {e}"
                        )

        except ClientError as e:
            logger.error(
                f"Error cleaning up TGW associations for gateway {gateway_id}: {e}"
            )

    def _cleanup_virtual_interfaces(self, gateway_id: str) -> None:
        """Remove all virtual interface attachments"""
        try:
            attachments_response = (
                self.dx_client.describe_direct_connect_gateway_attachments(
                    directConnectGatewayId=gateway_id
                )
            )
            attachments = attachments_response.get(
                "directConnectGatewayAttachments", []
            )

            for attachment in attachments:
                vif_id = attachment.get("virtualInterfaceId")
                if not vif_id:
                    continue

                if attachment.get("attachmentState") not in ["detaching", "detached"]:
                    if self.dry_run:
                        logger.info(
                            f"[DRY RUN] Would delete virtual interface: {vif_id}"
                        )
                        continue

                    try:
                        self.dx_client.delete_virtual_interface(
                            virtualInterfaceId=vif_id
                        )
                        logger.info(f"Initiated deletion of virtual interface {vif_id}")
                        self._wait_for_vif_deletion(vif_id)
                    except ClientError as e:
                        logger.error(f"Error deleting virtual interface {vif_id}: {e}")

        except ClientError as e:
            logger.error(
                f"Error cleaning up virtual interfaces for gateway {gateway_id}: {e}"
            )

    def _delete_direct_connect_gateway(self, gateway_id: str) -> None:
        """Delete the Direct Connect Gateway itself"""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete Direct Connect Gateway: {gateway_id}")
            return

        try:
            logger.info(f"Deleting Direct Connect Gateway: {gateway_id}")
            self.dx_client.delete_direct_connect_gateway(
                directConnectGatewayId=gateway_id
            )
            self._wait_for_gateway_deletion(gateway_id)
        except ClientError as e:
            logger.error(f"Error deleting Direct Connect Gateway {gateway_id}: {e}")

    def _wait_for_association_deletion(
        self, association_id: str, timeout: int = 600
    ) -> None:
        """Wait for a TGW association to be fully disassociated"""
        if self.dry_run:
            return

        def is_disassociated():
            try:
                response = self.dx_client.describe_direct_connect_gateway_associations(
                    associationId=association_id
                )
                associations = response.get("directConnectGatewayAssociations", [])

                if not associations:
                    logger.info(f"Association {association_id} no longer exists")
                    return True

                state = associations[0].get("associationState", "unknown")
                logger.info(f"Association {association_id} state: {state}")
                return state == "disassociated"

            except ClientError as e:
                if "NotFoundException" in str(e):
                    return True
                raise e

        if self.wait_for_deletion(is_disassociated, timeout=timeout):
            logger.info(f"TGW Association {association_id} successfully disassociated")
        else:
            logger.error(
                f"Timeout waiting for TGW association {association_id} to be disassociated"
            )

    def _wait_for_vif_deletion(self, vif_id: str, timeout: int = 600) -> None:
        """Wait for a virtual interface to be fully deleted"""
        if self.dry_run:
            return

        def is_deleted():
            try:
                response = self.dx_client.describe_virtual_interfaces(
                    virtualInterfaceId=vif_id
                )
                interfaces = response.get("virtualInterfaces", [])

                if not interfaces:
                    return True

                state = interfaces[0].get("virtualInterfaceState", "unknown")
                logger.info(f"Virtual interface {vif_id} state: {state}")
                return state == "deleted"

            except ClientError as e:
                if "NotFoundException" in str(e):
                    return True
                raise e

        if self.wait_for_deletion(is_deleted, timeout=timeout):
            logger.info(f"Virtual interface {vif_id} successfully deleted")
        else:
            logger.error(
                f"Timeout waiting for virtual interface {vif_id} to be deleted"
            )

    def _wait_for_gateway_deletion(self, gateway_id: str, timeout: int = 600) -> None:
        """Wait for a Direct Connect Gateway to be fully deleted"""
        if self.dry_run:
            return

        def is_deleted():
            try:
                response = self.dx_client.describe_direct_connect_gateways(
                    directConnectGatewayId=gateway_id
                )
                gateways = response.get("directConnectGateways", [])

                if not gateways:
                    return True

                state = gateways[0].get("directConnectGatewayState", "unknown")
                logger.info(f"Direct Connect Gateway {gateway_id} state: {state}")
                return state == "deleted"

            except ClientError as e:
                if "NotFoundException" in str(e):
                    return True
                raise e

        if self.wait_for_deletion(is_deleted, timeout=timeout):
            logger.info(f"Direct Connect Gateway {gateway_id} successfully deleted")
        else:
            logger.error(
                f"Timeout waiting for Direct Connect Gateway {gateway_id} to be deleted"
            )


class ResourceLister(ResourceManager):
    """Handles listing of AWS resources"""

    def list_all_resources(self) -> Dict[str, List[str]]:
        """List all resources in the region"""
        resources = {
            "VPCs": self._list_vpcs(),
            "EC2 Instances": self._list_instances(),
            "Subnets": self._list_subnets(),
            "Security Groups": self._list_security_groups(),
            "NAT Gateways": self._list_nat_gateways(),
            "Internet Gateways": self._list_internet_gateways(),
            "VPC Endpoints": self._list_vpc_endpoints(),
            "Network Firewalls": self._list_network_firewalls(),
            "Instance Connect Endpoints": self._list_instance_connect_endpoints(),
            "Transit Gateways": self._list_transit_gateways(),
            "Direct Connect Gateways": self._list_direct_connect_gateways(),
        }
        return resources

    def _list_vpcs(self) -> List[str]:
        vpcs = self.paginate(self.ec2_client, "describe_vpcs")
        return [vpc["VpcId"] for vpc in vpcs] or ["-"]

    def _list_instances(self) -> List[str]:
        instances = self.paginate(self.ec2_client, "describe_instances")
        return [
            f"{instance['InstanceId']} (State: {instance['State']['Name']})"
            for reservation in instances
            for instance in reservation["Instances"]
        ] or ["-"]

    # Additional listing methods for other resource types...


"""
class NewResourceManager(ResourceManager):
    #
    # Template structure for a new AWS resource manager
    # Always include a clear class docstring explaining the purpose
    #
    def __init__(self, region: str, dry_run: bool = False):
        # Always call parent class init first
        super().__init__(region, dry_run)
        # Add any additional AWS clients needed
        self.specific_client = boto3.client('service-name', region_name=region)

    # Example methods for a new resource manager:

    def _list_resources(self):      # List resources to process
    def _list_dependencies(self):   # Show what would be deleted
    def _cleanup_x(self):          # Delete specific resource type
    def _wait_for_x(self):         # Wait for operation completion

    # Error handling:

    try:
        # AWS operation
    except ClientError as e:
        logger.error(f"Specific error message: {e}")
        # Appropriate error handling

    # Dry run support:

    if self.dry_run:
        logger.info(f"[DRY RUN] Would perform action: {resource_id}")
        return

    # Logging:

    logger.info(f"Starting operation on: {resource_id}")
    logger.error(f"Error in operation: {e}")
    logger.info(f"Successfully completed: {resource_id}")

    # Clear docstring explaining:
    # - What the class/method does
    # - Parameters
    # - Return values
    # - Important notes

    def cleanup_resources(self) -> None:
        \"\"\"Main public method that orchestrates the cleanup\"\"\"
        # 1. List resources
        resources = self._list_resources()

        # 2. Process each resource
        for resource in resources:
            resource_id = resource['ResourceId']

            # Handle dry run first
            if self.dry_run:
                logger.info(f"[DRY RUN] Would process resource: {resource_id}")
                self._list_dependencies(resource_id)
                continue

            # 3. Follow dependency order
            self._cleanup_dependencies(resource_id)
            self._cleanup_main_resource(resource_id)

    # Private methods follow a common pattern:
    def _list_resources(self) -> List[Dict]:
        \"\"\"List all resources to be managed\"\"\"
        try:
            return self.paginate(
                self.specific_client,
                'describe_resources'
            )
        except ClientError as e:
            logger.error(f"Error listing resources: {e}")
            return []

    def _list_dependencies(self, resource_id: str) -> None:
        \"\"\"List dependencies for dry-run or analysis\"\"\"
        try:
            # List dependencies
            # Log what would be deleted
        except ClientError as e:
            logger.error(f"Error listing dependencies: {e}")

    def _cleanup_dependencies(self, resource_id: str) -> None:
        \"\"\"Clean up dependent resources first\"\"\"
        try:
            # Delete dependencies
            # Wait for completion
        except ClientError as e:
            logger.error(f"Error cleaning dependencies: {e}")

    def _wait_for_deletion(self, resource_id: str, timeout: int = 600) -> None:
        \"\"\"Wait for resource deletion\"\"\"
        if self.dry_run:
            return

        def is_deleted():
            try:
                # Check resource state
                # Return True if deleted
                return state == 'deleted'
            except ClientError as e:
                if 'NotFoundException' in str(e):
                    return True
                raise e

        if self.wait_for_deletion(is_deleted, timeout=timeout):
            logger.info(f"Resource {resource_id} deleted successfully")
        else:
            logger.error(f"Timeout waiting for deletion")
"""


def main():
    """Main execution flow"""
    parser = argparse.ArgumentParser(description="AWS Resource Cleanup Script")
    parser.add_argument(
        "--region", default="eu-west-1", help="AWS region (default: eu-west-1)"
    )
    parser.add_argument(
        "-l", "--list", action="store_true", help="List resources without deletion"
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="Perform a dry run without actually deleting resources",
    )
    args = parser.parse_args()

    try:
        if args.list:
            lister = ResourceLister(args.region)
            resources = lister.list_all_resources()
            for resource_type, resource_list in resources.items():
                print(f"\n{resource_type}:")
                for resource in resource_list:
                    print(f"  - {resource}")
        else:
            if args.dry_run:
                logger.info("=== DRY RUN MODE - No resources will be deleted ===")

            # Initialize all cleaners
            vpc_cleaner = VPCCleaner(args.region, args.dry_run)
            nfw_cleaner = NetworkFirewallCleaner(args.region, args.dry_run)
            cloudwan_cleaner = CloudWANCleaner(args.region, args.dry_run)
            dx_gateway_cleaner = DirectConnectGatewayManager(args.region, args.dry_run)
            tgw_cleaner = TransitGatewayManager(args.region, args.dry_run)

            # Cleanup sequence based on dependencies:

            # 1. First clean up Direct Connect Gateway associations
            # (This removes DX Gateway associations with Transit Gateways)
            dx_gateway_cleaner.cleanup_direct_connect_gateways()

            # 2. Clean up Transit Gateways and their attachments
            # (Now that DX Gateway associations are removed)
            tgw_cleaner.cleanup_transit_gateways()

            # 3. Clean up Network Firewalls
            # (Remove before VPC cleanup as they have GWLB dependencies)
            nfw_cleaner.cleanup_firewalls()

            # 4. Clean up CloudWAN resources
            # (After TGW cleanup as there might be dependencies)
            cloudwan_cleaner.cleanup_cloudwan()

            # 5. Clean up regular VPCs
            vpcs = vpc_cleaner.paginate(
                vpc_cleaner.ec2_client,
                "describe_vpcs",
                Filters=[{"Name": "isDefault", "Values": ["false"]}],
            )
            for vpc in vpcs:
                vpc_cleaner.cleanup_vpc(vpc["VpcId"])

            # 6. Finally clean up GWLB-only VPCs
            # (After Network Firewalls are removed)
            for vpc_id in vpc_cleaner.gwlb_only_vpcs:
                vpc_cleaner.cleanup_vpc(vpc_id)

            logger.info("Resource cleanup completed successfully")

    except Exception as e:
        logger.error(f"Error during resource cleanup: {e}")
        raise


if __name__ == "__main__":
    main()
