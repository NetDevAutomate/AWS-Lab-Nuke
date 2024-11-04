import logging
import time
from typing import List, Dict, Any, Callable, Set

import boto3
from botocore.exceptions import WaiterError, ClientError
from botocore.paginate import Paginator

logger = logging.getLogger(__name__)

class ResourceManager:
    def __init__(self, region: str, dry_run: bool = False):
        self.region = region
        self.dry_run = dry_run
        self.ec2_client = boto3.client("ec2", region_name=region)
        self.nfw_client = boto3.client("network-firewall", region_name=region)
        self.networkmanager_client = boto3.client("networkmanager", region_name=region)
        self.directconnect_client = boto3.client("directconnect", region_name=region)
        self.eks_client = boto3.client("eks", region_name=region)
        self.ecs_client = boto3.client("ecs", region_name=region)
        self.asg_client = boto3.client("autoscaling", region_name=region)
        self.elb = boto3.client("elbv2", region_name=region)
        self.logger = self._setup_logger()

    def _setup_logger(self):
        logger = logging.getLogger(self.__class__.__name__)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def paginate(self, client: Any, operation: str, **kwargs) -> List[Dict]:
        paginator = client.get_paginator(operation)
        items = []
        for page in paginator.paginate(**kwargs):
            items.extend(page.get(self._get_result_key(operation), []))
        return items

    @staticmethod
    def _get_result_key(operation: str) -> str:
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
            "list_clusters": "clusters",
            "list_nodegroups": "nodegroups",
            "describe_cluster": "cluster",
            "describe_nodegroup": "nodegroup",
            "list_services": "serviceArns",
            "list_task_definitions": "taskDefinitionArns",
            "list_tasks": "taskArns",
            "describe_auto_scaling_groups": "AutoScalingGroups",
        }
        return key_mapping.get(operation, "")

    def wait_for_deletion(
        self, check_func: Callable[[], bool], timeout: int = 600, interval: int = 30
    ) -> bool:
        end_time = time.time() + timeout
        while time.time() < end_time:
            if check_func():
                return True
            time.sleep(interval)
        return False
