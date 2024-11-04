import logging
from typing import Dict, List
from botocore.exceptions import ClientError

from lab_nuke_modules.resource_manager import ResourceManager

logger = logging.getLogger(__name__)

class ResourceLister(ResourceManager):
    def list_all_resources(self) -> Dict[str, List[str]]:
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
            "EKS Clusters": self._list_eks_clusters(),
            "ECS Clusters": self._list_ecs_clusters(),
            "Auto Scaling Groups": self._list_auto_scaling_groups(),
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

    def _list_eks_clusters(self) -> List[str]:
        try:
            clusters = self.eks_client.list_clusters()['clusters']
            return clusters if clusters else ["-"]
        except ClientError as e:
            logger.error(f"Error listing EKS clusters: {e}")
            return ["-"]

    def _list_ecs_clusters(self) -> List[str]:
        try:
            clusters = self.ecs_client.list_clusters()['clusterArns']
            return clusters if clusters else ["-"]
        except ClientError as e:
            logger.error(f"Error listing ECS clusters: {e}")
            return ["-"]

    def _list_auto_scaling_groups(self) -> List[str]:
        try:
            asgs = self.asg_client.describe_auto_scaling_groups()['AutoScalingGroups']
            return [asg['AutoScalingGroupName'] for asg in asgs] if asgs else ["-"]
        except ClientError as e:
            logger.error(f"Error listing Auto Scaling Groups: {e}")
            return ["-"]
