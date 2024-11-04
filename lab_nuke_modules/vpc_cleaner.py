import logging
import time
from botocore.exceptions import ClientError, WaiterError

from lab_nuke_modules.resource_manager import ResourceManager
from lab_nuke_modules.security_group_manager import SecurityGroupManager

logger = logging.getLogger(__name__)

class VPCCleaner(ResourceManager):
    def __init__(self, region: str, dry_run: bool = False):
        super().__init__(region, dry_run)
        self.sg_manager = SecurityGroupManager(self.ec2_client, dry_run)
        self.gwlb_only_vpcs = set()  # Initialize gwlb_only_vpcs as an empty set

    def cleanup_vpc(self, vpc_id: str) -> None:
        if self._is_default_vpc(vpc_id):
            self.logger.info(f"Skipping default VPC: {vpc_id}")
            return

        cleanup_sequence = [
            self._cleanup_instances,
            self._cleanup_network_load_balancers,
            self._cleanup_endpoints,
            self._cleanup_nat_gateways,
            self._cleanup_network_interfaces,
            self._cleanup_security_groups,
            self._cleanup_route_tables,
            self._cleanup_subnets,
            self._cleanup_internet_gateways,
        ]

        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would clean up VPC {vpc_id} with the following sequence:")
            for cleanup_step in cleanup_sequence:
                self.logger.info(f"[DRY RUN] - {cleanup_step.__name__}")
            return

        for cleanup_step in cleanup_sequence:
            try:
                cleanup_step(vpc_id)
            except Exception as e:
                self.logger.error(f"Error in {cleanup_step.__name__} for VPC {vpc_id}: {e}")
                if self._has_gwlb_resources(vpc_id):
                    self.gwlb_only_vpcs.add(vpc_id)
                    self.logger.info(f"Added VPC {vpc_id} to GWLB-only list for later deletion")
                return

        self._delete_vpc(vpc_id)

    def _cleanup_network_load_balancers(self, vpc_id: str) -> None:
        try:
            paginator = self.elb.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page['LoadBalancers']:
                    if lb['VpcId'] == vpc_id:
                        lb_arn = lb['LoadBalancerArn']
                        if self.dry_run:
                            self.logger.info(f"[DRY RUN] Would delete Load Balancer: {lb['LoadBalancerName']}")
                        else:
                            self.elb.delete_load_balancer(LoadBalancerArn=lb_arn)
                            self.logger.info(f"Deleted Load Balancer: {lb['LoadBalancerName']}")
                            waiter = self.elb.get_waiter('load_balancers_deleted')
                            waiter.wait(LoadBalancerArns=[lb_arn])
        except ClientError as e:
            self.logger.error(f"Error cleaning up Network Load Balancers in VPC {vpc_id}: {e}")

    def _cleanup_network_interfaces(self, vpc_id: str) -> None:
        try:
            enis = self.ec2_client.describe_network_interfaces(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['NetworkInterfaces']
            for eni in enis:
                eni_id = eni['NetworkInterfaceId']
                if self.dry_run:
                    self.logger.info(f"[DRY RUN] Would delete Network Interface: {eni_id}")
                else:
                    self._retry_delete(
                        lambda: self.ec2_client.delete_network_interface(NetworkInterfaceId=eni_id),
                        f"Deleted Network Interface: {eni_id}",
                        f"Failed to delete Network Interface {eni_id}"
                    )
        except ClientError as e:
            self.logger.error(f"Error cleaning up Network Interfaces in VPC {vpc_id}: {e}")

    def _is_default_vpc(self, vpc_id: str) -> bool:
        vpc = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        return vpc.get("IsDefault", False)

    def _has_gwlb_resources(self, vpc_id: str) -> bool:
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
        instances = self.paginate(
            self.ec2_client,
            "describe_instances",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        instance_ids = [
            instance["InstanceId"]
            for reservation in instances
            for instance in reservation["Instances"]
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

    def _cleanup_security_groups(self, vpc_id: str) -> None:
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
        route_tables = self.paginate(
            self.ec2_client,
            "describe_route_tables",
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
        )

        for rt in route_tables:
            if any(assoc.get("Main", False) for assoc in rt.get("Associations", [])):
                continue

            if self.dry_run:
                logger.info(f"[DRY RUN] Would delete route table: {rt['RouteTableId']}")
                continue

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

            try:
                self.ec2_client.delete_route_table(RouteTableId=rt["RouteTableId"])
                logger.info(f"Deleted route table: {rt['RouteTableId']}")
            except ClientError as e:
                logger.error(f"Failed to delete route table {rt['RouteTableId']}: {e}")

    def _cleanup_subnets(self, vpc_id: str) -> None:
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
        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete VPC: {vpc_id}")
            return

        try:
            self.ec2_client.delete_vpc(VpcId=vpc_id)
            logger.info(f"Deleted VPC: {vpc_id}")
        except ClientError as e:
            logger.error(f"Failed to delete VPC {vpc_id}: {e}")
