import argparse
import logging
import time

from lab_nuke_modules.container_resource_manager import ContainerResourceManager
from lab_nuke_modules.vpc_cleaner import VPCCleaner
from lab_nuke_modules.network_firewall_cleaner import NetworkFirewallCleaner
from lab_nuke_modules.cloudwan_cleaner import CloudWANCleaner
from lab_nuke_modules.direct_connect_gateway_manager import DirectConnectGatewayManager
from lab_nuke_modules.transit_gateway_manager import TransitGatewayManager
from lab_nuke_modules.resource_lister import ResourceLister

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="AWS Resource Cleanup Script")
    parser.add_argument("--region", default="eu-west-1", help="AWS region (default: eu-west-1)")
    parser.add_argument("-l", "--list", action="store_true", help="List resources without deletion")
    parser.add_argument("-d", "--dry-run", action="store_true", help="Perform a dry run without actually deleting resources")
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

            container_cleaner = ContainerResourceManager(args.region, args.dry_run)
            vpc_cleaner = VPCCleaner(args.region, args.dry_run)
            nfw_cleaner = NetworkFirewallCleaner(args.region, args.dry_run)
            cloudwan_cleaner = CloudWANCleaner(args.region, args.dry_run)
            dx_gateway_cleaner = DirectConnectGatewayManager(args.region, args.dry_run)
            tgw_cleaner = TransitGatewayManager(args.region, args.dry_run)

            logger.info("Starting container resource cleanup...")
            container_cleaner.cleanup_container_resources()

            logger.info("Verifying Launch Templates cleanup...")
            if not container_cleaner._verify_launch_templates_deleted():
                logger.info("Attempting Launch Templates cleanup again...")
                container_cleaner.cleanup_launch_templates()
                time.sleep(30)

            logger.info("Waiting for container resources to be fully cleaned up...")
            time.sleep(90)

            logger.info("Verifying Launch Templates cleanup...")
            container_cleaner.cleanup_launch_templates()

            logger.info("Starting Direct Connect Gateway cleanup...")
            dx_gateway_cleaner.cleanup_direct_connect_gateways()

            logger.info("Starting Transit Gateway cleanup...")
            tgw_cleaner.cleanup_transit_gateways()

            logger.info("Starting Network Firewall cleanup...")
            nfw_cleaner.cleanup_firewalls()

            logger.info("Starting CloudWAN cleanup...")
            cloudwan_cleaner.cleanup_cloudwan()

            logger.info("Starting VPC cleanup...")
            vpcs = vpc_cleaner.paginate(
                vpc_cleaner.ec2_client,
                "describe_vpcs",
                Filters=[{"Name": "isDefault", "Values": ["false"]}],
            )
            for vpc in vpcs:
                vpc_cleaner.cleanup_vpc(vpc["VpcId"])

            for vpc_id in vpc_cleaner.gwlb_only_vpcs:
                vpc_cleaner.cleanup_vpc(vpc_id)

            logger.info("Resource cleanup completed successfully")

    except Exception as e:
        logger.error(f"Error during resource cleanup: {e}")
        raise

if __name__ == "__main__":
    main()
