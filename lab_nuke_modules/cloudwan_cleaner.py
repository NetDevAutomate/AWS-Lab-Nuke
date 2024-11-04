import logging
from botocore.exceptions import ClientError

from lab_nuke_modules.resource_manager import ResourceManager

logger = logging.getLogger(__name__)

class CloudWANCleaner(ResourceManager):
    def cleanup_cloudwan(self) -> None:
        if self.dry_run:
            logger.info("[DRY RUN] Would clean up CloudWAN resources")
            self._list_resources_to_delete()
            return

        self._cleanup_global_networks()
        self._cleanup_core_networks()

    def _cleanup_global_networks(self) -> None:
        try:
            global_networks = self.paginate(self.networkmanager_client, "describe_global_networks")
            for network in global_networks:
                global_network_id = network["GlobalNetworkId"]
                if self.dry_run:
                    logger.info(f"[DRY RUN] Would clean up Global Network {global_network_id}")
                    continue
                self._cleanup_global_network(global_network_id)
        except ClientError as e:
            logger.error(f"Error cleaning up Global Networks: {e}")

    def _cleanup_global_network(self, global_network_id: str) -> None:
        try:
            tgws = self.networkmanager_client.get_transit_gateway_registrations(GlobalNetworkId=global_network_id)
            for tgw in tgws.get('TransitGatewayRegistrations', []):
                if self.dry_run:
                    logger.info(f"[DRY RUN] Would deregister Transit Gateway: {tgw['TransitGatewayArn']}")
                else:
                    self.networkmanager_client.deregister_transit_gateway(
                        GlobalNetworkId=global_network_id,
                        TransitGatewayArn=tgw['TransitGatewayArn']
                    )
                    logger.info(f"Deregistered Transit Gateway: {tgw['TransitGatewayArn']}")

            core_networks = self.networkmanager_client.list_core_networks(GlobalNetworkId=global_network_id)
            for cn in core_networks.get('CoreNetworks', []):
                self._delete_core_network(cn['CoreNetworkId'])

            if not self.dry_run:
                self.networkmanager_client.delete_global_network(GlobalNetworkId=global_network_id)
                logger.info(f"Deleted Global Network: {global_network_id}")
            else:
                logger.info(f"[DRY RUN] Would delete Global Network: {global_network_id}")
        except ClientError as e:
            logger.error(f"Error cleaning up Global Network {global_network_id}: {e}")

    def _cleanup_core_networks(self) -> None:
        try:
            core_networks = self.paginate(self.networkmanager_client, "list_core_networks")
            for network in core_networks:
                core_network_id = network["CoreNetworkId"]
                if self.dry_run:
                    logger.info(f"[DRY RUN] Would delete Core Network {core_network_id}")
                    continue
                self._delete_core_network(core_network_id)
        except ClientError as e:
            logger.error(f"Error cleaning up Core Networks: {e}")

    def _delete_core_network(self, core_network_id: str) -> None:
        try:
            peerings = self.networkmanager_client.list_peerings(CoreNetworkId=core_network_id)["Peerings"]
            for peering in peerings:
                if self.dry_run:
                    logger.info(f"[DRY RUN] Would delete peering: {peering['PeeringId']}")
                    continue
                self.networkmanager_client.delete_peering(PeeringId=peering["PeeringId"])
                logger.info(f"Deleted peering {peering['PeeringId']}")

            if not self.dry_run:
                self.networkmanager_client.delete_core_network(CoreNetworkId=core_network_id)
                logger.info(f"Deleted Core Network {core_network_id}")
        except ClientError as e:
            logger.error(f"Error deleting Core Network {core_network_id}: {e}")

    def _list_resources_to_delete(self) -> None:
        try:
            core_networks = self.paginate(self.networkmanager_client, "list_core_networks")
            for network in core_networks:
                logger.info(f"[DRY RUN] Would delete Core Network: {network['CoreNetworkId']}")
                peerings = self.networkmanager_client.list_peerings(CoreNetworkId=network["CoreNetworkId"])["Peerings"]
                for peering in peerings:
                    logger.info(f"[DRY RUN] Would delete peering: {peering['PeeringId']}")

            global_networks = self.networkmanager_client.describe_global_networks()["GlobalNetworks"]
            for network in global_networks:
                logger.info(f"[DRY RUN] Would delete Global Network: {network['GlobalNetworkId']}")
                sites = self.paginate(self.networkmanager_client, "get_sites", GlobalNetworkId=network["GlobalNetworkId"])
                for site in sites:
                    logger.info(f"[DRY RUN] Would delete site: {site['SiteId']}")
                devices = self.paginate(self.networkmanager_client, "get_devices", GlobalNetworkId=network["GlobalNetworkId"])
                for device in devices:
                    logger.info(f"[DRY RUN] Would delete device: {device['DeviceId']}")
        except ClientError as e:
            logger.error(f"Error listing CloudWAN resources: {e}")
