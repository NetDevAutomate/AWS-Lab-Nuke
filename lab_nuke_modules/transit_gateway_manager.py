import logging
import boto3
from typing import List, Dict
from botocore.exceptions import ClientError

from lab_nuke_modules.resource_manager import ResourceManager

logger = logging.getLogger(__name__)

class TransitGatewayManager(ResourceManager):
    def __init__(self, region: str, dry_run: bool = False):
        super().__init__(region, dry_run)
        self.networkmanager_client = boto3.client("networkmanager", region_name=region)

    def cleanup_transit_gateways(self) -> None:
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
        try:
            return self.paginate(self.ec2_client, "describe_transit_gateways")
        except ClientError as e:
            logger.error(f"Error listing Transit Gateways: {e}")
            return []

    def _list_tgw_dependencies(self, tgw_id: str) -> None:
        try:
            vpc_attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_vpc_attachments",
                Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}],
            )
            for attachment in vpc_attachments:
                logger.info(f"[DRY RUN] Would remove VPC attachment: {attachment['TransitGatewayAttachmentId']}")
                logger.info(f"[DRY RUN] - VPC ID: {attachment.get('VpcId', 'Unknown')}")
                logger.info(f"[DRY RUN] - State: {attachment.get('State', 'Unknown')}")

            vpn_attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_attachments",
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {"Name": "resource-type", "Values": ["vpn"]},
                ],
            )
            for attachment in vpn_attachments:
                logger.info(f"[DRY RUN] Would remove VPN attachment: {attachment['TransitGatewayAttachmentId']}")
                logger.info(f"[DRY RUN] - Resource ID: {attachment.get('ResourceId', 'Unknown')}")

            connect_attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_attachments",
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {"Name": "resource-type", "Values": ["connect"]},
                ],
            )
            for attachment in connect_attachments:
                logger.info(f"[DRY RUN] Would remove Connect peer attachment: {attachment['TransitGatewayAttachmentId']}")

            peering_attachments = self.paginate(
                self.ec2_client,
                "describe_transit_gateway_peering_attachments",
                Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}],
            )
            for attachment in peering_attachments:
                logger.info(f"[DRY RUN] Would remove peering attachment: {attachment['TransitGatewayAttachmentId']}")

        except ClientError as e:
            logger.error(f"Error listing dependencies for Transit Gateway {tgw_id}: {e}")

    def _cleanup_vpc_attachments(self, tgw_id: str) -> None:
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
                        logger.info(f"[DRY RUN] Would delete VPC attachment: {attachment_id}")
                        continue

                    try:
                        self.ec2_client.delete_transit_gateway_vpc_attachment(
                            TransitGatewayAttachmentId=attachment_id
                        )
                        self._wait_for_attachment_deletion(attachment_id)
                    except ClientError as e:
                        logger.error(f"Error deleting VPC attachment {attachment_id}: {e}")

        except ClientError as e:
            logger.error(f"Error cleaning up VPC attachments for Transit Gateway {tgw_id}: {e}")

    def _cleanup_vpn_attachments(self, tgw_id: str) -> None:
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
                        logger.info(f"[DRY RUN] Would delete VPN connection: {vpn_connection_id}")
                        continue

                    try:
                        self.ec2_client.delete_vpn_connection(VpnConnectionId=vpn_connection_id)
                        self._wait_for_vpn_deletion(vpn_connection_id)
                    except ClientError as e:
                        logger.error(f"Error deleting VPN connection {vpn_connection_id}: {e}")

        except ClientError as e:
            logger.error(f"Error cleaning up VPN attachments for Transit Gateway {tgw_id}: {e}")

    def _cleanup_connect_peer_attachments(self, tgw_id: str) -> None:
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
                        logger.info(f"[DRY RUN] Would delete Connect peer attachment: {attachment_id}")
                        continue

                    try:
                        self.ec2_client.delete_transit_gateway_connect(
                            TransitGatewayAttachmentId=attachment_id
                        )
                        self._wait_for_attachment_deletion(attachment_id)
                    except ClientError as e:
                        logger.error(f"Error deleting Connect peer attachment {attachment_id}: {e}")

        except ClientError as e:
            logger.error(f"Error cleaning up Connect peer attachments for Transit Gateway {tgw_id}: {e}")

    def _cleanup_peering_attachments(self, tgw_id: str) -> None:
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
                        logger.info(f"[DRY RUN] Would delete peering attachment: {attachment_id}")
                        continue

                    try:
                        self.ec2_client.delete_transit_gateway_peering_attachment(
                            TransitGatewayAttachmentId=attachment_id
                        )
                        self._wait_for_attachment_deletion(attachment_id)
                    except ClientError as e:
                        logger.error(f"Error deleting peering attachment {attachment_id}: {e}")

        except ClientError as e:
            logger.error(f"Error cleaning up peering attachments for Transit Gateway {tgw_id}: {e}")

    def _delete_transit_gateway(self, tgw_id: str) -> None:
        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete Transit Gateway: {tgw_id}")
            return

        try:
            logger.info(f"Deleting Transit Gateway: {tgw_id}")
            self.ec2_client.delete_transit_gateway(TransitGatewayId=tgw_id)
            self._wait_for_tgw_deletion(tgw_id)
        except ClientError as e:
            logger.error(f"Error deleting Transit Gateway {tgw_id}: {e}")

    def _wait_for_attachment_deletion(self, attachment_id: str, timeout: int = 600) -> None:
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
            logger.error(f"Timeout waiting for attachment {attachment_id} to be deleted")

    def _wait_for_vpn_deletion(self, vpn_connection_id: str, timeout: int = 600) -> None:
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
            logger.error(f"Timeout waiting for VPN connection {vpn_connection_id} to be deleted")

    def _wait_for_tgw_deletion(self, tgw_id: str, timeout: int = 600) -> None:
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
