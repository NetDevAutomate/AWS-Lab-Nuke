import logging
import boto3
from typing import List, Dict
from botocore.exceptions import ClientError

from lab_nuke_modules.resource_manager import ResourceManager

logger = logging.getLogger(__name__)

class DirectConnectGatewayManager(ResourceManager):
    def __init__(self, region: str, dry_run: bool = False):
        super().__init__(region, dry_run)
        self.dx_client = boto3.client("directconnect", region_name=region)

    def cleanup_direct_connect_gateways(self) -> None:
        dx_gateways = self._list_direct_connect_gateways()

        for gateway in dx_gateways:
            gateway_id = gateway["directConnectGatewayId"]

            if self.dry_run:
                logger.info(f"[DRY RUN] Would process Direct Connect Gateway: {gateway_id}")
                self._list_gateway_dependencies(gateway_id)
                continue

            logger.info(f"Processing Direct Connect Gateway: {gateway_id}")
            self._cleanup_transit_gateway_associations(gateway_id)
            self._cleanup_virtual_interfaces(gateway_id)
            self._delete_direct_connect_gateway(gateway_id)

    def _list_direct_connect_gateways(self) -> List[Dict]:
        try:
            return self.paginate(self.dx_client, "describe_direct_connect_gateways")
        except ClientError as e:
            logger.error(f"Error listing Direct Connect Gateways: {e}")
            return []

    def _list_gateway_dependencies(self, gateway_id: str) -> None:
        try:
            associations_response = self.dx_client.describe_direct_connect_gateway_associations(
                directConnectGatewayId=gateway_id
            )
            associations = associations_response.get("directConnectGatewayAssociations", [])

            for assoc in associations:
                logger.info(f"[DRY RUN] Would remove TGW association: {assoc.get('associationId')}")
                logger.info(f"[DRY RUN] - Association State: {assoc.get('associationState', 'Unknown')}")
                if "associatedGateway" in assoc:
                    logger.info(f"[DRY RUN] - Associated Gateway: {assoc['associatedGateway'].get('id', 'Unknown')}")

            attachments_response = self.dx_client.describe_direct_connect_gateway_attachments(
                directConnectGatewayId=gateway_id
            )
            attachments = attachments_response.get("directConnectGatewayAttachments", [])

            for attachment in attachments:
                logger.info(f"[DRY RUN] Would remove virtual interface attachment: {attachment.get('virtualInterfaceId', 'Unknown')}")
                logger.info(f"[DRY RUN] - Attachment State: {attachment.get('attachmentState', 'Unknown')}")

        except ClientError as e:
            logger.error(f"Error listing dependencies for gateway {gateway_id}: {e}")

    def _cleanup_transit_gateway_associations(self, gateway_id: str) -> None:
        try:
            associations_response = self.dx_client.describe_direct_connect_gateway_associations(
                directConnectGatewayId=gateway_id
            )
            associations = associations_response.get("directConnectGatewayAssociations", [])

            for association in associations:
                association_id = association.get("associationId")
                if not association_id:
                    continue

                if association.get("associationState") not in ["disassociated", "disassociating"]:
                    if self.dry_run:
                        logger.info(f"[DRY RUN] Would disassociate TGW association: {association_id}")
                        continue

                    try:
                        self.dx_client.delete_direct_connect_gateway_association(
                            associationId=association_id
                        )
                        logger.info(f"Initiated disassociation of TGW association {association_id}")
                        self._wait_for_association_deletion(association_id)
                    except ClientError as e:
                        logger.error(f"Error disassociating TGW association {association_id}: {e}")

        except ClientError as e:
            logger.error(f"Error cleaning up TGW associations for gateway {gateway_id}: {e}")

    def _cleanup_virtual_interfaces(self, gateway_id: str) -> None:
        try:
            attachments_response = self.dx_client.describe_direct_connect_gateway_attachments(
                directConnectGatewayId=gateway_id
            )
            attachments = attachments_response.get("directConnectGatewayAttachments", [])

            for attachment in attachments:
                vif_id = attachment.get("virtualInterfaceId")
                if not vif_id:
                    continue

                if attachment.get("attachmentState") not in ["detaching", "detached"]:
                    if self.dry_run:
                        logger.info(f"[DRY RUN] Would delete virtual interface: {vif_id}")
                        continue

                    try:
                        self.dx_client.delete_virtual_interface(virtualInterfaceId=vif_id)
                        logger.info(f"Initiated deletion of virtual interface {vif_id}")
                        self._wait_for_vif_deletion(vif_id)
                    except ClientError as e:
                        logger.error(f"Error deleting virtual interface {vif_id}: {e}")

        except ClientError as e:
            logger.error(f"Error cleaning up virtual interfaces for gateway {gateway_id}: {e}")

    def _delete_direct_connect_gateway(self, gateway_id: str) -> None:
        if self.dry_run:
            logger.info(f"[DRY RUN] Would delete Direct Connect Gateway: {gateway_id}")
            return

        try:
            logger.info(f"Deleting Direct Connect Gateway: {gateway_id}")
            self.dx_client.delete_direct_connect_gateway(directConnectGatewayId=gateway_id)
            self._wait_for_gateway_deletion(gateway_id)
        except ClientError as e:
            logger.error(f"Error deleting Direct Connect Gateway {gateway_id}: {e}")

    def _wait_for_association_deletion(self, association_id: str, timeout: int = 600) -> None:
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
            logger.error(f"Timeout waiting for TGW association {association_id} to be disassociated")

    def _wait_for_vif_deletion(self, vif_id: str, timeout: int = 600) -> None:
        if self.dry_run:
            return

        def is_deleted():
            try:
                response = self.dx_client.describe_virtual_interfaces(virtualInterfaceId=vif_id)
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
            logger.error(f"Timeout waiting for virtual interface {vif_id} to be deleted")

    def _wait_for_gateway_deletion(self, gateway_id: str, timeout: int = 600) -> None:
        if self.dry_run:
            return

        def is_deleted():
            try:
                response = self.dx_client.describe_direct_connect_gateways(directConnectGatewayId=gateway_id)
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
            logger.error(f"Timeout waiting for Direct Connect Gateway {gateway_id} to be deleted")
