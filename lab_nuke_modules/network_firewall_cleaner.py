import logging
from typing import Dict, Optional
from botocore.exceptions import ClientError

from lab_nuke_modules.resource_manager import ResourceManager

logger = logging.getLogger(__name__)

class NetworkFirewallCleaner(ResourceManager):
    def cleanup_firewalls(self, vpc_id: Optional[str] = None) -> None:
        filters = {"VpcIds": [vpc_id]} if vpc_id else {}
        firewalls = self.paginate(self.nfw_client, "list_firewalls", **filters)

        for firewall in firewalls:
            self._disable_protection(firewall)
            self._remove_logging(firewall)
            self._delete_firewall(firewall)

    def _disable_protection(self, firewall: Dict) -> None:
        try:
            firewall_config = self.nfw_client.describe_firewall(FirewallName=firewall["FirewallName"])
            if firewall_config["Firewall"]["DeleteProtection"]:
                self.nfw_client.update_firewall_delete_protection(
                    FirewallArn=firewall["FirewallArn"], DeleteProtection=False
                )
                logger.info(f"Disabled delete protection for firewall {firewall['FirewallName']}")
        except ClientError as e:
            logger.error(f"Error disabling protection for firewall {firewall['FirewallName']}: {e}")

    def _remove_logging(self, firewall: Dict) -> None:
        try:
            if self.dry_run:
                logger.info(f"[DRY RUN] Would remove logging from firewall: {firewall['FirewallName']}")
                return

            logging_config = self.nfw_client.describe_logging_configuration(FirewallArn=firewall["FirewallArn"])
            if "LoggingConfiguration" in logging_config:
                self.nfw_client.update_logging_configuration(
                    FirewallArn=firewall["FirewallArn"],
                    LoggingConfiguration={"LogDestinationConfigs": []},
                )
                logger.info(f"Removed logging configuration for firewall {firewall['FirewallName']}")
        except ClientError as e:
            if "InvalidRequestException" in str(e):
                try:
                    logging_config = self.nfw_client.describe_logging_configuration(FirewallArn=firewall["FirewallArn"])
                    current_configs = logging_config.get("LoggingConfiguration", {}).get("LogDestinationConfigs", [])

                    for config in current_configs:
                        remaining_configs = [c for c in current_configs if c != config]
                        self.nfw_client.update_logging_configuration(
                            FirewallArn=firewall["FirewallArn"],
                            LoggingConfiguration={"LogDestinationConfigs": remaining_configs},
                        )
                    logger.info(f"Removed all logging configurations for firewall {firewall['FirewallName']}")
                except ClientError as inner_e:
                    logger.error(f"Error removing individual logging configs for firewall {firewall['FirewallName']}: {inner_e}")
            else:
                logger.error(f"Error removing logging for firewall {firewall['FirewallName']}: {e}")

    def _delete_firewall(self, firewall: Dict) -> None:
        try:
            if self.dry_run:
                logger.info(f"[DRY RUN] Would delete firewall: {firewall['FirewallName']}")
                return

            self.nfw_client.delete_firewall(FirewallName=firewall["FirewallName"])
            logger.info(f"Deleted firewall {firewall['FirewallName']}")
        except ClientError as e:
            logger.error(f"Error deleting firewall {firewall['FirewallName']}: {e}")
