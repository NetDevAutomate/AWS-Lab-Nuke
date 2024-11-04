import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class SecurityGroupManager:
    def __init__(self, ec2_client, dry_run: bool = False):
        self.ec2_client = ec2_client
        self.dry_run = dry_run

    def remove_all_rules(self, sg_id: str) -> None:
        try:
            sg = self.ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
            if sg["IpPermissions"]:
                self.ec2_client.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=sg["IpPermissions"])
            if sg["IpPermissionsEgress"]:
                self.ec2_client.revoke_security_group_egress(GroupId=sg_id, IpPermissions=sg["IpPermissionsEgress"])
        except ClientError as e:
            logger.error(f"Error removing rules from security group {sg_id}: {e}")

    def remove_references(self, vpc_id: str, target_sg_id: str) -> None:
        security_groups = self.ec2_client.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        for sg in security_groups:
            if sg["GroupId"] == target_sg_id:
                continue
            self._remove_sg_references(sg["GroupId"], target_sg_id)

    def _remove_sg_references(self, sg_id: str, target_sg_id: str) -> None:
        try:
            sg = self.ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
            ingress_rules = [rule for rule in sg["IpPermissions"] if any(pair["GroupId"] == target_sg_id for pair in rule.get("UserIdGroupPairs", []))]
            if ingress_rules:
                self.ec2_client.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=ingress_rules)
            egress_rules = [rule for rule in sg["IpPermissionsEgress"] if any(pair["GroupId"] == target_sg_id for pair in rule.get("UserIdGroupPairs", []))]
            if egress_rules:
                self.ec2_client.revoke_security_group_egress(GroupId=sg_id, IpPermissions=egress_rules)
        except ClientError as e:
            logger.error(f"Error removing references to {target_sg_id} from {sg_id}: {e}")
