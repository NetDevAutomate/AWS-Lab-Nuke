import logging
import time
from typing import List, Dict, Any, Callable

import boto3
from botocore.exceptions import ClientError, WaiterError
from botocore.paginate import Paginator

from lab_nuke_modules.resource_manager import ResourceManager

logger = logging.getLogger(__name__)

class ContainerResourceManager(ResourceManager):
    def __init__(self, region: str, dry_run: bool = False):
        super().__init__(region, dry_run)
        self.eks = self.eks_client
        self.ecs = self.ecs_client
        self.asg = self.asg_client
        self.logger = logging.getLogger('ContainerResourceManager')

    def cleanup_container_resources(self) -> None:
        self.logger.info("Starting container resource cleanup...")
        try:
            self.cleanup_launch_templates()
            time.sleep(30)
            self.cleanup_eks_clusters()
            time.sleep(30)
            self.cleanup_ecs_resources()
            self.logger.info("Container resource cleanup completed")
        except Exception as e:
            self.logger.error(f"Error during container resource cleanup: {e}")

    def cleanup_launch_templates(self) -> None:
        try:
            paginator = self.ec2_client.get_paginator('describe_launch_templates')
            for page in paginator.paginate():
                for template in page['LaunchTemplates']:
                    template_id = template['LaunchTemplateId']
                    template_name = template['LaunchTemplateName']
                    if ('eks' in template_name.lower() or 'ecs' in template_name.lower() or 'kubernetes' in template_name.lower()):
                        if self.dry_run:
                            self.logger.info(f"[DRY RUN] Would delete Launch Template: {template_name} ({template_id})")
                            continue
                        try:
                            self.logger.info(f"Deleting Launch Template: {template_name} ({template_id})")
                            self.ec2_client.delete_launch_template(LaunchTemplateId=template_id)
                            self.logger.info(f"Successfully deleted Launch Template: {template_name}")
                        except ClientError as e:
                            if 'VersionLimitExceeded' in str(e):
                                self.logger.info(f"Deleting versions for template: {template_name}")
                                paginator = self.ec2_client.get_paginator('describe_launch_template_versions')
                                versions = []
                                for page in paginator.paginate(LaunchTemplateId=template_id):
                                    versions.extend(page['LaunchTemplateVersions'])
                                for version in versions:
                                    version_number = version['VersionNumber']
                                    if not version.get('DefaultVersion', False):
                                        try:
                                            self.ec2_client.delete_launch_template_versions(
                                                LaunchTemplateId=template_id,
                                                Versions=[str(version_number)]
                                            )
                                        except ClientError as ve:
                                            self.logger.error(f"Error deleting version {version_number} of template {template_name}: {ve}")
                                try:
                                    self.ec2_client.delete_launch_template(LaunchTemplateId=template_id)
                                except ClientError as te:
                                    self.logger.error(f"Error deleting template {template_name} after version cleanup: {te}")
                            else:
                                self.logger.error(f"Error deleting Launch Template {template_name}: {e}")
        except ClientError as e:
            self.logger.error(f"Error listing Launch Templates: {e}")

    def _verify_launch_templates_deleted(self) -> bool:
        try:
            paginator = self.ec2_client.get_paginator('describe_launch_templates')
            for page in paginator.paginate():
                for template in page['LaunchTemplates']:
                    if ('eks' in template['LaunchTemplateName'].lower() or 'ecs' in template['LaunchTemplateName'].lower() or 'kubernetes' in template['LaunchTemplateName'].lower()):
                        return False
            return True
        except ClientError as e:
            self.logger.error(f"Error verifying Launch Templates deletion: {e}")
            return False

    def cleanup_eks_clusters(self) -> None:
        try:
            clusters = self.eks.list_clusters()['clusters']
            if not clusters:
                self.logger.info("No EKS clusters found")
                return
            for cluster_name in clusters:
                self.logger.info(f"Processing EKS cluster: {cluster_name}")
                try:
                    self._scale_down_all_nodegroups(cluster_name)
                    time.sleep(60)
                    self._delete_eks_managed_nodegroups(cluster_name)
                    time.sleep(30)
                    if not self.dry_run:
                        self.logger.info(f"Deleting EKS cluster: {cluster_name}")
                        self.eks.delete_cluster(name=cluster_name)
                        self._wait_for_cluster_deletion(cluster_name)
                    else:
                        self.logger.info(f"[DRY RUN] Would delete EKS cluster: {cluster_name}")
                except ClientError as e:
                    self.logger.error(f"Error processing cluster {cluster_name}: {e}")
                    continue
        except ClientError as e:
            self.logger.error(f"Error listing EKS clusters: {e}")

    def _scale_down_all_nodegroups(self, cluster_name: str) -> None:
        try:
            nodegroups = self.eks.list_nodegroups(clusterName=cluster_name)['nodegroups']
            if not nodegroups:
                self.logger.info(f"No nodegroups found for cluster {cluster_name}")
                return
            for nodegroup in nodegroups:
                self.logger.info(f"Scaling down nodegroup: {nodegroup}")
                if not self.dry_run:
                    try:
                        nodegroup_info = self.eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)['nodegroup']
                        if 'resources' in nodegroup_info and 'autoScalingGroups' in nodegroup_info['resources']:
                            for asg in nodegroup_info['resources']['autoScalingGroups']:
                                asg_name = asg['name']
                                self.logger.info(f"Setting ASG {asg_name} capacity to 0")
                                self.asg.update_auto_scaling_group(
                                    AutoScalingGroupName=asg_name,
                                    MinSize=0,
                                    MaxSize=0,
                                    DesiredCapacity=0,
                                    NewInstancesProtectedFromScaleIn=False
                                )
                        self.eks.update_nodegroup_config(
                            clusterName=cluster_name,
                            nodegroupName=nodegroup,
                            scalingConfig={
                                'minSize': 0,
                                'maxSize': 0,
                                'desiredSize': 0
                            }
                        )
                        self._wait_for_nodegroup_scale_down(cluster_name, nodegroup)
                    except ClientError as e:
                        self.logger.error(f"Error scaling down nodegroup {nodegroup}: {e}")
                else:
                    self.logger.info(f"[DRY RUN] Would scale down nodegroup: {nodegroup}")
        except ClientError as e:
            self.logger.error(f"Error listing nodegroups for cluster {cluster_name}: {e}")

    def _delete_eks_managed_nodegroups(self, cluster_name: str) -> None:
        try:
            nodegroups = self.eks.list_nodegroups(clusterName=cluster_name)['nodegroups']
            for nodegroup in nodegroups:
                self.logger.info(f"Processing managed nodegroup: {nodegroup}")
                try:
                    nodegroup_info = self.eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)['nodegroup']
                    if 'resources' in nodegroup_info and 'autoScalingGroups' in nodegroup_info['resources']:
                        for asg in nodegroup_info['resources']['autoScalingGroups']:
                            asg_name = asg['name']
                            self.logger.info(f"Found associated ASG: {asg_name}")
                            if not self.dry_run:
                                self._force_delete_asg_instances(asg_name)
                            else:
                                self.logger.info(f"[DRY RUN] Would delete ASG: {asg_name}")
                    if not self.dry_run:
                        self.logger.info(f"Deleting nodegroup {nodegroup}")
                        self.eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)
                        self._wait_for_nodegroup_deletion(cluster_name, nodegroup)
                    else:
                        self.logger.info(f"[DRY RUN] Would delete nodegroup: {nodegroup}")
                except ClientError as e:
                    self.logger.error(f"Error processing nodegroup {nodegroup}: {e}")
        except ClientError as e:
            self.logger.error(f"Error listing nodegroups: {e}")

    def _force_delete_asg_instances(self, asg_name: str) -> None:
        try:
            self.logger.info(f"Setting capacity to 0 for ASG: {asg_name}")
            self.asg.update_auto_scaling_group(
                AutoScalingGroupName=asg_name,
                MinSize=0,
                MaxSize=0,
                DesiredCapacity=0,
                NewInstancesProtectedFromScaleIn=False
            )
            response = self.asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
            if not response['AutoScalingGroups']:
                return
            asg = response['AutoScalingGroups'][0]
            instance_ids = [i['InstanceId'] for i in asg['Instances']]
            if instance_ids:
                self.logger.info(f"Force terminating instances in ASG {asg_name}: {instance_ids}")
                self.ec2_client.terminate_instances(InstanceIds=instance_ids)
                waiter = self.ec2_client.get_waiter('instance_terminated')
                try:
                    waiter.wait(InstanceIds=instance_ids, WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
                except WaiterError as e:
                    self.logger.warning(f"Timeout waiting for instances to terminate in ASG {asg_name}")
            self.logger.info(f"Deleting ASG: {asg_name}")
            self.asg.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
            while True:
                try:
                    self.asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
                    self.logger.info(f"Waiting for ASG {asg_name} deletion...")
                    time.sleep(15)
                except ClientError as e:
                    if 'AutoScalingGroupNotFound' in str(e):
                        break
                    raise e
        except ClientError as e:
            self.logger.error(f"Error force deleting ASG {asg_name}: {e}")

    def cleanup_ecs_resources(self) -> None:
        try:
            clusters = self.ecs.list_clusters()['clusterArns']
            for cluster_arn in clusters:
                self.logger.info(f"Processing ECS cluster: {cluster_arn}")
                services = self.ecs.list_services(cluster=cluster_arn)['serviceArns']
                for service_arn in services:
                    if not self.dry_run:
                        self.logger.info(f"Deleting service: {service_arn}")
                        self.ecs.update_service(cluster=cluster_arn, service=service_arn, desiredCount=0)
                        self.ecs.delete_service(cluster=cluster_arn, service=service_arn, force=True)
                    else:
                        self.logger.info(f"[DRY RUN] Would delete service: {service_arn}")
                task_definitions = self.ecs.list_task_definitions()['taskDefinitionArns']
                for task_def in task_definitions:
                    if not self.dry_run:
                        self.logger.info(f"Deregistering task definition: {task_def}")
                        self.ecs.deregister_task_definition(taskDefinition=task_def)
                    else:
                        self.logger.info(f"[DRY RUN] Would deregister task definition: {task_def}")
                tasks = self.ecs.list_tasks(cluster=cluster_arn)['taskArns']
                for task in tasks:
                    if not self.dry_run:
                        self.logger.info(f"Stopping task: {task}")
                        self.ecs.stop_task(cluster=cluster_arn, task=task)
                    else:
                        self.logger.info(f"[DRY RUN] Would stop task: {task}")
                if not self.dry_run:
                    self.logger.info(f"Deleting cluster: {cluster_arn}")
                    self.ecs.delete_cluster(cluster=cluster_arn)
                else:
                    self.logger.info(f"[DRY RUN] Would delete cluster: {cluster_arn}")
        except ClientError as e:
            self.logger.error(f"Error deleting ECS resources: {e}")

    def _wait_for_nodegroup_scale_down(self, cluster_name: str, nodegroup_name: str, timeout: int = 600) -> None:
        if self.dry_run:
            return
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = self.eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
                scaling_config = response['nodegroup']['scalingConfig']
                current_size = response['nodegroup'].get('status', {}).get('desiredSize', -1)
                if scaling_config['desiredSize'] == 0 and current_size == 0:
                    self.logger.info(f"Nodegroup {nodegroup_name} successfully scaled down")
                    return
                self.logger.info(f"Waiting for nodegroup {nodegroup_name} to scale down... Current size: {current_size}")
                time.sleep(30)
            except ClientError as e:
                if 'ResourceNotFoundException' in str(e):
                    self.logger.info(f"Nodegroup {nodegroup_name} not found (already deleted)")
                    return
                raise e
        raise TimeoutError(f"Timeout waiting for nodegroup {nodegroup_name} to scale down")

    def _wait_for_nodegroup_deletion(self, cluster_name: str, nodegroup_name: str, timeout: int = 600) -> None:
        if self.dry_run:
            return
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                self.eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)
                self.logger.info(f"Waiting for nodegroup {nodegroup_name} deletion...")
                time.sleep(30)
            except ClientError as e:
                if 'ResourceNotFoundException' in str(e):
                    return
                raise e
        raise TimeoutError(f"Timeout waiting for nodegroup {nodegroup_name} deletion")

    def _wait_for_cluster_deletion(self, cluster_name: str, timeout: int = 600) -> None:
        if self.dry_run:
            return
        try:
            waiter = self.eks.get_waiter('cluster_deleted')
            waiter.wait(name=cluster_name, WaiterConfig={'Delay': 30, 'MaxAttempts': timeout // 30})
        except WaiterError as e:
            self.logger.error(f"Error waiting for cluster {cluster_name} deletion: {e}")
            raise TimeoutError(f"Timeout waiting for cluster {cluster_name} deletion")
