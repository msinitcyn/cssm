import botocore.exceptions
from typing import List
from aws_scanner.engines.common.resource_definition import ResourceCollection, ResourceDefinition
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


class ResourceAwsSecurityGroupCollector:
    def __init__(self, boto3_wrapper: Boto3Wrapper, regions: List[str]):
        self._boto3_wrapper = boto3_wrapper
        self._regions = regions

    def collect(self) -> ResourceCollection:
        collection = ResourceCollection()

        if self._regions:
            for region in self._regions:
                try:
                    ec2 = self._boto3_wrapper.get_ec2(region=region)
                    self._collect_security_groups(ec2, collection)
                except botocore.exceptions.ClientError:
                    continue

        return collection

    def _collect_security_groups(self, ec2, collection: ResourceCollection) -> None:
        try:
            response = ec2.describe_security_groups()
            security_groups = response.get("SecurityGroups", [])

            for sg in security_groups:
                group_id = sg.get("GroupId")
                if not group_id:
                    continue

                sg_resource = ResourceDefinition(
                    logical_id=group_id,
                    resource_type="AWS::EC2::SecurityGroup",
                    properties={
                        "GroupId": group_id,
                        "GroupName": sg.get("GroupName", ""),
                        "OwnerId": sg.get("OwnerId", ""),
                        "SecurityGroupIngress": sg.get("IpPermissions", [])
                    }
                )
                collection.add_resource(sg_resource)

        except botocore.exceptions.ClientError:
            pass
