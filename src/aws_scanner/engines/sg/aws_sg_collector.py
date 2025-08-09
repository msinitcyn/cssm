import botocore.exceptions
from typing import List, Optional
from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from .sg_collector import SgCollector
from .sg_data import SgData

class AwsSgCollector(SgCollector):

    def __init__(self, boto3_wrapper: Boto3Wrapper, regions: list[str] = None):
        self._boto3_wrapper = boto3_wrapper
        self._regions = regions

    def collect(self) -> List[SgData]:
        results = []

        if self._regions:
            for region in self._regions:
                try:
                    regional_ec2 = self._boto3_wrapper.get_ec2(region=region)
                    self._collect_security_groups(regional_ec2, results, region)
                except botocore.exceptions.ClientError:
                    continue
        else:
            ec2 = self._boto3_wrapper.get_ec2()
            self._collect_security_groups(ec2, results, None)

        return results

    def _collect_security_groups(self, ec2_client, results: List[SgData], region: Optional[str]) -> None:
        try:
            groups = ec2_client.describe_security_groups().get("SecurityGroups", [])

            for group in groups:
                try:
                    results.append(SgData(
                        group_id=group["GroupId"],
                        group_name=group.get("GroupName", ""),
                        owner_id=group.get("OwnerId", ""),
                        ingress_permissions=group.get("IpPermissions", []),
                        region=region
                    ))
                except KeyError:
                    continue

        except botocore.exceptions.ClientError:
            pass