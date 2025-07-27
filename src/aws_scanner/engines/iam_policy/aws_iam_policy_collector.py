from typing import List
import botocore.exceptions
from aws_scanner.engines.common.iam_policy_data import IamPolicyData
from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from .iam_policy_collector import IamPolicyCollector

class AwsIamPolicyCollector(IamPolicyCollector):
    def __init__(self, boto3_wrapper: Boto3Wrapper, attached_only: bool = False):
        self._boto3_wrapper = boto3_wrapper
        self._attached_only = attached_only

    def collect(self) -> List[IamPolicyData]:
        iam = self._boto3_wrapper.get_iam()
        policies = []
        paginator = iam.get_paginator("list_policies")

        for page in paginator.paginate(Scope='Local' if self._attached_only else 'All'):
            for policy in page.get("Policies", []):
                if self._attached_only and not policy.get("AttachmentCount", 0):
                    continue

                policy_arn = policy["Arn"]
                policy_name = policy["PolicyName"]
                try:
                    version_info = iam.get_policy(PolicyArn=policy_arn)
                    default_version_id = version_info["Policy"]["DefaultVersionId"]
                    version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version_id
                    )
                    policy_doc = version["PolicyVersion"]["Document"]
                    policies.append(IamPolicyData(
                        name=policy_name,
                        policy_type="attached",
                        arn=policy_arn,
                        document=policy_doc,
                        is_inline=False
                    ))
                except botocore.exceptions.ClientError:
                    policies.append(IamPolicyData(
                        name=policy_name,
                        policy_type="attached",
                        arn=policy_arn,
                        document={},
                        is_inline=False
                    ))

        return policies
