import botocore.exceptions
from typing import Dict

from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.engines.common.iam_policy_data import IamPolicyData

boto3Wrapper = Boto3Wrapper()

def collect_iam_policies(attached_only: bool=False) -> Dict[str, IamPolicyData]:
    iam = boto3Wrapper.get_iam()
    policies = {}
    paginator = iam.get_paginator("list_policies")

    for page in paginator.paginate(Scope='Local' if attached_only else 'All'):
        for policy in page.get("Policies", []):
            if attached_only and not policy.get("AttachmentCount", 0):
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
                policies[policy_name] = IamPolicyData(
                    name=policy_name,
                    policy_type="attached",
                    arn=policy_arn,
                    document=policy_doc,
                    is_inline=False
                )
            except botocore.exceptions.ClientError:
                policies[policy_name] = IamPolicyData(
                    name=policy_name,
                    policy_type="attached",
                    arn=policy_arn,
                    document={},
                    is_inline=False
                )

    return policies