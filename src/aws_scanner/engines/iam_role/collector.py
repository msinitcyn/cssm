import botocore.exceptions

from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.engines.common.iam_policy_data import IamPolicyData
from .iam_role_data import IamRoleData

boto3Wrapper = Boto3Wrapper()

def collect_iam_roles():
    iam = boto3Wrapper.get_iam()
    roles = []
    paginator = iam.get_paginator("list_roles")

    for page in paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            inline_policies = {}
            attached_policies = {}

            # Inline policies
            try:
                response = iam.list_role_policies(RoleName=role_name)
                for policy_name in response.get("PolicyNames", []):
                    policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    policy_doc = policy.get("PolicyDocument", {})
                    inline_policies[policy_name] = IamPolicyData(
                        name=policy_name,
                        policy_type="inline",
                        document=policy_doc,
                        is_inline=True
                    )
            except botocore.exceptions.ClientError:
                inline_policies["<inline_policy_error>"] = IamPolicyData(
                    name="<inline_policy_error>",
                    policy_type="inline",
                    document={},
                    is_inline=True
                )

            # Attached policies
            try:
                response = iam.list_attached_role_policies(RoleName=role_name)
                for policy in response.get("AttachedPolicies", []):
                    policy_arn = policy["PolicyArn"]
                    policy_name = policy["PolicyName"]
                    try:
                        version_info = iam.get_policy(PolicyArn=policy_arn)
                        default_version_id = version_info["Policy"]["DefaultVersionId"]
                        version = iam.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=default_version_id
                        )
                        policy_doc = version["PolicyVersion"]["Document"]
                        attached_policies[policy_name] = IamPolicyData(
                            name=policy_name,
                            policy_type="attached",
                            arn=policy_arn,
                            document=policy_doc,
                            is_inline=False
                        )
                    except botocore.exceptions.ClientError:
                        attached_policies[policy_name] = IamPolicyData(
                            name=policy_name,
                            policy_type="attached",
                            arn=policy_arn,
                            document={},
                            is_inline=False
                        )
            except botocore.exceptions.ClientError:
                pass  # optionally log it

            roles.append(IamRoleData(
                name=role_name,
                inline_policies=inline_policies,
                attached_policies=attached_policies
            ))

    return roles
