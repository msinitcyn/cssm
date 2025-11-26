import botocore.exceptions
from aws_scanner.engines.common.resource_definition import ResourceCollection, ResourceDefinition
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


class ResourceAwsIamRoleCollector:
    def __init__(self, boto3_wrapper: Boto3Wrapper):
        self._boto3_wrapper = boto3_wrapper

    def collect(self) -> ResourceCollection:
        iam = self._boto3_wrapper.get_iam()
        collection = ResourceCollection()
        paginator = iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page["Roles"]:
                role_name = role["RoleName"]

                try:
                    role_details = iam.get_role(RoleName=role_name)
                    trust_policy = role_details["Role"]["AssumeRolePolicyDocument"]
                except botocore.exceptions.ClientError:
                    trust_policy = {}

                role_resource = ResourceDefinition(
                    logical_id=role_name,
                    resource_type="AWS::IAM::Role",
                    properties={
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": trust_policy
                    }
                )
                collection.add_resource(role_resource)

                try:
                    response = iam.list_role_policies(RoleName=role_name)
                    for policy_name in response.get("PolicyNames", []):
                        policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                        policy_doc = policy.get("PolicyDocument", {})

                        inline_policy_resource = ResourceDefinition(
                            logical_id=f"{role_name}-{policy_name}",
                            resource_type="AWS::IAM::Policy",
                            properties={
                                "PolicyName": policy_name,
                                "PolicyDocument": policy_doc
                            }
                        )
                        collection.add_resource(inline_policy_resource)
                except botocore.exceptions.ClientError:
                    pass

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

                            attached_policy_resource = ResourceDefinition(
                                logical_id=f"{role_name}-{policy_name}",
                                resource_type="AWS::IAM::ManagedPolicy",
                                properties={
                                    "PolicyName": policy_name,
                                    "PolicyDocument": policy_doc
                                }
                            )
                            collection.add_resource(attached_policy_resource)
                        except botocore.exceptions.ClientError:
                            pass
                except botocore.exceptions.ClientError:
                    pass

        return collection
