import botocore.exceptions
from aws_scanner.engines.common.resource_definition import ResourceCollection, ResourceDefinition
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


class ResourceAwsIamPolicyCollector:
    def __init__(self, boto3_wrapper: Boto3Wrapper, attached_only: bool = False):
        self._boto3_wrapper = boto3_wrapper
        self._attached_only = attached_only

    def collect(self) -> ResourceCollection:
        iam = self._boto3_wrapper.get_iam()
        collection = ResourceCollection()
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

                    policy_resource = ResourceDefinition(
                        logical_id=policy_name,
                        resource_type="AWS::IAM::Policy",
                        properties={
                            "PolicyName": policy_name,
                            "PolicyDocument": policy_doc
                        }
                    )
                    collection.add_resource(policy_resource)
                except botocore.exceptions.ClientError:
                    pass

        return collection
