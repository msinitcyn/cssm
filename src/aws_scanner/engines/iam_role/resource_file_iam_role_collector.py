import json
from aws_scanner.engines.common.resource_definition import (
    ResourceCollection,
    ResourceDefinition,
    ResourceReference
)


class ResourceFileIamRoleCollector:
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> ResourceCollection:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        collection = ResourceCollection()

        for role_name, role_dict in raw_data.items():
            role_references = []

            for inline_policy in role_dict.get("inline_policies", []):
                policy_logical_id = f"{role_name}-{inline_policy['name']}"
                policy_resource = ResourceDefinition(
                    logical_id=policy_logical_id,
                    resource_type="AWS::IAM::Policy",
                    properties={
                        "PolicyName": inline_policy["name"],
                        "PolicyDocument": inline_policy.get("document", {})
                    }
                )
                collection.add_resource(policy_resource)

                role_references.append(ResourceReference(
                    target_logical_id=policy_logical_id,
                    reference_type="inline_policy"
                ))

            for attached_policy in role_dict.get("attached_policies", []):
                policy_logical_id = f"{role_name}-{attached_policy['name']}"
                policy_resource = ResourceDefinition(
                    logical_id=policy_logical_id,
                    resource_type="AWS::IAM::ManagedPolicy",
                    properties={
                        "ManagedPolicyName": attached_policy["name"]
                    }
                )
                collection.add_resource(policy_resource)

                role_references.append(ResourceReference(
                    target_logical_id=policy_logical_id,
                    reference_type="managed_policy"
                ))

            role_resource = ResourceDefinition(
                logical_id=role_name,
                resource_type="AWS::IAM::Role",
                properties={
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": role_dict.get("assume_role_policy_document", {})
                },
                references=role_references
            )
            collection.add_resource(role_resource)

        return collection