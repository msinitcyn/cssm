from pathlib import Path

from aws_scanner.engines.cloudformation.reader import CloudFormationReader
from aws_scanner.engines.common.resource_definition import ResourceCollection, ResourceDefinition


class ResourceFileCloudFormationCollector:
    def __init__(self, file_path: str):
        self.file_path = file_path
    
    def collect(self) -> ResourceCollection:
        path = Path(self.file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"CloudFormation template not found: {self.file_path}")
        
        with open(self.file_path, 'r') as f:
            content = f.read()
        
        reader = CloudFormationReader()
        collection = reader.read(content)
        
        self._extract_inline_policies_from_roles(collection)
        self._extract_bucket_policies(collection)
        
        return collection
    
    def _extract_inline_policies_from_roles(self, collection: ResourceCollection) -> None:
        roles_to_process = [r for r in collection.resources.values() if r.resource_type == "AWS::IAM::Role"]
        
        for role_resource in roles_to_process:
            inline_policies = role_resource.properties.get("Policies", [])
            for policy in inline_policies:
                policy_doc = policy.get("PolicyDocument", {})
                if policy_doc:
                    policy_logical_id = policy.get("PolicyName", f"{role_resource.logical_id}-InlinePolicy")
                    policy_resource = ResourceDefinition(
                        logical_id=policy_logical_id,
                        resource_type="AWS::IAM::Policy",
                        properties={
                            "PolicyName": policy.get("PolicyName", "InlinePolicy"),
                            "PolicyDocument": policy_doc
                        }
                    )
                    collection.add_resource(policy_resource)
    
    def _extract_bucket_policies(self, collection: ResourceCollection) -> None:
        bucket_policies = [r for r in collection.resources.values() if r.resource_type == "AWS::S3::BucketPolicy"]

        for policy_resource in bucket_policies:
            policy_doc = policy_resource.properties.get("PolicyDocument", {})
            bucket_ref = policy_resource.properties.get("Bucket", "")

            if policy_doc:
                bucket_logical_id = bucket_ref
                if isinstance(bucket_ref, dict) and "Ref" in bucket_ref:
                    bucket_logical_id = bucket_ref["Ref"]

                target_bucket = collection.resources.get(bucket_logical_id)
                if target_bucket:
                    bucket_name = target_bucket.properties.get("BucketName", bucket_logical_id)
                    target_bucket.properties["Policy"] = policy_doc
                else:
                    bucket_name = bucket_ref if isinstance(bucket_ref, str) else bucket_logical_id

                policy_as_iam_resource = ResourceDefinition(
                    logical_id=f"{policy_resource.logical_id}-AsPolicy",
                    resource_type="AWS::IAM::Policy",
                    properties={
                        "PolicyName": policy_resource.logical_id,
                        "PolicyDocument": policy_doc,
                        "_bucket_name": bucket_name
                    }
                )
                collection.add_resource(policy_as_iam_resource)

        for policy_resource in bucket_policies:
            if policy_resource.logical_id in collection.resources:
                del collection.resources[policy_resource.logical_id]
