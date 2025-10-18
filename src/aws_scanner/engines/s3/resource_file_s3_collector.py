import json
from aws_scanner.engines.common.resource_definition import (
    ResourceCollection,
    ResourceDefinition,
    ResourceReference,
    ReferenceType
)


class ResourceFileS3Collector:
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> ResourceCollection:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        collection = ResourceCollection()

        for bucket_name, bucket_dict in raw_data.items():
            bucket_references = []

            policy = bucket_dict.get("policy")
            if policy:
                policy_logical_id = f"{bucket_name}-bucket-policy"
                policy_resource = ResourceDefinition(
                    logical_id=policy_logical_id,
                    resource_type="AWS::S3::BucketPolicy",
                    properties={
                        "PolicyDocument": policy
                    }
                )
                collection.add_resource(policy_resource)

                bucket_references.append(ResourceReference(
                    target_logical_id=policy_logical_id,
                    reference_type=ReferenceType.INLINE
                ))

            bucket_resource = ResourceDefinition(
                logical_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                properties={
                    "BucketName": bucket_name,
                    "AclGrants": bucket_dict.get("acl_grants", []),
                    "BucketPolicy": policy,
                    "PublicAccessBlockConfiguration": bucket_dict.get("public_access_block")
                },
                references=bucket_references
            )
            collection.add_resource(bucket_resource)

        return collection