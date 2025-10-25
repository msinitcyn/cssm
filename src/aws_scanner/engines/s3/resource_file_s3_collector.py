import json
from typing import List, Dict, Any
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

            acl_grants = self._process_acl_field(bucket_dict)
            pab_config = self._get_pab_config(bucket_dict)

            bucket_resource = ResourceDefinition(
                logical_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                properties={
                    "BucketName": bucket_name,
                    "AclGrants": acl_grants,
                    "BucketPolicy": policy,
                    "PublicAccessBlockConfiguration": pab_config
                },
                references=bucket_references
            )
            collection.add_resource(bucket_resource)

        return collection

    def _process_acl_field(self, bucket_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        acl_value = bucket_dict.get("acl", bucket_dict.get("acl_grants", []))

        if isinstance(acl_value, str):
            return self._convert_acl_string_to_grants(acl_value)
        elif isinstance(acl_value, list):
            return acl_value
        else:
            return []

    def _get_pab_config(self, bucket_dict: Dict[str, Any]) -> Dict[str, Any]:
        return (bucket_dict.get("public_access_block") or
                bucket_dict.get("block_public_access") or
                bucket_dict.get("pab_config"))

    def _convert_acl_string_to_grants(self, acl_string: str) -> List[Dict[str, Any]]:
        if acl_string == "public-read":
            return [{
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                },
                "Permission": "READ"
            }]
        elif acl_string == "public-read-write":
            return [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                },
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "WRITE"
                }
            ]
        elif acl_string == "private":
            return []
        else:
            return []