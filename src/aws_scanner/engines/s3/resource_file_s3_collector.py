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

        if "bucket_name" in raw_data or "resource_type" in raw_data:
            buckets_data = {raw_data.get("bucket_name", "UnnamedBucket"): raw_data}
        else:
            buckets_data = raw_data

        for bucket_name, bucket_dict in buckets_data.items():
            policy = bucket_dict.get("policy")
            acl_grants = self._process_acl_field(bucket_dict)
            pab_config = self._get_pab_config(bucket_dict)
            versioning_config = self._get_versioning_config(bucket_dict)
            mfa_delete = bucket_dict.get("mfa_delete", bucket_dict.get("MfaDelete"))
            encryption_config = self._get_encryption_config(bucket_dict)
            logging_config = self._get_logging_config(bucket_dict)
            cors_config = self._get_cors_config(bucket_dict)
            website_config = self._get_website_config(bucket_dict)

            bucket_resource = ResourceDefinition(
                logical_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                properties={
                    "BucketName": bucket_name,
                    "AclGrants": acl_grants,
                    "Policy": policy,
                    "PublicAccessBlockConfiguration": pab_config,
                    "VersioningConfiguration": versioning_config,
                    "MfaDelete": mfa_delete,
                    "BucketEncryption": encryption_config,
                    "LoggingConfiguration": logging_config,
                    "CorsConfiguration": cors_config,
                    "WebsiteConfiguration": website_config
                }
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
        result = (bucket_dict.get("public_access_block") or
                  bucket_dict.get("block_public_access") or
                  bucket_dict.get("pab_config"))
        return result if result is not None else {}

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

    def _get_versioning_config(self, bucket_dict: Dict[str, Any]) -> Dict[str, Any]:
        versioning = bucket_dict.get("versioning") or bucket_dict.get("VersioningConfiguration")
        if versioning and isinstance(versioning, dict):
            if "status" in versioning:
                return {"Status": versioning["status"]}
            return versioning
        return {}

    def _get_encryption_config(self, bucket_dict: Dict[str, Any]) -> Dict[str, Any]:
        result = bucket_dict.get("encryption") or bucket_dict.get("BucketEncryption")
        return result if result is not None else {}

    def _get_logging_config(self, bucket_dict: Dict[str, Any]) -> Dict[str, Any]:
        logging = bucket_dict.get("server_access_logging") or bucket_dict.get("LoggingConfiguration")
        if logging and isinstance(logging, dict):
            if "enabled" in logging and not logging["enabled"]:
                return {}
            return logging
        return {}

    def _get_cors_config(self, bucket_dict: Dict[str, Any]) -> Dict[str, Any]:
        result = bucket_dict.get("cors") or bucket_dict.get("CorsConfiguration")
        return result if result is not None else {}

    def _get_website_config(self, bucket_dict: Dict[str, Any]) -> Dict[str, Any]:
        result = bucket_dict.get("website") or bucket_dict.get("WebsiteConfiguration")
        return result if result is not None else {}