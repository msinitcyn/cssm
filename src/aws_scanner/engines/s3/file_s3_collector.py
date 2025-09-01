import json
from typing import List, Dict, Any, Optional
from .s3_collector import S3Collector
from .s3_bucket_data import S3BucketData
from aws_scanner.engines.common.iam_policy_data import IamPolicyData

class FileS3Collector(S3Collector):
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> List[S3BucketData]:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        results = []

        if isinstance(raw_data, dict):
            if self._is_single_bucket(raw_data):
                bucket_data = self._create_bucket_from_dict(raw_data, raw_data.get("bucket_name", raw_data.get("name", "bucket")))
                if bucket_data:
                    results.append(bucket_data)
            else:
                for idx, (bucket_key, bucket_dict) in enumerate(raw_data.items()):
                    bucket_name = bucket_dict.get("bucket_name", bucket_dict.get("name", f"bucket-{idx}"))
                    bucket_data = self._create_bucket_from_dict(bucket_dict, bucket_name)
                    if bucket_data:
                        results.append(bucket_data)
        elif isinstance(raw_data, list):
            for idx, bucket_dict in enumerate(raw_data):
                bucket_name = bucket_dict.get("bucket_name", bucket_dict.get("name", f"bucket-{idx}"))
                bucket_data = self._create_bucket_from_dict(bucket_dict, bucket_name)
                if bucket_data:
                    results.append(bucket_data)

        return results

    def _is_single_bucket(self, data: Dict[str, Any]) -> bool:
        bucket_indicators = {
            "bucket_name", "name", "policy", "acl", "block_public_access",
            "pab_config", "server_access_logging", "versioning", "encryption"
        }
        return any(field in data for field in bucket_indicators)

    def _create_bucket_from_dict(self, bucket_dict: Dict[str, Any], bucket_name: str) -> Optional[S3BucketData]:
        pab_config = bucket_dict.get("pab_config") or bucket_dict.get("block_public_access") or {}

        acl_grants = []
        acl_value = bucket_dict.get("acl")
        if isinstance(acl_value, str):
            acl_grants = self._convert_acl_string_to_grants(acl_value)
        elif isinstance(acl_value, list):
            acl_grants = acl_value

        policy = None
        policy_value = bucket_dict.get("policy")
        if isinstance(policy_value, dict):
            policy = IamPolicyData(
                name=f"{bucket_name}-bucket-policy",
                policy_type="resource",
                document=policy_value,
                arn=None,
                is_inline=False
            )

        cors_config = bucket_dict.get("cors_config") or {}
        website_config = bucket_dict.get("website_config") or {}
        server_access_logging = bucket_dict.get("server_access_logging") or {}
        versioning = bucket_dict.get("versioning") or {}
        encryption = bucket_dict.get("encryption") or {}
        mfa_delete = bucket_dict.get("mfa_delete")
        if isinstance(mfa_delete, str):
            mfa_delete = mfa_delete.lower() == "enabled" or mfa_delete.lower() == "true"

        return S3BucketData(
            name=bucket_name,
            pab_config=pab_config,
            acl_grants=acl_grants,
            policy=policy,
            cors_config=cors_config,
            website_config=website_config,
            server_access_logging=server_access_logging,
            versioning=versioning,
            encryption=encryption,
            mfa_delete=mfa_delete
        )

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