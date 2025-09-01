from typing import Optional, Dict, List, Any
from aws_scanner.engines.common.iam_policy_data import IamPolicyData

class S3BucketData:
    def __init__(
        self,
        name: str,
        pab_config: Optional[Dict[str, bool]] = None,
        acl_grants: Optional[List[Dict[str, Any]]] = None,
        policy: Optional[IamPolicyData] = None,
        cors_config: Optional[Dict[str, Any]] = None,
        website_config: Optional[Dict[str, Any]] = None,
        server_access_logging: Optional[Dict[str, Any]] = None,
        versioning: Optional[Dict[str, Any]] = None,
        encryption: Optional[Dict[str, Any]] = None,
        mfa_delete: Optional[bool] = None
    ):
        self.name = name
        self.pab_config = pab_config or {}
        self.acl_grants = acl_grants or []
        self.policy = policy
        self.cors_config = cors_config or {}
        self.website_config = website_config or {}
        self.server_access_logging = server_access_logging or {}
        self.versioning = versioning or {}
        self.encryption = encryption or {}
        self.mfa_delete = mfa_delete