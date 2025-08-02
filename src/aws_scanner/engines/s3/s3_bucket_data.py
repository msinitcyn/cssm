from aws_scanner.engines.common.iam_policy_data import IamPolicyData

class S3BucketData:
    def __init__(
            self,
            name: str,
            pab_config=None,
            acl_grants=None,
            policy: IamPolicyData=None,
            cors_config=None,
            website_config=None):
        self.name = name
        self.pab_config = pab_config or {}
        self.acl_grants = acl_grants or []
        self.policy = policy or None
        self.cors_config = cors_config or {}
        self.website_config = website_config or {}