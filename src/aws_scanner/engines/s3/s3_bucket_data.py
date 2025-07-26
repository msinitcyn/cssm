class S3BucketData:
    def __init__(self, name, pab_config=None, acl_grants=None, policy_doc=None,
                 cors_config=None, website_config=None):
        self.name = name
        self.pab_config = pab_config or {}
        self.acl_grants = acl_grants or []
        self.policy_doc = policy_doc or {}
        self.cors_config = cors_config or {}
        self.website_config = website_config or {}