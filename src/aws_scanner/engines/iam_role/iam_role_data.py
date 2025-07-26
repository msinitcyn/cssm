class IamRoleData:
    def __init__(self, name: str, inline_policies: dict = None, attached_policies: dict = None, trust_policy_document: dict = None):
        self.name = name
        self.inline_policies = inline_policies or {}
        self.attached_policies = attached_policies or {}
        self.trust_policy_document = trust_policy_document
