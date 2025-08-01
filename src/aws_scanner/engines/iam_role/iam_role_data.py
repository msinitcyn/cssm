from typing import List
from aws_scanner.engines.common.iam_policy_data import IamPolicyData


class IamRoleData:
    def __init__(
        self,
        name: str,
        inline_policies: List[IamPolicyData] = None,
        attached_policies: List[IamPolicyData] = None,
        trust_policy_document: dict = None,
    ):
        self.name = name
        self.inline_policies = inline_policies or []
        self.attached_policies = attached_policies or []
        self.trust_policy_document = trust_policy_document or {}
