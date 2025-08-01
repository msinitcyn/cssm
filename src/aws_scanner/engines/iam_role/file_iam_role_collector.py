from typing import List
import json
from aws_scanner.engines.common.iam_policy_data import IamPolicyData
from .iam_role_data import IamRoleData
from .iam_role_collector import IamRoleCollector

class FileIamRoleCollector(IamRoleCollector):
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> List[IamRoleData]:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        roles = []
        for role_name, role_dict in raw_data.items():
            inline_policies = []
            for policy in role_dict.get("inline_policies", []):
                inline_policies.append(IamPolicyData(
                    name=policy["name"],
                    policy_type=policy.get("policy_type", "inline"),
                    document=policy.get("document", {}),
                    arn=policy.get("arn"),
                    is_inline=True
                ))

            attached_policies = []
            for policy in role_dict.get("attached_policies", []):
                attached_policies.append(IamPolicyData(
                    name=policy["name"],
                    policy_type=policy.get("policy_type", "managed"),
                    document=policy.get("document", {}),
                    arn=policy.get("arn"),
                    is_inline=False
                ))

            roles.append(IamRoleData(
                name=role_name,
                inline_policies=inline_policies,
                attached_policies=attached_policies,
                trust_policy_document=role_dict.get("trust_policy_document", {})
            ))

        return roles
