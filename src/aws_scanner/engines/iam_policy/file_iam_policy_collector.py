from typing import List
import json
from aws_scanner.engines.common.iam_policy_data import IamPolicyData
from .iam_policy_collector import IamPolicyCollector

class FileIamPolicyCollector(IamPolicyCollector):
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> List[IamPolicyData]:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        policies = []
        for policy_name, policy_dict in raw_data.items():
            policies.append(IamPolicyData(
                name=policy_dict["name"],
                policy_type=policy_dict["policy_type"],
                document=policy_dict.get("document", {}),
                arn=policy_dict.get("arn"),
                is_inline=policy_dict.get("is_inline", True)
            ))

        return policies