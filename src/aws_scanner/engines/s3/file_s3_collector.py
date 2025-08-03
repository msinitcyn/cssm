import json
from typing import List

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
        for idx, (policy_key, policy_dict) in enumerate(raw_data.items()):
            policy = IamPolicyData(
                name=policy_dict.get("name", policy_key),
                policy_type=policy_dict["policy_type"],
                document=policy_dict.get("document", {}),
                arn=policy_dict.get("arn"),
                is_inline=policy_dict.get("is_inline", True)
            )

            bucket_name = f"bucket-{idx}"  # временное имя, если другого нет
            results.append(S3BucketData(
                name=bucket_name,
                policy=policy
            ))

        return results
