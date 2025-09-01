import botocore.exceptions
import json
from typing import List, Optional
from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.engines.common.iam_policy_data import IamPolicyData
from .s3_collector import S3Collector
from .s3_bucket_data import S3BucketData


class AwsS3Collector(S3Collector):

    def __init__(self, boto3_wrapper: Boto3Wrapper):
        self._s3 = boto3_wrapper.get_s3()

    def collect(self) -> List[S3BucketData]:
        return self._collect_s3_bucket_data()

    def _collect_s3_bucket_data(self, bucket_name: Optional[str] = None) -> List[S3BucketData]:
        results = []

        if bucket_name:
            buckets = [{'Name': bucket_name}]
        else:
            try:
                buckets = self._s3.list_buckets().get('Buckets', [])
            except botocore.exceptions.ClientError:
                return []

        for bucket in buckets:
            name = bucket['Name']
            bucket_data = self._collect_single_bucket_data(name)
            if bucket_data:
                results.append(bucket_data)

        return results

    def _collect_single_bucket_data(self, bucket_name: str) -> Optional[S3BucketData]:
        pab = acl = policy = cors = website = None
        server_logging = versioning = encryption = mfa_delete = None

        try:
            pab = self._s3.get_public_access_block(Bucket=bucket_name).get("PublicAccessBlockConfiguration", {})
        except botocore.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchPublicAccessBlock":
                return None

        try:
            acl = self._s3.get_bucket_acl(Bucket=bucket_name).get("Grants", [])
        except botocore.exceptions.ClientError:
            pass

        try:
            policy_str = self._s3.get_bucket_policy(Bucket=bucket_name).get("Policy")
            if policy_str:
                try:
                    policy_doc = json.loads(policy_str)
                    policy = IamPolicyData(
                        name=f"{bucket_name}-bucket-policy",
                        policy_type="resource",
                        document=policy_doc,
                        arn=None,
                        is_inline=False
                    )
                except json.JSONDecodeError:
                    pass
        except botocore.exceptions.ClientError:
            pass

        try:
            cors = self._s3.get_bucket_cors(Bucket=bucket_name)
        except botocore.exceptions.ClientError:
            pass

        try:
            website = self._s3.get_bucket_website(Bucket=bucket_name)
        except botocore.exceptions.ClientError:
            pass

        try:
            server_logging = self._s3.get_bucket_logging(Bucket=bucket_name).get("LoggingEnabled", {})
        except botocore.exceptions.ClientError:
            pass

        try:
            versioning = self._s3.get_bucket_versioning(Bucket=bucket_name)
        except botocore.exceptions.ClientError:
            pass

        try:
            encryption = self._s3.get_bucket_encryption(Bucket=bucket_name).get("ServerSideEncryptionConfiguration", {})
        except botocore.exceptions.ClientError:
            pass

        try:
            mfa_delete_status = self._s3.get_bucket_versioning(Bucket=bucket_name).get("MfaDelete")
            mfa_delete = mfa_delete_status == "Enabled" if mfa_delete_status else None
        except botocore.exceptions.ClientError:
            pass

        return S3BucketData(
            name=bucket_name,
            pab_config=pab,
            acl_grants=acl,
            policy=policy,
            cors_config=cors,
            website_config=website,
            server_access_logging=server_logging,
            versioning=versioning,
            encryption=encryption,
            mfa_delete=mfa_delete
        )