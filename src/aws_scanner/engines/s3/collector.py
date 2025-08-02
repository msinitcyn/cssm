import botocore.exceptions
import json

from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.engines.common.iam_policy_data import IamPolicyData
from .s3_bucket_data import S3BucketData

def collect_s3_bucket_data(bucket_name:str=None):
    s3 = Boto3Wrapper().get_s3()
    results = []

    if bucket_name:
        buckets = [{'Name': bucket_name}]
    else:
        try:
            buckets = s3.list_buckets().get('Buckets', [])
        except botocore.exceptions.ClientError:
            return []

    for bucket in buckets:
        name = bucket['Name']
        pab = acl = policy = cors = website = None

        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
        except botocore.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchPublicAccessBlock":
                continue

        try:
            acl = s3.get_bucket_acl(Bucket=name).get("Grants", [])
        except botocore.exceptions.ClientError:
            pass

        policy = None
        try:
            policy_str = s3.get_bucket_policy(Bucket=name).get("Policy")
            if policy_str:
                try:
                    policy = IamPolicyData(
                        name=f"{name}-bucket-policy",
                        policy_type="resource",
                        document=json.loads(policy_str),
                        arn=None,
                        is_inline=False
                    )
                except json.JSONDecodeError:
                    pass
        except botocore.exceptions.ClientError:
            pass

        try:
            cors = s3.get_bucket_cors(Bucket=name)
        except botocore.exceptions.ClientError:
            pass

        try:
            website = s3.get_bucket_website(Bucket=name)
        except botocore.exceptions.ClientError:
            pass

        results.append(S3BucketData(
            name=name,
            pab_config=pab,
            acl_grants=acl,
            policy=policy,
            cors_config=cors,
            website_config=website
        ))
    
    return results