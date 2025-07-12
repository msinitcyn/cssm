import boto3
import botocore.exceptions
from .s3_bucket_data import S3BucketData

def collect_s3_bucket_data(s3, bucket_name):
    pab = acl = policy = cors = website = None

    try:
        pab = s3.get_public_access_block(Bucket=bucket_name).get("PublicAccessBlockConfiguration", {})
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NoSuchPublicAccessBlock":
            raise

    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name).get("Grants", [])
    except botocore.exceptions.ClientError:
        pass

    try:
        policy_str = s3.get_bucket_policy(Bucket=bucket_name).get("Policy")
        if policy_str:
            import json
            policy = json.loads(policy_str)
    except botocore.exceptions.ClientError:
        pass

    try:
        cors = s3.get_bucket_cors(Bucket=bucket_name)
    except botocore.exceptions.ClientError:
        pass

    try:
        website = s3.get_bucket_website(Bucket=bucket_name)
    except botocore.exceptions.ClientError:
        pass

    return S3BucketData(
        name=bucket_name,
        pab_config=pab,
        acl_grants=acl,
        policy_doc=policy,
        cors_config=cors,
        website_config=website
    )