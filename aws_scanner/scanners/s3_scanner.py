import boto3
import botocore.exceptions
from .s3.collector import collect_s3_bucket_data
from .s3.analyzer import analyze_s3_bucket

def find_public_s3_buckets(s3=None):
    if s3 is None:
        s3 = boto3.client("s3")

    results = []
    try:
        buckets = s3.list_buckets()["Buckets"]
    except botocore.exceptions.ClientError as e:
        return [{"bucket": "<list_error>", "error": str(e)}]

    for bucket in buckets:
        name = bucket["Name"]
        try:
            bucket_data = collect_s3_bucket_data(s3, name)
            analysis = analyze_s3_bucket(bucket_data)
            results.append(analysis)
        except botocore.exceptions.ClientError as e:
            results.append({"bucket": name, "error": str(e)})

    return results