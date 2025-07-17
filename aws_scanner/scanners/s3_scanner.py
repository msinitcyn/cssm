import botocore.exceptions

from .s3.collector import collect_s3_bucket_data
from .s3.analyzer import analyze_s3_bucket

def find_public_s3_buckets(s3_client=None):
    results = []

    try:
        buckets_data = collect_s3_bucket_data(bucket_name=None)

        for bucket_data in buckets_data:
            try:
                analysis = analyze_s3_bucket(bucket_data)
                results.append(analysis)
            except botocore.exceptions.ClientError as e:
                bucket_name = bucket_data.get('Name', '<unknown>')
                results.append({
                    "bucket": bucket_name,
                    "error": str(e)
                })

    except botocore.exceptions.ClientError as e:
        results.append({
            "bucket": "<collection_error>",
            "error": str(e)
        })

    return results