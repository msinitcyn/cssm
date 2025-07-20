import logging
import sys
import botocore.exceptions

from aws_scanner.core.configs import S3Config

from .s3.collector import collect_s3_bucket_data
from .s3.analyzer import analyze_s3_bucket

def find_public_s3_buckets(config : S3Config):
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

def run_s3_scanner(config : S3Config):
    logging.info("Scanning S3 buckets for public access...")
    try:
        results = find_public_s3_buckets(config)
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found. Aborting S3 scan.")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"S3 endpoint error: {e}")
        sys.exit(1)

    for item in results:
        bucket = item["bucket"]
        if item.get("error"):
            logging.warning(f"{bucket}: ERROR — {item['error']}")
        elif item.get("public"):
            logging.warning(f"{bucket} is PUBLIC via {item.get('access_vector')}")
        elif item.get("potentially_public"):
            logging.warning(f"{bucket} is POTENTIALLY public: {item.get('reason')}")
        else:
            logging.info(f"{bucket} is private")
    return results
