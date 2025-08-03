import sys
import logging
import botocore.exceptions

from aws_scanner.core.configs import S3Config
from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
from aws_scanner.engines.s3.file_s3_collector import FileS3Collector
from aws_scanner.engines.s3.analyzer import analyze_s3_bucket

from aws_scanner.core.boto3_wrapper import Boto3Wrapper

def get_collector(config: S3Config, boto3_wrapper: Boto3Wrapper):
    if config.file:
        return FileS3Collector(config.file)
    return AwsS3Collector(boto3_wrapper)

def analyze_s3_buckets(items):
    results = []
    for item in items:
        try:
            findings = analyze_s3_bucket(item)
            results.append({
                "bucket_name": item.name,
                "vulnerabilities": findings
            })
        except Exception as e:
            results.append({
                "bucket_name": item.name,
                "error": str(e)
            })
    return results

def run_scanner(s3_config: S3Config, boto3_wrapper: Boto3Wrapper):
    logging.info("Starting S3 scanner")
    try:
        collector = get_collector(s3_config, boto3_wrapper)
        items = collector.collect()
        results = analyze_s3_buckets(items)
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"Connection error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        sys.exit(1)

    for result in results:
        if "error" in result:
            logging.error(f"Error scanning {result.get('bucket_name')}: {result['error']}")
            continue

        for vuln in result.get("vulnerabilities", []):
            logging.warning(f"Bucket {result['bucket_name']}: {vuln.get('description', 'Unknown vulnerability')}")

    return results