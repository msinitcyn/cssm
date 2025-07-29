import sys
import logging
import botocore.exceptions

from aws_scanner.core.configs import S3Config
from aws_scanner.engines.s3.collector import collect_s3_bucket_data
from aws_scanner.engines.s3.analyzer import analyze_s3_bucket

def find_issues(s3_config: S3Config):
    results = []
    items = collect_s3_bucket_data()
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

def run_scanner(s3_config: S3Config):
    logging.info("Starting S3 scanner")
    try:
        results = find_issues(s3_config)
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