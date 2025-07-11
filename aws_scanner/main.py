import json
import argparse
import logging
import sys
from pathlib import Path
import botocore.exceptions

from scanners.s3_scanner import find_public_s3_buckets
from scanners.iam_scanner import find_overpermissive_roles
from scanners.sg_scanner import find_open_security_groups

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

def scan_s3():
    logging.info("Scanning S3 buckets for public access...")
    try:
        results = find_public_s3_buckets()
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
            logging.warning(f"{bucket} is PUBLIC")
        else:
            logging.info(f"{bucket} is private")
    return results

def scan_iam():
    logging.info("Scanning IAM roles for over-permissive policies...")
    try:
        results = find_overpermissive_roles()
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found. Aborting IAM scan.")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"IAM endpoint error: {e}")
        sys.exit(1)

    for item in results:
        role = item.get("role", "<unknown>")
        error = item.get("error")
        policy_type = item.get("policy_type", "")
        policy_name = item.get("policy_name", "")
        if error:
            logging.warning(f"{role}: ERROR — {error}")
        else:
            logging.warning(f"{role}: {policy_type} policy '{policy_name}' is over-permissive")
    return results

def scan_sg():
    logging.info("Scanning security groups for open ports...")
    try:
        results = find_open_security_groups()
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found. Aborting SG scan.")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"SG endpoint error: {e}")
        sys.exit(1)

    for item in results:
        if "error" in item:
            logging.warning(f"Security group scan error: {item['error']}")
            continue
        group_id = item.get("group_id", "<unknown>")
        group_name = item.get("group_name", "")
        from_port = item.get("from_port")
        cidr = item.get("cidr")
        logging.warning(f"{group_id} ({group_name}): Port {from_port} open to {cidr}")
    return results

def main():
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--s3-only', action='store_true', help='Scan only S3 buckets')
    group.add_argument('--iam-only', action='store_true', help='Scan only IAM roles')
    group.add_argument('--sg-only', action='store_true', help='Scan only security groups')
    group.add_argument('--all', action='store_true', help='Scan everything (default)')

    args = parser.parse_args()
    output = {}

    if args.s3_only:
        output["s3_public_buckets"] = scan_s3()
    elif args.iam_only:
        output["overpermissive_iam_roles"] = scan_iam()
    elif args.sg_only:
        output["sg_open_ports"] = scan_sg()
    else:
        output["s3_public_buckets"] = scan_s3()
        output["overpermissive_iam_roles"] = scan_iam()
        output["sg_open_ports"] = scan_sg()

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "report.json"

    with report_path.open("w") as f:
        json.dump(output, f, indent=2)

    logging.info(f"Report saved to {report_path.resolve()}")

if __name__ == "__main__":
    main()
