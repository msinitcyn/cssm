import argparse
from pathlib import Path

def get_args():
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner")
    subparsers = parser.add_subparsers(dest="command", required=False, help="Scan target")

    subparsers.add_parser("s3", help="Scan S3 buckets")

    subparsers.add_parser("iam", help="Scan IAM roles")

    sg_parser = subparsers.add_parser("sg", help="Scan Security Groups")
    sg_parser.add_argument("--regions", type=str, help="Comma-separated list of AWS regions")

    parser.add_argument("--output", type=Path, default=Path("output/report.json"),
                        help="Path to save JSON report")
    parser.add_argument("--html", action="store_true", help="Also generate HTML summary report")

    return parser.parse_args()