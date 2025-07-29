import argparse
from pathlib import Path
import sys

def get_args():
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner")
    subparsers = parser.add_subparsers(dest="command", required=False, help="Scan target")

    subparsers.add_parser("s3", help="Scan S3 buckets")

    iam_parser = subparsers.add_parser("iam", help="Scan IAM roles or policies")
    iam_parser.add_argument("--policies-only", action="store_true",
                            help="Scan only policies without checking trust relationships")
    iam_parser.add_argument("--attached-only", action="store_true",
                            help="Limit scan to only policies attached to roles (requires --policies-only)")
    iam_parser.add_argument("--file", type=Path,
                            help="Path to local IAM policy JSON file (runs in standalone mode)")

    sg_parser = subparsers.add_parser("sg", help="Scan Security Groups")
    sg_parser.add_argument("--regions", type=str, help="Comma-separated list of AWS regions")

    parser.add_argument("--output", type=Path, default=Path("output/report.json"),
                        help="Path to save JSON report")
    parser.add_argument("--html", action="store_true", help="Also generate HTML summary report")

    args = parser.parse_args()

    if args.command == "iam":
        if args.attached_only and not args.policies_only:
            print("Error: --attached-only can only be used together with --policies-only", file=sys.stderr)
            sys.exit(1)

        #if args.file and (args.policies_only or args.attached_only):
        #    print("Error: --file cannot be combined with --policies-only or --attached-only", file=sys.stderr)
        #    sys.exit(1)

    return args
