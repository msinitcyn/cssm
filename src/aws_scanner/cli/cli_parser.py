import argparse
from pathlib import Path
import sys

def get_args():
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner", add_help=False)

    parser.add_argument("--output", type=Path, default=Path("output/report.json"),
                        help="Path to save JSON report")
    parser.add_argument("--html", action="store_true", help="Also generate HTML summary report")
    parser.add_argument("command", nargs='?', choices=['s3', 'iam', 'sg'], help="Scan target")

    args, remaining = parser.parse_known_args()

    if args.command == "iam":
        iam_parser = argparse.ArgumentParser(description="Scan IAM roles or policies")
        iam_parser.add_argument("--policies", action="store_true",
                                help="Scan only policies without checking trust relationships")
        iam_parser.add_argument("--attached-only", action="store_true",
                                help="Limit scan to only policies attached to roles (requires --policies)")
        iam_parser.add_argument("--file", type=Path,
                                help="Path to local IAM policy JSON file (runs in standalone mode)")
        iam_args = iam_parser.parse_args(remaining)

        if iam_args.attached_only and not iam_args.policies:
            print("Error: --attached-only can only be used together with --policies", file=sys.stderr)
            sys.exit(1)

        return argparse.Namespace(**vars(args), **vars(iam_args))

    elif args.command == "sg":
        sg_parser = argparse.ArgumentParser(description="Scan Security Groups")
        sg_parser.add_argument("--regions", type=str, help="Comma-separated list of AWS regions")
        sg_parser.add_argument("--file", type=Path, help="Path to local Security Group configuration JSON file")
        sg_args = sg_parser.parse_args(remaining)
        return argparse.Namespace(**vars(args), **vars(sg_args))

    elif args.command == "s3":
        s3_parser = argparse.ArgumentParser(description="Scan S3 buckets")
        s3_parser.add_argument("--file", type=Path, help="Path to local S3 configuration JSON file")
        s3_args = s3_parser.parse_args(remaining)
        return argparse.Namespace(**vars(args), **vars(s3_args))

    else:
        parser.print_help()
        sys.exit(1)