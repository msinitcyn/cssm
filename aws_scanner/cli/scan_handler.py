import argparse
from pathlib import Path
from aws_scanner.scanners.iam_scanner import run_iam_scanner
from aws_scanner.scanners.s3_scanner import run_s3_scanner
from aws_scanner.scanners.sg_scanner import run_sg_scanner
from aws_scanner.reports.report_generator import generate_report

def get_args():
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--s3-only', action='store_true', help='Scan only S3 buckets')
    group.add_argument('--iam-only', action='store_true', help='Scan only IAM roles')
    group.add_argument('--sg-only', action='store_true', help='Scan only security groups')
    group.add_argument('--all', action='store_true', help='Scan everything (default if no --*-only flags)')

    parser.add_argument('--regions', type=str, help='Comma-separated list of AWS regions to scan (SG only)')
    parser.add_argument('--output', type=Path, default=Path("output/report.json"), help='Path to save JSON report')
    parser.add_argument('--html', action='store_true', help='Also generate HTML summary report')

    return parser.parse_args()

def create_scan_config(args):
    # Determine which scanners are enabled
    run_all = not (args.s3_only or args.iam_only or args.sg_only) or args.all

    config = {}

    if run_all or args.s3_only:
        config["s3"] = {}

    if run_all or args.iam_only:
        config["iam"] = {}

    if run_all or args.sg_only:
        config["sg"] = {
            "regions": args.regions.split(",") if args.regions else None
        }

    config["output"] = {
        "path": args.output.resolve(),
        "html": args.html
    }

    return config

def run_scan():
    args = get_args()
    config = create_scan_config(args)

    results = {}

    if "s3" in config:
        results["s3_buckets"] = run_s3_scanner(config["s3"])

    if "iam" in config:
        results["iam_roles"] = run_iam_scanner(config["iam"])

    if "sg" in config:
        results["security_groups"] = run_sg_scanner(config["sg"])

    generate_report(config["output"], results)

if __name__ == "__main__":
    run_scan()
