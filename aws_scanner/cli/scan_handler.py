import argparse
from pathlib import Path
from aws_scanner.scanners.iam_scanner import run_iam_scanner
from aws_scanner.scanners.s3_scanner import run_s3_scanner
from aws_scanner.scanners.sg_scanner import run_sg_scanner
from aws_scanner.reports.report_generator import generate_report

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

def create_scan_config(args):
    config = {}
    cmd = args.command

    if cmd is None:
        # No subcommand: run all
        config["s3"] = {}
        config["iam"] = {}
        config["sg"] = {}
    else:
        if cmd == "s3":
            config["s3"] = {}
        elif cmd == "iam":
            config["iam"] = {}
        elif cmd == "sg":
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
