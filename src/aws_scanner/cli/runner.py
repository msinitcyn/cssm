from aws_scanner.scanners.iam_scanner import run_iam_scanner
from aws_scanner.scanners.s3_scanner import run_s3_scanner
from aws_scanner.scanners.sg_scanner import run_sg_scanner
from aws_scanner.reports.report_generator import generate_report

from aws_scanner.core.configs import RunConfig

def run_scan(runConfig: RunConfig):

    results = {}

    if runConfig.s3:
        results["s3_buckets"] = run_s3_scanner(runConfig.s3)

    if runConfig.iam:
        results["iam_roles"] = run_iam_scanner(runConfig.iam)

    if runConfig.sg:
        results["security_groups"] = run_sg_scanner(runConfig.sg)

    generate_report(runConfig.report, results)
