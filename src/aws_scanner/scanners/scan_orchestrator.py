from .iam_role_scanner import run_scanner as run_iam_role_scanner
from .iam_policy_scanner import run_scanner as run_iam_policy_scanner
from .s3_scanner import run_scanner as run_s3_scanner
from .sg_scanner import run_scanner as run_sg_scanner
from aws_scanner.engines.cloudformation.cloudformation_scanner import scan_cloudformation_template
from aws_scanner.reports.report_generator import generate_report
from aws_scanner.core.boto3_wrapper import Boto3Wrapper

from aws_scanner.core.configs import RunConfig

def run_scan(run_config: RunConfig):

    boto3Wrapper = Boto3Wrapper()
    results = {}

    if run_config.cloudformation:
        results = scan_cloudformation_template(run_config.cloudformation.file)
    else:
        if run_config.s3:
            results["s3_buckets"] = run_s3_scanner(run_config.s3, boto3Wrapper)

        if run_config.iam_role:
            results["iam_roles"] = run_iam_role_scanner(run_config.iam_role, boto3Wrapper)

        if run_config.iam_policy:
            results["iam_policies"] = run_iam_policy_scanner(run_config.iam_policy, boto3Wrapper)

        if run_config.sg:
            results["security_groups"] = run_sg_scanner(run_config.sg, boto3Wrapper)

    generate_report(run_config.report, results)