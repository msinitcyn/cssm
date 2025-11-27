from aws_scanner.engines.cloudformation.resource_file_cloudformation_collector import ResourceFileCloudFormationCollector
from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector
from aws_scanner.engines.iam_policy.resource_aws_iam_policy_collector import ResourceAwsIamPolicyCollector
from aws_scanner.engines.iam_role.resource_file_iam_role_collector import ResourceFileIamRoleCollector
from aws_scanner.engines.iam_role.resource_aws_iam_role_collector import ResourceAwsIamRoleCollector
from aws_scanner.engines.s3.resource_file_s3_collector import ResourceFileS3Collector
from aws_scanner.engines.s3.resource_aws_s3_collector import ResourceAwsS3Collector
from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector
from aws_scanner.engines.sg.resource_aws_security_group_collector import ResourceAwsSecurityGroupCollector
from aws_scanner.core import resource_orchestrator
from aws_scanner.core.result_formatter import format_results
from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.reports.report_generator import generate_report
from aws_scanner.core.configs import RunConfig


def _get_collector(config: RunConfig, boto3_wrapper):
    if config.cloudformation:
        return ResourceFileCloudFormationCollector(config.cloudformation.file)

    if config.iam_policy:
        if config.iam_policy.file:
            return ResourceFileIamPolicyCollector(config.iam_policy.file)
        else:
            return ResourceAwsIamPolicyCollector(boto3_wrapper, config.iam_policy.attached_only)

    if config.iam_role:
        if config.iam_role.file:
            return ResourceFileIamRoleCollector(config.iam_role.file)
        else:
            return ResourceAwsIamRoleCollector(boto3_wrapper)

    if config.s3:
        if config.s3.file:
            return ResourceFileS3Collector(config.s3.file)
        else:
            return ResourceAwsS3Collector(boto3_wrapper, None)

    if config.sg:
        if config.sg.file:
            return ResourceFileSgCollector(config.sg.file)
        else:
            return ResourceAwsSecurityGroupCollector(boto3_wrapper, config.sg.regions)


def run_scan(run_config: RunConfig):
    boto3_wrapper = Boto3Wrapper()
    collector = _get_collector(run_config, boto3_wrapper)
    collection = collector.collect()
    findings = resource_orchestrator.analyze_resources(collection)
    results = format_results(findings)

    generate_report(run_config.report, results)
