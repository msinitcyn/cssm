from aws_scanner.engines.cloudformation.cloudformation_scanner import scan_cloudformation_template
from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector
from aws_scanner.engines.iam_role.resource_file_iam_role_collector import ResourceFileIamRoleCollector
from aws_scanner.engines.s3.resource_file_s3_collector import ResourceFileS3Collector
from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector
from aws_scanner.core import resource_orchestrator
from aws_scanner.core.result_formatter import format_results
from aws_scanner.reports.report_generator import generate_report
from aws_scanner.core.configs import RunConfig


def _get_collector(config: RunConfig):
    if config.iam_policy:
        if config.iam_policy.file:
            return ResourceFileIamPolicyCollector(config.iam_policy.file)
        else:
            raise NotImplementedError("AWS API scanning not yet migrated to resource path")

    if config.iam_role:
        if config.iam_role.file:
            return ResourceFileIamRoleCollector(config.iam_role.file)
        else:
            raise NotImplementedError("AWS API scanning not yet migrated to resource path")

    if config.s3:
        if config.s3.file:
            return ResourceFileS3Collector(config.s3.file)
        else:
            raise NotImplementedError("AWS API scanning not yet migrated to resource path")

    if config.sg:
        if config.sg.file:
            return ResourceFileSgCollector(config.sg.file)
        else:
            raise NotImplementedError("AWS API scanning not yet migrated to resource path")


def run_scan(run_config: RunConfig):
    if run_config.cloudformation:
        results = scan_cloudformation_template(run_config.cloudformation.file)
    else:
        collector = _get_collector(run_config)
        collection = collector.collect()
        findings = resource_orchestrator.analyze_resources(collection)
        results = format_results(findings)

    generate_report(run_config.report, results)
