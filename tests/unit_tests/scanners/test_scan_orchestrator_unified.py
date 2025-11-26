import pytest
from unittest.mock import Mock, patch, call
from pathlib import Path

from aws_scanner.scanners.scan_orchestrator import run_scan
from aws_scanner.core.configs import (
    RunConfig,
    CloudFormationConfig,
    IamPolicyConfig,
    IamRoleConfig,
    S3Config,
    SgConfig,
    ReportConfig
)
from aws_scanner.engines.common.resource_definition import ResourceCollection


@patch("aws_scanner.scanners.scan_orchestrator.generate_report")
@patch("aws_scanner.scanners.scan_orchestrator.scan_cloudformation_template")
def test_cloudformation_path(mock_scan_cf, mock_generate):
    mock_results = {"iam_roles": [{"role_name": "role1", "vulnerabilities": []}]}
    mock_scan_cf.return_value = mock_results

    config = RunConfig(
        cloudformation=CloudFormationConfig(file="/path/to/template.yaml"),
        s3=None,
        iam_role=None,
        iam_policy=None,
        sg=None,
        report=ReportConfig(path=Path("output/report.json"))
    )

    run_scan(config)

    mock_scan_cf.assert_called_once_with("/path/to/template.yaml")
    mock_generate.assert_called_once_with(config.report, mock_results)


@patch("aws_scanner.scanners.scan_orchestrator.generate_report")
@patch("aws_scanner.scanners.scan_orchestrator.format_results")
@patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources")
@patch("aws_scanner.scanners.scan_orchestrator.ResourceFileIamPolicyCollector")
def test_iam_policy_file_path(mock_collector, mock_analyze, mock_format, mock_generate):
    mock_collection = ResourceCollection()
    mock_collector_instance = Mock()
    mock_collector_instance.collect.return_value = mock_collection
    mock_collector.return_value = mock_collector_instance

    mock_findings = [{"entity_type": "iam_policy", "entity_name": "policy1"}]
    mock_analyze.return_value = mock_findings

    mock_formatted = {"iam_roles": [{"role_name": "policy1", "vulnerabilities": []}]}
    mock_format.return_value = mock_formatted

    config = RunConfig(
        cloudformation=None,
        s3=None,
        iam_role=None,
        iam_policy=IamPolicyConfig(file="/path/to/policies.json", attached_only=False),
        sg=None,
        report=ReportConfig(path=Path("output/report.json"))
    )

    run_scan(config)

    mock_collector.assert_called_once_with("/path/to/policies.json")
    mock_collector_instance.collect.assert_called_once()
    mock_analyze.assert_called_once_with(mock_collection)
    mock_format.assert_called_once_with(mock_findings)
    mock_generate.assert_called_once_with(config.report, mock_formatted)


@patch("aws_scanner.scanners.scan_orchestrator.generate_report")
@patch("aws_scanner.scanners.scan_orchestrator.format_results")
@patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources")
@patch("aws_scanner.scanners.scan_orchestrator.ResourceFileIamRoleCollector")
def test_iam_role_file_path(mock_collector, mock_analyze, mock_format, mock_generate):
    mock_collection = ResourceCollection()
    mock_collector_instance = Mock()
    mock_collector_instance.collect.return_value = mock_collection
    mock_collector.return_value = mock_collector_instance

    mock_findings = [{"entity_type": "iam_role", "entity_name": "role1"}]
    mock_analyze.return_value = mock_findings

    mock_formatted = {"iam_roles": [{"role_name": "role1", "vulnerabilities": []}]}
    mock_format.return_value = mock_formatted

    config = RunConfig(
        cloudformation=None,
        s3=None,
        iam_role=IamRoleConfig(file="/path/to/roles.json"),
        iam_policy=None,
        sg=None,
        report=ReportConfig(path=Path("output/report.json"))
    )

    run_scan(config)

    mock_collector.assert_called_once_with("/path/to/roles.json")
    mock_collector_instance.collect.assert_called_once()
    mock_analyze.assert_called_once_with(mock_collection)
    mock_format.assert_called_once_with(mock_findings)
    mock_generate.assert_called_once_with(config.report, mock_formatted)


@patch("aws_scanner.scanners.scan_orchestrator.generate_report")
@patch("aws_scanner.scanners.scan_orchestrator.format_results")
@patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources")
@patch("aws_scanner.scanners.scan_orchestrator.ResourceFileS3Collector")
def test_s3_file_path(mock_collector, mock_analyze, mock_format, mock_generate):
    mock_collection = ResourceCollection()
    mock_collector_instance = Mock()
    mock_collector_instance.collect.return_value = mock_collection
    mock_collector.return_value = mock_collector_instance

    mock_findings = [{"entity_type": "s3_bucket", "entity_name": "bucket1"}]
    mock_analyze.return_value = mock_findings

    mock_formatted = {"s3_buckets": [{"bucket_name": "bucket1", "vulnerabilities": []}]}
    mock_format.return_value = mock_formatted

    config = RunConfig(
        cloudformation=None,
        s3=S3Config(file="/path/to/buckets.json"),
        iam_role=None,
        iam_policy=None,
        sg=None,
        report=ReportConfig(path=Path("output/report.json"))
    )

    run_scan(config)

    mock_collector.assert_called_once_with("/path/to/buckets.json")
    mock_collector_instance.collect.assert_called_once()
    mock_analyze.assert_called_once_with(mock_collection)
    mock_format.assert_called_once_with(mock_findings)
    mock_generate.assert_called_once_with(config.report, mock_formatted)


@patch("aws_scanner.scanners.scan_orchestrator.generate_report")
@patch("aws_scanner.scanners.scan_orchestrator.format_results")
@patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources")
@patch("aws_scanner.scanners.scan_orchestrator.ResourceFileSgCollector")
def test_sg_file_path(mock_collector, mock_analyze, mock_format, mock_generate):
    mock_collection = ResourceCollection()
    mock_collector_instance = Mock()
    mock_collector_instance.collect.return_value = mock_collection
    mock_collector.return_value = mock_collector_instance

    mock_findings = [{"entity_type": "security_group", "entity_name": "sg1"}]
    mock_analyze.return_value = mock_findings

    mock_formatted = {"security_groups": [{"group_name": "sg1", "vulnerabilities": []}]}
    mock_format.return_value = mock_formatted

    config = RunConfig(
        cloudformation=None,
        s3=None,
        iam_role=None,
        iam_policy=None,
        sg=SgConfig(file="/path/to/sgs.json", regions=None),
        report=ReportConfig(path=Path("output/report.json"))
    )

    run_scan(config)

    mock_collector.assert_called_once_with("/path/to/sgs.json")
    mock_collector_instance.collect.assert_called_once()
    mock_analyze.assert_called_once_with(mock_collection)
    mock_format.assert_called_once_with(mock_findings)
    mock_generate.assert_called_once_with(config.report, mock_formatted)
