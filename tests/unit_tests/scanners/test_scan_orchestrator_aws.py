from unittest.mock import MagicMock, patch
from aws_scanner.core.configs import RunConfig, IamPolicyConfig, IamRoleConfig, S3Config, SgConfig, ReportConfig
from aws_scanner.scanners.scan_orchestrator import run_scan


def test_iam_policy_aws_path():
    config = RunConfig(
        iam_policy=IamPolicyConfig(attached_only=True, file=None),
        iam_role=None,
        s3=None,
        sg=None,
        cloudformation=None,
        report=ReportConfig()
    )

    with patch("aws_scanner.scanners.scan_orchestrator.Boto3Wrapper") as mock_boto3_wrapper_class, \
         patch("aws_scanner.scanners.scan_orchestrator.ResourceAwsIamPolicyCollector") as mock_collector, \
         patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources") as mock_analyze, \
         patch("aws_scanner.scanners.scan_orchestrator.format_results") as mock_format, \
         patch("aws_scanner.scanners.scan_orchestrator.generate_report") as mock_report:

        mock_boto3_wrapper_instance = MagicMock()
        mock_boto3_wrapper_class.return_value = mock_boto3_wrapper_instance
        mock_collector_instance = MagicMock()
        mock_collector.return_value = mock_collector_instance
        mock_collection = MagicMock()
        mock_collector_instance.collect.return_value = mock_collection
        mock_findings = [{"finding": "test"}]
        mock_analyze.return_value = mock_findings
        mock_results = [{"result": "test"}]
        mock_format.return_value = mock_results

        run_scan(config)

        mock_boto3_wrapper_class.assert_called_once()
        mock_collector.assert_called_once_with(mock_boto3_wrapper_instance, True)
        mock_collector_instance.collect.assert_called_once()
        mock_analyze.assert_called_once_with(mock_collection)
        mock_format.assert_called_once_with(mock_findings)
        mock_report.assert_called_once()


def test_iam_role_aws_path():
    config = RunConfig(
        iam_policy=None,
        iam_role=IamRoleConfig(file=None),
        s3=None,
        sg=None,
        cloudformation=None,
        report=ReportConfig()
    )

    with patch("aws_scanner.scanners.scan_orchestrator.Boto3Wrapper") as mock_boto3_wrapper_class, \
         patch("aws_scanner.scanners.scan_orchestrator.ResourceAwsIamRoleCollector") as mock_collector, \
         patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources") as mock_analyze, \
         patch("aws_scanner.scanners.scan_orchestrator.format_results") as mock_format, \
         patch("aws_scanner.scanners.scan_orchestrator.generate_report") as mock_report:

        mock_boto3_wrapper_instance = MagicMock()
        mock_boto3_wrapper_class.return_value = mock_boto3_wrapper_instance
        mock_collector_instance = MagicMock()
        mock_collector.return_value = mock_collector_instance
        mock_collection = MagicMock()
        mock_collector_instance.collect.return_value = mock_collection
        mock_findings = [{"finding": "test"}]
        mock_analyze.return_value = mock_findings
        mock_results = [{"result": "test"}]
        mock_format.return_value = mock_results

        run_scan(config)

        mock_boto3_wrapper_class.assert_called_once()
        mock_collector.assert_called_once_with(mock_boto3_wrapper_instance)
        mock_collector_instance.collect.assert_called_once()
        mock_analyze.assert_called_once_with(mock_collection)
        mock_format.assert_called_once_with(mock_findings)
        mock_report.assert_called_once()


def test_s3_aws_path():
    config = RunConfig(
        iam_policy=None,
        iam_role=None,
        s3=S3Config(file=None),
        sg=None,
        cloudformation=None,
        report=ReportConfig()
    )

    with patch("aws_scanner.scanners.scan_orchestrator.Boto3Wrapper") as mock_boto3_wrapper_class, \
         patch("aws_scanner.scanners.scan_orchestrator.ResourceAwsS3Collector") as mock_collector, \
         patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources") as mock_analyze, \
         patch("aws_scanner.scanners.scan_orchestrator.format_results") as mock_format, \
         patch("aws_scanner.scanners.scan_orchestrator.generate_report") as mock_report:

        mock_boto3_wrapper_instance = MagicMock()
        mock_boto3_wrapper_class.return_value = mock_boto3_wrapper_instance
        mock_collector_instance = MagicMock()
        mock_collector.return_value = mock_collector_instance
        mock_collection = MagicMock()
        mock_collector_instance.collect.return_value = mock_collection
        mock_findings = [{"finding": "test"}]
        mock_analyze.return_value = mock_findings
        mock_results = [{"result": "test"}]
        mock_format.return_value = mock_results

        run_scan(config)

        mock_boto3_wrapper_class.assert_called_once()
        mock_collector.assert_called_once_with(mock_boto3_wrapper_instance, None)
        mock_collector_instance.collect.assert_called_once()
        mock_analyze.assert_called_once_with(mock_collection)
        mock_format.assert_called_once_with(mock_findings)
        mock_report.assert_called_once()


def test_sg_aws_path():
    config = RunConfig(
        iam_policy=None,
        iam_role=None,
        s3=None,
        sg=SgConfig(regions=["us-east-1"], file=None),
        cloudformation=None,
        report=ReportConfig()
    )

    with patch("aws_scanner.scanners.scan_orchestrator.Boto3Wrapper") as mock_boto3_wrapper_class, \
         patch("aws_scanner.scanners.scan_orchestrator.ResourceAwsSecurityGroupCollector") as mock_collector, \
         patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources") as mock_analyze, \
         patch("aws_scanner.scanners.scan_orchestrator.format_results") as mock_format, \
         patch("aws_scanner.scanners.scan_orchestrator.generate_report") as mock_report:

        mock_boto3_wrapper_instance = MagicMock()
        mock_boto3_wrapper_class.return_value = mock_boto3_wrapper_instance
        mock_collector_instance = MagicMock()
        mock_collector.return_value = mock_collector_instance
        mock_collection = MagicMock()
        mock_collector_instance.collect.return_value = mock_collection
        mock_findings = [{"finding": "test"}]
        mock_analyze.return_value = mock_findings
        mock_results = [{"result": "test"}]
        mock_format.return_value = mock_results

        run_scan(config)

        mock_boto3_wrapper_class.assert_called_once()
        mock_collector.assert_called_once_with(mock_boto3_wrapper_instance, ["us-east-1"])
        mock_collector_instance.collect.assert_called_once()
        mock_analyze.assert_called_once_with(mock_collection)
        mock_format.assert_called_once_with(mock_findings)
        mock_report.assert_called_once()


def test_boto3_wrapper_passed_to_collectors():
    config = RunConfig(
        iam_policy=IamPolicyConfig(attached_only=False, file=None),
        iam_role=None,
        s3=None,
        sg=None,
        cloudformation=None,
        report=ReportConfig()
    )

    with patch("aws_scanner.scanners.scan_orchestrator.Boto3Wrapper") as mock_boto3_wrapper_class, \
         patch("aws_scanner.scanners.scan_orchestrator.ResourceAwsIamPolicyCollector") as mock_collector, \
         patch("aws_scanner.scanners.scan_orchestrator.resource_orchestrator.analyze_resources") as mock_analyze, \
         patch("aws_scanner.scanners.scan_orchestrator.format_results") as mock_format, \
         patch("aws_scanner.scanners.scan_orchestrator.generate_report") as mock_report:

        mock_boto3_wrapper_instance = MagicMock()
        mock_boto3_wrapper_class.return_value = mock_boto3_wrapper_instance
        mock_collector_instance = MagicMock()
        mock_collector.return_value = mock_collector_instance
        mock_collector_instance.collect.return_value = MagicMock()
        mock_analyze.return_value = []
        mock_format.return_value = []

        run_scan(config)

        mock_collector.assert_called_once_with(mock_boto3_wrapper_instance, False)
