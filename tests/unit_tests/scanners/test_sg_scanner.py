from unittest.mock import patch, MagicMock
import botocore.exceptions

from aws_scanner.engines.sg.sg_data import SgData
from aws_scanner.core.configs import SgConfig
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


def test_get_collector_file():
    mock_config = MagicMock()
    mock_config.file = "test_file.json"
    mock_config.regions = ["us-east-1"]
    mock_boto3_wrapper = MagicMock()

    with patch("aws_scanner.scanners.sg_scanner.FileSgCollector") as mock_file_collector:
        from aws_scanner.scanners.sg_scanner import get_collector
        get_collector(mock_config, mock_boto3_wrapper)

        mock_file_collector.assert_called_once_with("test_file.json")


def test_get_collector_aws():
    mock_config = MagicMock()
    mock_config.file = None
    mock_config.regions = ["us-east-1"]
    mock_boto3_wrapper = MagicMock()

    with patch("aws_scanner.scanners.sg_scanner.AwsSgCollector") as mock_aws_collector:
        from aws_scanner.scanners.sg_scanner import get_collector
        get_collector(mock_config, mock_boto3_wrapper)

        mock_aws_collector.assert_called_once_with(mock_boto3_wrapper, ["us-east-1"])


def test_analyze_security_groups_success():
    mock_sg1 = MagicMock(spec=SgData)
    mock_sg1.group_id = "sg-123"
    mock_sg1.group_name = "group1"
    mock_sg2 = MagicMock(spec=SgData)
    mock_sg2.group_id = "sg-456"
    mock_sg2.group_name = "group2"

    mock_findings1 = [{"type": "open_port", "description": "Open port 22"}]
    mock_findings2 = [{"type": "wide_open", "description": "0.0.0.0/0 access"}]

    with patch("aws_scanner.scanners.sg_scanner.analyze_sg",
              side_effect=[mock_findings1, mock_findings2]):
        from aws_scanner.scanners.sg_scanner import analyze_security_groups
        results = analyze_security_groups([mock_sg1, mock_sg2])

        assert len(results) == 2
        assert results[0]["group_id"] == "sg-123"
        assert results[0]["group_name"] == "group1"
        assert results[0]["vulnerabilities"] == mock_findings1
        assert results[1]["group_id"] == "sg-456"
        assert results[1]["group_name"] == "group2"
        assert results[1]["vulnerabilities"] == mock_findings2


def test_analyze_security_groups_with_error():
    mock_sg = MagicMock(spec=SgData)
    mock_sg.group_id = "sg-err"
    mock_sg.group_name = "error-group"

    with patch("aws_scanner.scanners.sg_scanner.analyze_sg",
              side_effect=Exception("Test error")):
        from aws_scanner.scanners.sg_scanner import analyze_security_groups
        results = analyze_security_groups([mock_sg])

        assert len(results) == 1
        assert results[0]["group_id"] == "sg-err"
        assert results[0]["group_name"] == "error-group"
        assert results[0]["error"] == "Test error"


def test_run_scanner_success():
    mock_config = MagicMock(spec=SgConfig)
    mock_config.regions = ["us-east-1"]
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)

    mock_sg = MagicMock(spec=SgData)
    mock_sg.group_id = "sg-123"
    mock_sg.group_name = "test-group"
    mock_findings = [{"description": "Test finding"}]

    with patch("aws_scanner.scanners.sg_scanner.get_collector") as mock_get_collector, \
         patch("aws_scanner.scanners.sg_scanner.analyze_security_groups", return_value=[{
             "group_id": "sg-123",
             "group_name": "test-group",
             "vulnerabilities": mock_findings
         }]), \
         patch("logging.info") as mock_info:

        mock_collector = MagicMock()
        mock_collector.collect.return_value = [mock_sg]
        mock_get_collector.return_value = mock_collector

        from aws_scanner.scanners.sg_scanner import run_scanner
        results = run_scanner(mock_config, mock_boto3_wrapper)

        assert len(results) == 1
        assert results[0]["group_id"] == "sg-123"
        mock_info.assert_called_once_with("Starting Security Group scanner")


def test_run_scanner_no_credentials():
    mock_config = MagicMock(spec=SgConfig)
    mock_config.regions = ["us-east-1"]
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_collector = MagicMock()
    mock_collector.collect.side_effect = botocore.exceptions.NoCredentialsError()

    with patch("aws_scanner.scanners.sg_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.sg_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("No AWS credentials found")
        mock_exit.assert_called_once_with(1)


def test_run_scanner_connection_error():
    mock_config = MagicMock(spec=SgConfig)
    mock_config.regions = ["us-east-1"]
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)

    mock_collector = MagicMock()
    mock_collector.collect.side_effect = botocore.exceptions.EndpointConnectionError(
        endpoint_url="test",
        error="Connection error"
    )

    with patch("aws_scanner.scanners.sg_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.sg_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once()
        mock_exit.assert_called_once_with(1)


def test_run_scanner_unexpected_error():
    mock_config = MagicMock(spec=SgConfig)
    mock_config.regions = ["us-east-1"]
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)

    mock_collector = MagicMock()
    mock_collector.collect.side_effect = Exception("Unexpected error")

    with patch("aws_scanner.scanners.sg_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.sg_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("Unexpected error: Unexpected error")
        mock_exit.assert_called_once_with(1)


def test_run_scanner_with_errors():
    mock_config = MagicMock(spec=SgConfig)
    mock_config.regions = ["us-east-1"]
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)

    mock_results = [
        {"group_id": "sg-err", "group_name": "error-group", "error": "Scan error"},
        {
            "group_id": "sg-ok",
            "group_name": "good-group",
            "vulnerabilities": [{"description": "Some vulnerability"}]
        }
    ]

    with patch("aws_scanner.scanners.sg_scanner.get_collector") as mock_get_collector, \
         patch("aws_scanner.scanners.sg_scanner.analyze_security_groups", return_value=mock_results):

        mock_collector = MagicMock()
        mock_collector.collect.return_value = [MagicMock(), MagicMock()]
        mock_get_collector.return_value = mock_collector

        from aws_scanner.scanners.sg_scanner import run_scanner
        results = run_scanner(mock_config, mock_boto3_wrapper)

        assert results == mock_results


def test_integration_with_mocks():
    mock_sg1 = MagicMock(spec=SgData)
    mock_sg1.group_id = "sg-123"
    mock_sg1.group_name = "group1"
    mock_sg2 = MagicMock(spec=SgData)
    mock_sg2.group_id = "sg-456"
    mock_sg2.group_name = "group2"

    mock_findings1 = [{"type": "open_port", "raw_data": {"port": 22}}]
    mock_findings2 = [{"type": "wide_open", "raw_data": {"cidr": "0.0.0.0/0"}}]

    with patch("aws_scanner.scanners.sg_scanner.analyze_sg",
              side_effect=[mock_findings1, mock_findings2]):
        from aws_scanner.scanners.sg_scanner import analyze_security_groups
        results = analyze_security_groups([mock_sg1, mock_sg2])

        all_findings = []
        for result in results:
            if "vulnerabilities" in result:
                all_findings.extend(result["vulnerabilities"])

        assert any(f.get("type") == "open_port" for f in all_findings)
        assert any(f.get("type") == "wide_open" for f in all_findings)