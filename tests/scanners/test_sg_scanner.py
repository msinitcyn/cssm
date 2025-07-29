from unittest.mock import patch, MagicMock
import botocore.exceptions

def test_find_issues_success():
    mock_sg_config = MagicMock()
    mock_sg_config.regions = ["us-east-1"]

    mock_groups = [
        MagicMock(group_id="sg-1", group_name="test-sg-1"),
        MagicMock(group_id="sg-2", group_name="test-sg-2")
    ]

    mock_findings_1 = [{"type": "open_port", "description": "Port 22 open to 0.0.0.0/0"}]
    mock_findings_2 = [{"type": "cross_account", "description": "Cross account access detected"}]

    with patch("aws_scanner.scanners.sg_scanner.collect_security_groups", return_value=mock_groups) as mock_collect, \
         patch("aws_scanner.scanners.sg_scanner.analyze_sg", side_effect=[mock_findings_1, mock_findings_2]) as mock_analyze:

        from aws_scanner.scanners.sg_scanner import find_issues
        results = find_issues(mock_sg_config)

        assert len(results) == 2
        assert results[0]["group_id"] == "sg-1"
        assert results[0]["group_name"] == "test-sg-1"
        assert results[0]["vulnerabilities"] == mock_findings_1
        assert results[1]["group_id"] == "sg-2"
        assert results[1]["group_name"] == "test-sg-2"
        assert results[1]["vulnerabilities"] == mock_findings_2

        mock_collect.assert_called_once_with(regions=["us-east-1"])
        assert mock_analyze.call_count == 2


def test_find_issues_analyzer_error():
    mock_sg_config = MagicMock()
    mock_sg_config.regions = ["us-east-1"]

    mock_groups = [MagicMock(group_id="sg-1", group_name="test-sg-1")]

    with patch("aws_scanner.scanners.sg_scanner.collect_security_groups", return_value=mock_groups) as mock_collect, \
         patch("aws_scanner.scanners.sg_scanner.analyze_sg", side_effect=Exception("Analysis failed")) as mock_analyze:

        from aws_scanner.scanners.sg_scanner import find_issues
        results = find_issues(mock_sg_config)

        assert len(results) == 1
        assert results[0]["group_id"] == "sg-1"
        assert results[0]["group_name"] == "test-sg-1"
        assert results[0]["error"] == "Analysis failed"

        mock_collect.assert_called_once_with(regions=["us-east-1"])
        mock_analyze.assert_called_once()


def test_run_scanner_success():
    mock_sg_config = MagicMock()
    mock_results = [
        {
            "group_id": "sg-1",
            "group_name": "test-sg-1",
            "vulnerabilities": [{"description": "Port 22 open to 0.0.0.0/0"}]
        }
    ]

    with patch("aws_scanner.scanners.sg_scanner.find_issues", return_value=mock_results) as mock_find_issues, \
         patch("logging.info") as mock_info, \
         patch("logging.warning") as mock_warning:

        from aws_scanner.scanners.sg_scanner import run_scanner
        results = run_scanner(mock_sg_config)

        assert results == mock_results
        mock_find_issues.assert_called_once_with(mock_sg_config)
        mock_info.assert_called_once_with("Starting Security Group scanner")
        mock_warning.assert_called_once_with("SG sg-1 (test-sg-1): Port 22 open to 0.0.0.0/0")


def test_run_scanner_no_credentials():
    mock_sg_config = MagicMock()

    with patch("aws_scanner.scanners.sg_scanner.find_issues", side_effect=botocore.exceptions.NoCredentialsError()), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.sg_scanner import run_scanner
        try:
            run_scanner(mock_sg_config)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("No AWS credentials found")
        mock_exit.assert_called_once_with(1)


def test_run_scanner_connection_error():
    mock_sg_config = MagicMock()

    with patch("aws_scanner.scanners.sg_scanner.find_issues", side_effect=botocore.exceptions.EndpointConnectionError(endpoint_url="https://ec2.us-east-1.amazonaws.com", error="Connection error")), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.sg_scanner import run_scanner
        try:
            run_scanner(mock_sg_config)
        except SystemExit:
            pass

        mock_critical.assert_called_once()
        mock_exit.assert_called_once_with(1)


def test_run_scanner_with_errors():
    mock_sg_config = MagicMock()
    mock_results = [
        {"group_id": "sg-1", "error": "Failed to analyze"},
        {
            "group_id": "sg-2",
            "group_name": "test-sg-2",
            "vulnerabilities": [{"description": "Some vulnerability"}]
        }
    ]

    with patch("aws_scanner.scanners.sg_scanner.find_issues", return_value=mock_results), \
         patch("logging.error") as mock_error, \
         patch("logging.warning") as mock_warning:

        from aws_scanner.scanners.sg_scanner import run_scanner
        results = run_scanner(mock_sg_config)

        assert results == mock_results
        mock_error.assert_called_once_with("Error scanning sg-1: Failed to analyze")
        mock_warning.assert_called_once_with("SG sg-2 (test-sg-2): Some vulnerability")


def test_integration_with_mocks():
    mock_sg_config = MagicMock()
    mock_sg_config.regions = ["us-east-1"]

    mock_groups = [
        MagicMock(group_id="sg-1", group_name="test-sg-1"),
        MagicMock(group_id="sg-2", group_name="test-sg-2")
    ]

    mock_findings_1 = [{"type": "open_port", "raw_data": {"cidr": "0.0.0.0/0"}}]
    mock_findings_2 = [{"type": "cross_account", "raw_data": {"user_id": "2222"}}]

    with patch("aws_scanner.scanners.sg_scanner.collect_security_groups", return_value=mock_groups) as mock_collect, \
         patch("aws_scanner.scanners.sg_scanner.analyze_sg", side_effect=[mock_findings_1, mock_findings_2]) as mock_analyze:

        from aws_scanner.scanners.sg_scanner import find_issues
        results = find_issues(mock_sg_config)

        all_findings = []
        for result in results:
            if "vulnerabilities" in result:
                all_findings.extend(result["vulnerabilities"])

        assert any(f.get("type") == "open_port" and f.get("raw_data", {}).get("cidr") == "0.0.0.0/0" for f in all_findings)
        assert any(f.get("type") == "cross_account" and f.get("raw_data", {}).get("user_id") == "2222" for f in all_findings)
        assert mock_collect.called
        assert mock_analyze.call_count == len(mock_groups)