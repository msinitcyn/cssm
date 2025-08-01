from unittest.mock import patch, MagicMock
import botocore.exceptions

def test_analyze_policies_success():
    mock_role1 = MagicMock()
    mock_role1.name = "role1"
    mock_role2 = MagicMock()
    mock_role2.name = "role2"
    mock_items = [mock_role1, mock_role2]

    mock_findings1 = [{"type": "trust_policy", "description": "Overly permissive trust policy"}]
    mock_findings2 = [{"type": "permissions", "description": "Excessive permissions"}]

    with patch("aws_scanner.scanners.iam_role_scanner.analyze_iam_role", side_effect=[mock_findings1, mock_findings2]):
        from aws_scanner.scanners.iam_role_scanner import analyze_policies
        results = analyze_policies(mock_items)

        assert len(results) == 2
        assert results[0]["role_name"] == "role1"
        assert results[0]["vulnerabilities"] == mock_findings1
        assert results[1]["role_name"] == "role2"
        assert results[1]["vulnerabilities"] == mock_findings2

def test_analyze_policies_analyzer_error():
    mock_role = MagicMock()
    mock_role.name = "test-role"
    mock_items = [mock_role]

    with patch("aws_scanner.scanners.iam_role_scanner.analyze_iam_role", side_effect=Exception("Analysis error")):
        from aws_scanner.scanners.iam_role_scanner import analyze_policies
        results = analyze_policies(mock_items)

        assert len(results) == 1
        assert results[0]["role_name"] == "test-role"
        assert results[0]["error"] == "Analysis error"

def test_get_collector_file():
    mock_config = MagicMock()
    mock_config.file = "test_file.json"
    mock_boto3_wrapper = MagicMock()

    with patch("aws_scanner.scanners.iam_role_scanner.FileIamRoleCollector") as mock_file_collector:
        from aws_scanner.scanners.iam_role_scanner import get_collector
        collector = get_collector(mock_config, mock_boto3_wrapper)
        
        mock_file_collector.assert_called_once_with("test_file.json")

def test_get_collector_aws():
    mock_config = MagicMock()
    mock_config.file = None
    mock_boto3_wrapper = MagicMock()

    with patch("aws_scanner.scanners.iam_role_scanner.AwsIamRoleCollector") as mock_aws_collector:
        from aws_scanner.scanners.iam_role_scanner import get_collector
        collector = get_collector(mock_config, mock_boto3_wrapper)
        
        mock_aws_collector.assert_called_once_with(mock_boto3_wrapper)

def test_run_scanner_success():
    mock_config = MagicMock()
    mock_boto3_wrapper = MagicMock()
    mock_collector = MagicMock()
    mock_items = [MagicMock()]
    mock_collector.collect.return_value = mock_items
    
    mock_results = [{
        "role_name": "test-role",
        "vulnerabilities": [{"description": "Overly permissive trust policy"}]
    }]

    with patch("aws_scanner.scanners.iam_role_scanner.get_collector", return_value=mock_collector), \
         patch("aws_scanner.scanners.iam_role_scanner.analyze_policies", return_value=mock_results), \
         patch("logging.info"), \
         patch("logging.warning"):

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        results = run_scanner(mock_config, mock_boto3_wrapper)
        assert results == mock_results

def test_run_scanner_no_credentials():
    mock_config = MagicMock()
    mock_boto3_wrapper = MagicMock()
    mock_collector = MagicMock()
    mock_collector.collect.side_effect = botocore.exceptions.NoCredentialsError()

    with patch("aws_scanner.scanners.iam_role_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("No AWS credentials found")
        mock_exit.assert_called_once_with(1)

def test_run_scanner_connection_error():
    mock_config = MagicMock()
    mock_boto3_wrapper = MagicMock()
    mock_collector = MagicMock()
    mock_collector.collect.side_effect = botocore.exceptions.EndpointConnectionError(endpoint_url="test", error="Error")

    with patch("aws_scanner.scanners.iam_role_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once()
        mock_exit.assert_called_once_with(1)

def test_run_scanner_unexpected_error():
    mock_config = MagicMock()
    mock_boto3_wrapper = MagicMock()
    mock_collector = MagicMock()
    mock_collector.collect.side_effect = Exception("Unexpected error")

    with patch("aws_scanner.scanners.iam_role_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("Unexpected error: Unexpected error")
        mock_exit.assert_called_once_with(1)

def test_run_scanner_with_errors():
    mock_config = MagicMock()
    mock_boto3_wrapper = MagicMock()
    mock_collector = MagicMock()
    mock_items = [MagicMock()]
    mock_collector.collect.return_value = mock_items
    
    mock_results = [
        {"role_name": "role1", "error": "Scan error"},
        {
            "role_name": "role2",
            "vulnerabilities": [{"description": "Some vulnerability"}]
        }
    ]

    with patch("aws_scanner.scanners.iam_role_scanner.get_collector", return_value=mock_collector), \
         patch("aws_scanner.scanners.iam_role_scanner.analyze_policies", return_value=mock_results), \
         patch("logging.error"), \
         patch("logging.warning"):

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        results = run_scanner(mock_config, mock_boto3_wrapper)
        assert results == mock_results

def test_integration_with_mocks():
    mock_role1 = MagicMock()
    mock_role1.name = "role1"
    mock_role2 = MagicMock()
    mock_role2.name = "role2"
    mock_items = [mock_role1, mock_role2]

    mock_findings1 = [{"type": "trust_policy", "raw_data": {"policy": "permissive"}}]
    mock_findings2 = [{"type": "permissions", "raw_data": {"actions": ["*"]}}]

    with patch("aws_scanner.scanners.iam_role_scanner.analyze_iam_role", side_effect=[mock_findings1, mock_findings2]):
        from aws_scanner.scanners.iam_role_scanner import analyze_policies
        results = analyze_policies(mock_items)

        all_findings = []
        for result in results:
            if "vulnerabilities" in result:
                all_findings.extend(result["vulnerabilities"])

        assert any(f.get("type") == "trust_policy" for f in all_findings)
        assert any(f.get("type") == "permissions" for f in all_findings)