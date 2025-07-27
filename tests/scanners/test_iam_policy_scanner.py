from unittest.mock import patch, MagicMock
import botocore.exceptions
import pytest

def test_analyze_policies_success():
    mock_policy1 = MagicMock()
    mock_policy1.arn = "arn:aws:iam::123456789012:policy/policy1"
    mock_policy1.name = "policy1"
    mock_policy2 = MagicMock()
    mock_policy2.arn = "arn:aws:iam::123456789012:policy/policy2"
    mock_policy2.name = "policy2"
    mock_policies = [mock_policy1, mock_policy2]

    mock_findings1 = [{"type": "wildcard_actions", "description": "Policy uses wildcard actions"}]
    mock_findings2 = [{"type": "overprivileged", "description": "Policy has excessive permissions"}]

    with patch("aws_scanner.scanners.iam_policy_scanner.analyze_policy", side_effect=[mock_findings1, mock_findings2]):

        from aws_scanner.scanners.iam_policy_scanner import analyze_policies
        results = analyze_policies(mock_policies)

        assert len(results) == 2
        assert results[0]["policy_arn"] == "arn:aws:iam::123456789012:policy/policy1"
        assert results[0]["policy_name"] == "policy1"
        assert results[0]["vulnerabilities"] == mock_findings1
        assert results[1]["policy_arn"] == "arn:aws:iam::123456789012:policy/policy2"
        assert results[1]["policy_name"] == "policy2"
        assert results[1]["vulnerabilities"] == mock_findings2

def test_analyze_policies_error():
    mock_policy = MagicMock()
    mock_policy.arn = "arn:aws:iam::123456789012:policy/test-policy"
    mock_policy.name = "test-policy"
    mock_policies = [mock_policy]

    with patch("aws_scanner.scanners.iam_policy_scanner.analyze_policy", 
              side_effect=Exception("Analysis error")), \
         patch("logging.error") as mock_error:

        from aws_scanner.scanners.iam_policy_scanner import analyze_policies
        results = analyze_policies(mock_policies)

        assert len(results) == 1
        assert results[0]["policy_arn"] == "arn:aws:iam::123456789012:policy/test-policy"
        assert results[0]["policy_name"] == "test-policy"
        assert results[0]["error"] == "Analysis error"
        mock_error.assert_called_once()

def test_get_collector_file():
    mock_config = MagicMock()
    mock_config.file = "/path/to/file.json"
    mock_config.attached_only = False
    mock_boto3 = MagicMock()

    from aws_scanner.scanners.iam_policy_scanner import get_collector
    from aws_scanner.engines.iam_policy.file_iam_policy_collector import FileIamPolicyCollector
    
    collector = get_collector(mock_config, mock_boto3)
    assert isinstance(collector, FileIamPolicyCollector)
    assert collector._file_path == "/path/to/file.json"

def test_get_collector_aws():
    mock_config = MagicMock()
    mock_config.file = None
    mock_config.attached_only = True
    mock_boto3 = MagicMock()

    from aws_scanner.scanners.iam_policy_scanner import get_collector
    from aws_scanner.engines.iam_policy.aws_iam_policy_collector import AwsIamPolicyCollector
    
    collector = get_collector(mock_config, mock_boto3)
    assert isinstance(collector, AwsIamPolicyCollector)
    assert collector._attached_only is True

def test_run_scanner_success():
    mock_config = MagicMock()
    mock_boto3 = MagicMock()
    mock_results = [{
        "policy_arn": "arn:aws:iam::123456789012:policy/test-policy",
        "policy_name": "test-policy",
        "vulnerabilities": [{"description": "Policy uses wildcard actions"}]
    }]

    with patch("aws_scanner.scanners.iam_policy_scanner.get_collector") as mock_get_collector, \
         patch("aws_scanner.scanners.iam_policy_scanner.analyze_policies", 
              return_value=mock_results), \
         patch("logging.info") as mock_info, \
         patch("logging.warning") as mock_warning:

        mock_collector = MagicMock()
        mock_collector.collect.return_value = []
        mock_get_collector.return_value = mock_collector

        from aws_scanner.scanners.iam_policy_scanner import run_scanner
        results = run_scanner(mock_config, mock_boto3)

        assert results == mock_results
        mock_info.assert_called_once_with("Starting IAM policy scanner")
        mock_warning.assert_called_once_with(
            "Policy test-policy (arn:aws:iam::123456789012:policy/test-policy): Policy uses wildcard actions"
        )

def test_run_scanner_no_credentials():
    mock_config = MagicMock()
    mock_boto3 = MagicMock()

    with patch("aws_scanner.scanners.iam_policy_scanner.get_collector", 
              side_effect=botocore.exceptions.NoCredentialsError()), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)):

        from aws_scanner.scanners.iam_policy_scanner import run_scanner
        with pytest.raises(SystemExit):
            run_scanner(mock_config, mock_boto3)

        mock_critical.assert_called_once_with("No AWS credentials found")

def test_run_scanner_connection_error():
    mock_config = MagicMock()
    mock_boto3 = MagicMock()

    with patch("aws_scanner.scanners.iam_policy_scanner.get_collector", 
              side_effect=botocore.exceptions.EndpointConnectionError(
                  endpoint_url="test", error="Error")), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)):

        from aws_scanner.scanners.iam_policy_scanner import run_scanner
        with pytest.raises(SystemExit):
            run_scanner(mock_config, mock_boto3)

        mock_critical.assert_called_once()

def test_run_scanner_with_errors():
    mock_config = MagicMock()
    mock_boto3 = MagicMock()
    mock_results = [
        {
            "policy_arn": "arn:aws:iam::123456789012:policy/policy1",
            "policy_name": "policy1",
            "error": "Scan error"
        },
        {
            "policy_arn": "arn:aws:iam::123456789012:policy/policy2",
            "policy_name": "policy2",
            "vulnerabilities": [{"description": "Some vulnerability"}]
        }
    ]

    with patch("aws_scanner.scanners.iam_policy_scanner.get_collector") as mock_get_collector, \
         patch("aws_scanner.scanners.iam_policy_scanner.analyze_policies", 
              return_value=mock_results), \
         patch("logging.warning") as mock_warning:

        mock_collector = MagicMock()
        mock_collector.collect.return_value = []
        mock_get_collector.return_value = mock_collector

        from aws_scanner.scanners.iam_policy_scanner import run_scanner
        results = run_scanner(mock_config, mock_boto3)

        assert results == mock_results
        mock_warning.assert_called_once_with(
            "Policy policy2 (arn:aws:iam::123456789012:policy/policy2): Some vulnerability"
        )