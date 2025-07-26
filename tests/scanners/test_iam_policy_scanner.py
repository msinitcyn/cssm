from unittest.mock import patch, MagicMock
import botocore.exceptions

def test_find_issues_success():
    mock_config = MagicMock()

    mock_policy1 = MagicMock()
    mock_policy1.arn = "arn:aws:iam::123456789012:policy/policy1"
    mock_policy1.name = "policy1"
    mock_policy2 = MagicMock()
    mock_policy2.arn = "arn:aws:iam::123456789012:policy/policy2"
    mock_policy2.name = "policy2"
    mock_policies = [mock_policy1, mock_policy2]

    mock_findings1 = [{"type": "wildcard_actions", "description": "Policy uses wildcard actions"}]
    mock_findings2 = [{"type": "overprivileged", "description": "Policy has excessive permissions"}]

    with patch("aws_scanner.scanners.iam_policy_scanner.collect_iam_policies", return_value=mock_policies), \
         patch("aws_scanner.scanners.iam_policy_scanner.analyze_policy", side_effect=[mock_findings1, mock_findings2]):

        from aws_scanner.scanners.iam_policy_scanner import find_issues
        results = find_issues(mock_config)

        assert len(results) == 2
        assert results[0]["policy_arn"] == "arn:aws:iam::123456789012:policy/policy1"
        assert results[0]["policy_name"] == "policy1"
        assert results[0]["vulnerabilities"] == mock_findings1
        assert results[1]["policy_arn"] == "arn:aws:iam::123456789012:policy/policy2"
        assert results[1]["policy_name"] == "policy2"
        assert results[1]["vulnerabilities"] == mock_findings2

def test_find_issues_analyzer_error():
    mock_config = MagicMock()

    mock_policy = MagicMock()
    mock_policy.arn = "arn:aws:iam::123456789012:policy/test-policy"
    mock_policy.name = "test-policy"
    mock_policies = [mock_policy]

    with patch("aws_scanner.scanners.iam_policy_scanner.collect_iam_policies", return_value=mock_policies), \
         patch("aws_scanner.scanners.iam_policy_scanner.analyze_policy", side_effect=Exception("Analysis error")):

        from aws_scanner.scanners.iam_policy_scanner import find_issues
        results = find_issues(mock_config)

        assert len(results) == 1
        assert results[0]["policy_arn"] == "arn:aws:iam::123456789012:policy/test-policy"
        assert results[0]["policy_name"] == "test-policy"
        assert results[0]["error"] == "Analysis error"

def test_find_issues_collector_error():
    mock_config = MagicMock()

    with patch("aws_scanner.scanners.iam_policy_scanner.collect_iam_policies", side_effect=Exception("Collection error")):
        from aws_scanner.scanners.iam_policy_scanner import find_issues
        results = find_issues(mock_config)

        assert len(results) == 1
        assert "error" in results[0]
        assert results[0]["error"] == "Collection error"

def test_run_scanner_success():
    mock_config = MagicMock()
    mock_results = [{
        "policy_arn": "arn:aws:iam::123456789012:policy/test-policy",
        "policy_name": "test-policy",
        "vulnerabilities": [{"description": "Policy uses wildcard actions"}]
    }]

    with patch("aws_scanner.scanners.iam_policy_scanner.find_issues", return_value=mock_results), \
         patch("logging.info") as mock_info, \
         patch("logging.warning") as mock_warning:

        from aws_scanner.scanners.iam_policy_scanner import run_scanner
        results = run_scanner(mock_config)

        assert results == mock_results
        mock_info.assert_called_once_with("Starting IAM policy scanner")
        mock_warning.assert_called_once_with("Policy test-policy (arn:aws:iam::123456789012:policy/test-policy): Policy uses wildcard actions")

def test_run_scanner_no_credentials():
    mock_config = MagicMock()

    with patch("aws_scanner.scanners.iam_policy_scanner.find_issues", side_effect=botocore.exceptions.NoCredentialsError()), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.iam_policy_scanner import run_scanner
        try:
            run_scanner(mock_config)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("No AWS credentials found")
        mock_exit.assert_called_once_with(1)

def test_run_scanner_connection_error():
    mock_config = MagicMock()

    with patch("aws_scanner.scanners.iam_policy_scanner.find_issues", side_effect=botocore.exceptions.EndpointConnectionError(endpoint_url="test", error="Error")), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.iam_policy_scanner import run_scanner
        try:
            run_scanner(mock_config)
        except SystemExit:
            pass

        mock_critical.assert_called_once()
        mock_exit.assert_called_once_with(1)

def test_run_scanner_with_errors():
    mock_config = MagicMock()
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

    with patch("aws_scanner.scanners.iam_policy_scanner.find_issues", return_value=mock_results), \
         patch("logging.error") as mock_error, \
         patch("logging.warning") as mock_warning:

        from aws_scanner.scanners.iam_policy_scanner import run_scanner
        results = run_scanner(mock_config)

        assert results == mock_results
        mock_error.assert_called_once_with("Error scanning arn:aws:iam::123456789012:policy/policy1: Scan error")
        mock_warning.assert_called_once_with("Policy policy2 (arn:aws:iam::123456789012:policy/policy2): Some vulnerability")

def test_integration_with_mocks():
    mock_config = MagicMock()

    mock_policy1 = MagicMock()
    mock_policy1.arn = "arn:aws:iam::123456789012:policy/policy1"
    mock_policy1.name = "policy1"
    mock_policy2 = MagicMock()
    mock_policy2.arn = "arn:aws:iam::123456789012:policy/policy2"
    mock_policy2.name = "policy2"
    mock_policies = [mock_policy1, mock_policy2]

    mock_findings1 = [{"type": "wildcard_actions", "raw_data": {"actions": ["*"]}}]
    mock_findings2 = [{"type": "overprivileged", "raw_data": {"resources": ["*"]}}]

    with patch("aws_scanner.scanners.iam_policy_scanner.collect_iam_policies", return_value=mock_policies), \
         patch("aws_scanner.scanners.iam_policy_scanner.analyze_policy", side_effect=[mock_findings1, mock_findings2]):

        from aws_scanner.scanners.iam_policy_scanner import find_issues
        results = find_issues(mock_config)

        all_findings = []
        for result in results:
            if "vulnerabilities" in result:
                all_findings.extend(result["vulnerabilities"])

        assert any(f.get("type") == "wildcard_actions" and f.get("raw_data", {}).get("actions") == ["*"] for f in all_findings)
        assert any(f.get("type") == "overprivileged" and f.get("raw_data", {}).get("resources") == ["*"] for f in all_findings)