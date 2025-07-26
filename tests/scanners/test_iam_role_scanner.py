from unittest.mock import patch, MagicMock
import botocore.exceptions

def test_find_issues_success():
    mock_config = MagicMock()

    mock_role1 = MagicMock()
    mock_role1.name = "role1"
    mock_role2 = MagicMock()
    mock_role2.name = "role2"
    mock_roles = [mock_role1, mock_role2]

    mock_findings1 = [{"type": "trust_policy", "description": "Overly permissive trust policy"}]
    mock_findings2 = [{"type": "permissions", "description": "Excessive permissions"}]

    with patch("aws_scanner.scanners.iam_role_scanner.collect_iam_roles", return_value=mock_roles), \
         patch("aws_scanner.scanners.iam_role_scanner.analyze_iam_role", side_effect=[mock_findings1, mock_findings2]):

        from aws_scanner.scanners.iam_role_scanner import find_issues
        results = find_issues(mock_config)

        assert len(results) == 2
        assert results[0]["role_name"] == "role1"
        assert results[0]["vulnerabilities"] == mock_findings1
        assert results[1]["role_name"] == "role2"
        assert results[1]["vulnerabilities"] == mock_findings2

def test_find_issues_analyzer_error():
    mock_config = MagicMock()

    mock_role = MagicMock()
    mock_role.name = "test-role"
    mock_roles = [mock_role]

    with patch("aws_scanner.scanners.iam_role_scanner.collect_iam_roles", return_value=mock_roles), \
         patch("aws_scanner.scanners.iam_role_scanner.analyze_iam_role", side_effect=Exception("Analysis error")):

        from aws_scanner.scanners.iam_role_scanner import find_issues
        results = find_issues(mock_config)

        assert len(results) == 1
        assert results[0]["role_name"] == "test-role"
        assert results[0]["error"] == "Analysis error"

def test_find_issues_collector_error():
    mock_config = MagicMock()

    with patch("aws_scanner.scanners.iam_role_scanner.collect_iam_roles", side_effect=Exception("Collection error")):
        from aws_scanner.scanners.iam_role_scanner import find_issues
        results = find_issues(mock_config)

        assert len(results) == 1
        assert "error" in results[0]
        assert results[0]["error"] == "Collection error"

def test_run_scanner_success():
    mock_config = MagicMock()
    mock_results = [{
        "role_name": "test-role",
        "vulnerabilities": [{"description": "Overly permissive trust policy"}]
    }]

    with patch("aws_scanner.scanners.iam_role_scanner.find_issues", return_value=mock_results), \
         patch("logging.info"), \
         patch("logging.warning"):

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        results = run_scanner(mock_config)
        assert results == mock_results

def test_run_scanner_no_credentials():
    mock_config = MagicMock()

    with patch("aws_scanner.scanners.iam_role_scanner.find_issues", side_effect=botocore.exceptions.NoCredentialsError()), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        try:
            run_scanner(mock_config)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("No AWS credentials found")
        mock_exit.assert_called_once_with(1)

def test_run_scanner_connection_error():
    mock_config = MagicMock()

    with patch("aws_scanner.scanners.iam_role_scanner.find_issues", side_effect=botocore.exceptions.EndpointConnectionError(endpoint_url="test", error="Error")), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        try:
            run_scanner(mock_config)
        except SystemExit:
            pass

        mock_critical.assert_called_once()
        mock_exit.assert_called_once_with(1)

def test_run_scanner_with_errors():
    mock_config = MagicMock()
    mock_results = [
        {"role_name": "role1", "error": "Scan error"},
        {
            "role_name": "role2",
            "vulnerabilities": [{"description": "Some vulnerability"}]
        }
    ]

    with patch("aws_scanner.scanners.iam_role_scanner.find_issues", return_value=mock_results), \
         patch("logging.error"), \
         patch("logging.warning"):

        from aws_scanner.scanners.iam_role_scanner import run_scanner
        results = run_scanner(mock_config)
        assert results == mock_results

def test_integration_with_mocks():
    mock_config = MagicMock()

    mock_role1 = MagicMock()
    mock_role1.name = "role1"
    mock_role2 = MagicMock()
    mock_role2.name = "role2"
    mock_roles = [mock_role1, mock_role2]

    mock_findings1 = [{"type": "trust_policy", "raw_data": {"policy": "permissive"}}]
    mock_findings2 = [{"type": "permissions", "raw_data": {"actions": ["*"]}}]

    with patch("aws_scanner.scanners.iam_role_scanner.collect_iam_roles", return_value=mock_roles), \
         patch("aws_scanner.scanners.iam_role_scanner.analyze_iam_role", side_effect=[mock_findings1, mock_findings2]):

        from aws_scanner.scanners.iam_role_scanner import find_issues
        results = find_issues(mock_config)

        all_findings = []
        for result in results:
            if "vulnerabilities" in result:
                all_findings.extend(result["vulnerabilities"])

        assert any(f.get("type") == "trust_policy" for f in all_findings)
        assert any(f.get("type") == "permissions" for f in all_findings)