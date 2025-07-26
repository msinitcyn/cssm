from unittest.mock import patch, MagicMock
import botocore.exceptions

def test_find_issues_success():
    mock_s3_config = MagicMock()

    mock_bucket_1 = MagicMock()
    mock_bucket_1.name = "bucket-1"
    mock_bucket_2 = MagicMock()
    mock_bucket_2.name = "bucket-2"
    mock_buckets = [mock_bucket_1, mock_bucket_2]

    mock_findings_1 = [{"type": "public_read", "description": "Bucket allows public read access"}]
    mock_findings_2 = [{"type": "public_write", "description": "Bucket allows public write access"}]

    with patch("aws_scanner.scanners.s3_scanner.collect_s3_bucket_data", return_value=mock_buckets) as mock_collect, \
         patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket", side_effect=[mock_findings_1, mock_findings_2]) as mock_analyze:

        from aws_scanner.scanners.s3_scanner import find_issues
        results = find_issues(mock_s3_config)

        assert len(results) == 2
        assert results[0]["bucket_name"] == "bucket-1"
        assert results[0]["vulnerabilities"] == mock_findings_1
        assert results[1]["bucket_name"] == "bucket-2"
        assert results[1]["vulnerabilities"] == mock_findings_2

        mock_collect.assert_called_once()
        assert mock_analyze.call_count == 2


def test_find_issues_analyzer_error():
    mock_s3_config = MagicMock()

    mock_bucket_1 = MagicMock()
    mock_bucket_1.name = "bucket-1"
    mock_buckets = [mock_bucket_1]

    with patch("aws_scanner.scanners.s3_scanner.collect_s3_bucket_data", return_value=mock_buckets) as mock_collect, \
         patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket", side_effect=Exception("Analysis failed")) as mock_analyze:

        from aws_scanner.scanners.s3_scanner import find_issues
        results = find_issues(mock_s3_config)

        assert len(results) == 1
        assert results[0]["bucket_name"] == "bucket-1"
        assert results[0]["error"] == "Analysis failed"

        mock_collect.assert_called_once()
        mock_analyze.assert_called_once()


def test_find_issues_collector_error():
    mock_s3_config = MagicMock()

    with patch("aws_scanner.scanners.s3_scanner.collect_s3_bucket_data", side_effect=Exception("Collection failed")) as mock_collect:
        from aws_scanner.scanners.s3_scanner import find_issues
        results = find_issues(mock_s3_config)

        assert len(results) == 1
        assert "error" in results[0]
        assert results[0]["error"] == "Collection failed"

        mock_collect.assert_called_once()


def test_run_scanner_success():
    mock_s3_config = MagicMock()
    mock_results = [
        {
            "bucket_name": "bucket-1",
            "vulnerabilities": [{"description": "Bucket allows public read access"}]
        }
    ]

    with patch("aws_scanner.scanners.s3_scanner.find_issues", return_value=mock_results) as mock_find_issues, \
         patch("logging.info") as mock_info, \
         patch("logging.warning") as mock_warning:

        from aws_scanner.scanners.s3_scanner import run_scanner
        results = run_scanner(mock_s3_config)

        assert results == mock_results
        mock_find_issues.assert_called_once_with(mock_s3_config)
        mock_info.assert_called_once_with("Starting S3 scanner")
        mock_warning.assert_called_once_with("Bucket bucket-1: Bucket allows public read access")


def test_run_scanner_no_credentials():
    mock_s3_config = MagicMock()

    with patch("aws_scanner.scanners.s3_scanner.find_issues", side_effect=botocore.exceptions.NoCredentialsError()), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.s3_scanner import run_scanner
        try:
            run_scanner(mock_s3_config)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("No AWS credentials found")
        mock_exit.assert_called_once_with(1)


def test_run_scanner_connection_error():
    mock_s3_config = MagicMock()

    with patch("aws_scanner.scanners.s3_scanner.find_issues", side_effect=botocore.exceptions.EndpointConnectionError(endpoint_url="https://s3.us-east-1.amazonaws.com", error="Connection error")), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.s3_scanner import run_scanner
        try:
            run_scanner(mock_s3_config)
        except SystemExit:
            pass

        mock_critical.assert_called_once()
        mock_exit.assert_called_once_with(1)


def test_run_scanner_with_errors():
    mock_s3_config = MagicMock()
    mock_results = [
        {"bucket_name": "bucket-1", "error": "Failed to analyze"},
        {
            "bucket_name": "bucket-2",
            "vulnerabilities": [{"description": "Some vulnerability"}]
        }
    ]

    with patch("aws_scanner.scanners.s3_scanner.find_issues", return_value=mock_results), \
         patch("logging.error") as mock_error, \
         patch("logging.warning") as mock_warning:

        from aws_scanner.scanners.s3_scanner import run_scanner
        results = run_scanner(mock_s3_config)

        assert results == mock_results
        mock_error.assert_called_once_with("Error scanning bucket-1: Failed to analyze")
        mock_warning.assert_called_once_with("Bucket bucket-2: Some vulnerability")


def test_integration_with_mocks():
    mock_s3_config = MagicMock()

    mock_bucket_1 = MagicMock()
    mock_bucket_1.name = "bucket-1"
    mock_bucket_2 = MagicMock()
    mock_bucket_2.name = "bucket-2"
    mock_buckets = [mock_bucket_1, mock_bucket_2]

    mock_findings_1 = [{"type": "public_read", "raw_data": {"policy": "public"}}]
    mock_findings_2 = [{"type": "no_encryption", "raw_data": {"encryption": None}}]

    with patch("aws_scanner.scanners.s3_scanner.collect_s3_bucket_data", return_value=mock_buckets) as mock_collect, \
         patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket", side_effect=[mock_findings_1, mock_findings_2]) as mock_analyze:

        from aws_scanner.scanners.s3_scanner import find_issues
        results = find_issues(mock_s3_config)

        all_findings = []
        for result in results:
            if "vulnerabilities" in result:
                all_findings.extend(result["vulnerabilities"])

        assert any(f.get("type") == "public_read" and f.get("raw_data", {}).get("policy") == "public" for f in all_findings)
        assert any(f.get("type") == "no_encryption" and f.get("raw_data", {}).get("encryption") is None for f in all_findings)
        assert mock_collect.called
        assert mock_analyze.call_count == len(mock_buckets)