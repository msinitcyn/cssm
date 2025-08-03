from unittest.mock import patch, MagicMock
import botocore.exceptions

from aws_scanner.engines.s3.s3_bucket_data import S3BucketData
from aws_scanner.core.configs import S3Config
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


def test_get_collector_file():
    mock_config = MagicMock()
    mock_config.file = "test_file.json"
    mock_boto3_wrapper = MagicMock()

    with patch("aws_scanner.scanners.s3_scanner.FileS3Collector") as mock_file_collector:
        from aws_scanner.scanners.s3_scanner import get_collector
        get_collector(mock_config, mock_boto3_wrapper)

        mock_file_collector.assert_called_once_with("test_file.json")


def test_get_collector_aws():
    mock_config = MagicMock()
    mock_config.file = None
    mock_boto3_wrapper = MagicMock()

    with patch("aws_scanner.scanners.s3_scanner.AwsS3Collector") as mock_aws_collector:
        from aws_scanner.scanners.s3_scanner import get_collector
        get_collector(mock_config, mock_boto3_wrapper)

        mock_aws_collector.assert_called_once_with(mock_boto3_wrapper)


def test_analyze_s3_buckets_success():
    mock_bucket1 = MagicMock(spec=S3BucketData)
    mock_bucket1.name = "bucket1"
    mock_bucket2 = MagicMock(spec=S3BucketData)
    mock_bucket2.name = "bucket2"

    mock_findings1 = [{"type": "public", "description": "Public access"}]
    mock_findings2 = [{"type": "encryption", "description": "No encryption"}]

    with patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket",
              side_effect=[mock_findings1, mock_findings2]):
        from aws_scanner.scanners.s3_scanner import analyze_s3_buckets
        results = analyze_s3_buckets([mock_bucket1, mock_bucket2])

        assert len(results) == 2
        assert results[0]["bucket_name"] == "bucket1"
        assert results[0]["vulnerabilities"] == mock_findings1
        assert results[1]["bucket_name"] == "bucket2"
        assert results[1]["vulnerabilities"] == mock_findings2


def test_analyze_s3_buckets_with_error():
    mock_bucket = MagicMock(spec=S3BucketData)
    mock_bucket.name = "error-bucket"

    with patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket",
              side_effect=Exception("Test error")):
        from aws_scanner.scanners.s3_scanner import analyze_s3_buckets
        results = analyze_s3_buckets([mock_bucket])

        assert len(results) == 1
        assert results[0]["bucket_name"] == "error-bucket"
        assert results[0]["error"] == "Test error"


def test_run_scanner_success():
    mock_config = MagicMock(spec=S3Config)
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)

    mock_bucket = MagicMock(spec=S3BucketData)
    mock_bucket.name = "test-bucket"
    mock_findings = [{"description": "Test finding"}]

    with patch("aws_scanner.scanners.s3_scanner.get_collector") as mock_get_collector, \
         patch("aws_scanner.scanners.s3_scanner.analyze_s3_buckets", return_value=[{
             "bucket_name": "test-bucket",
             "vulnerabilities": mock_findings
         }]), \
         patch("logging.info") as mock_info, \
         patch("logging.warning") as mock_warning:

        mock_collector = MagicMock()
        mock_collector.collect.return_value = [mock_bucket]
        mock_get_collector.return_value = mock_collector

        from aws_scanner.scanners.s3_scanner import run_scanner
        results = run_scanner(mock_config, mock_boto3_wrapper)

        assert len(results) == 1
        assert results[0]["bucket_name"] == "test-bucket"
        mock_info.assert_called_once_with("Starting S3 scanner")
        mock_warning.assert_called_once_with("Bucket test-bucket: Test finding")


def test_run_scanner_no_credentials():
    mock_config = MagicMock(spec=S3Config)
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_collector = MagicMock()
    mock_collector.collect.side_effect = botocore.exceptions.NoCredentialsError()

    with patch("aws_scanner.scanners.s3_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:
        
        from aws_scanner.scanners.s3_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("No AWS credentials found")
        mock_exit.assert_called_once_with(1)


def test_run_scanner_connection_error():
    mock_config = MagicMock(spec=S3Config)
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)

    mock_collector = MagicMock()
    mock_collector.collect.side_effect = botocore.exceptions.EndpointConnectionError(
        endpoint_url="test",
        error="Connection error"
    )

    with patch("aws_scanner.scanners.s3_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.s3_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once()
        mock_exit.assert_called_once_with(1)


def test_run_scanner_unexpected_error():
    mock_config = MagicMock(spec=S3Config)
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)

    mock_collector = MagicMock()
    mock_collector.collect.side_effect = Exception("Unexpected error")

    with patch("aws_scanner.scanners.s3_scanner.get_collector", return_value=mock_collector), \
         patch("logging.critical") as mock_critical, \
         patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:

        from aws_scanner.scanners.s3_scanner import run_scanner
        try:
            run_scanner(mock_config, mock_boto3_wrapper)
        except SystemExit:
            pass

        mock_critical.assert_called_once_with("Unexpected error: Unexpected error")
        mock_exit.assert_called_once_with(1)


def test_run_scanner_with_errors():
    mock_config = MagicMock(spec=S3Config)
    mock_boto3_wrapper = MagicMock(spec=Boto3Wrapper)

    mock_results = [
        {"bucket_name": "error-bucket", "error": "Scan error"},
        {
            "bucket_name": "good-bucket",
            "vulnerabilities": [{"description": "Some vulnerability"}]
        }
    ]

    with patch("aws_scanner.scanners.s3_scanner.get_collector") as mock_get_collector, \
         patch("aws_scanner.scanners.s3_scanner.analyze_s3_buckets", return_value=mock_results), \
         patch("logging.error") as mock_error, \
         patch("logging.warning") as mock_warning:

        mock_collector = MagicMock()
        mock_collector.collect.return_value = [MagicMock(), MagicMock()]
        mock_get_collector.return_value = mock_collector

        from aws_scanner.scanners.s3_scanner import run_scanner
        results = run_scanner(mock_config, mock_boto3_wrapper)

        assert results == mock_results
        mock_error.assert_called_once_with("Error scanning error-bucket: Scan error")
        mock_warning.assert_called_once_with("Bucket good-bucket: Some vulnerability")


def test_integration_with_mocks():
    mock_bucket1 = MagicMock(spec=S3BucketData)
    mock_bucket1.name = "bucket1"
    mock_bucket2 = MagicMock(spec=S3BucketData)
    mock_bucket2.name = "bucket2"

    mock_findings1 = [{"type": "public", "raw_data": {"policy": "public"}}]
    mock_findings2 = [{"type": "encryption", "raw_data": {"encryption": None}}]

    with patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket",
              side_effect=[mock_findings1, mock_findings2]):
        from aws_scanner.scanners.s3_scanner import analyze_s3_buckets
        results = analyze_s3_buckets([mock_bucket1, mock_bucket2])

        all_findings = []
        for result in results:
            if "vulnerabilities" in result:
                all_findings.extend(result["vulnerabilities"])

        assert any(f.get("type") == "public" for f in all_findings)
        assert any(f.get("type") == "encryption" for f in all_findings)