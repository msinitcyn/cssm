import pytest
from unittest.mock import MagicMock, patch
import botocore
from aws_scanner.scanners import s3_scanner

def make_s3_list_buckets(names):
    return {"Buckets": [{"Name": n} for n in names]}

@patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket")
@patch("aws_scanner.scanners.s3_scanner.collect_s3_bucket_data")
def test_find_public_s3_buckets_all_success(mock_collect, mock_analyze):
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = make_s3_list_buckets(["bucket1", "bucket2"])
    mock_collect.side_effect = lambda s3, name: f"data-{name}"
    mock_analyze.side_effect = lambda data: {"bucket": data.split("-")[1], "public": False}
    result = s3_scanner.find_public_s3_buckets(mock_s3)
    assert result == [
        {"bucket": "bucket1", "public": False},
        {"bucket": "bucket2", "public": False}
    ]

@patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket")
@patch("aws_scanner.scanners.s3_scanner.collect_s3_bucket_data")
def test_find_public_s3_buckets_list_error(mock_collect, mock_analyze):
    mock_s3 = MagicMock()
    mock_s3.list_buckets.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied"}}, "ListBuckets"
    )
    result = s3_scanner.find_public_s3_buckets(mock_s3)
    assert result[0]["bucket"] == "<list_error>"
    assert "error" in result[0]

@patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket")
@patch("aws_scanner.scanners.s3_scanner.collect_s3_bucket_data")
def test_find_public_s3_buckets_bucket_error(mock_collect, mock_analyze):
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = make_s3_list_buckets(["bucket1", "bucket2"])
    def collect_side_effect(s3, name):
        if name == "bucket1":
            raise botocore.exceptions.ClientError({"Error": {"Code": "AccessDenied"}}, "GetBucket")
        return f"data-{name}"
    mock_collect.side_effect = collect_side_effect
    mock_analyze.side_effect = lambda data: {"bucket": data.split("-")[1], "public": True}
    result = s3_scanner.find_public_s3_buckets(mock_s3)
    buckets = {r["bucket"]: r for r in result}
    assert "error" in buckets["bucket1"]
    assert buckets["bucket2"]["public"] is True

@patch("aws_scanner.scanners.s3_scanner.analyze_s3_bucket")
@patch("aws_scanner.scanners.s3_scanner.collect_s3_bucket_data")
def test_find_public_s3_buckets_mixed_results(mock_collect, mock_analyze):
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = make_s3_list_buckets(["bucket1", "bucket2", "bucket3"])
    def collect_side_effect(s3, name):
        if name == "bucket2":
            raise botocore.exceptions.ClientError({"Error": {"Code": "AccessDenied"}}, "GetBucket")
        return f"data-{name}"
    mock_collect.side_effect = collect_side_effect
    mock_analyze.side_effect = lambda data: {"bucket": data.split("-")[1], "public": False}
    result = s3_scanner.find_public_s3_buckets(mock_s3)
    buckets = {r["bucket"]: r for r in result}
    assert buckets["bucket1"]["public"] is False
    assert "error" in buckets["bucket2"]
    assert buckets["bucket3"]["public"] is False
