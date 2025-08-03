from unittest.mock import patch, mock_open
import json
import pytest
from aws_scanner.engines.s3.file_s3_collector import FileS3Collector
from aws_scanner.engines.common.iam_policy_data import IamPolicyData

def test_collect_success():
    test_data = {
        "policy1": {
            "name": "test-policy1",
            "policy_type": "managed",
            "document": {"Version": "2012-10-17", "Statement": []},
            "arn": "arn:aws:iam::123456789012:policy/test-policy1",
            "is_inline": False
        },
        "policy2": {
            "name": "test-policy2",
            "policy_type": "inline",
            "document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]},
            "is_inline": True
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/buckets.json")
        results = collector.collect()

        assert len(results) == 2

        bucket1 = results[0]
        assert bucket1.name == "bucket-0"
        assert isinstance(bucket1.policy, IamPolicyData)
        assert bucket1.policy.name == "test-policy1"
        assert bucket1.policy.policy_type == "managed"
        assert bucket1.policy.document == {"Version": "2012-10-17", "Statement": []}
        assert bucket1.policy.arn == "arn:aws:iam::123456789012:policy/test-policy1"
        assert bucket1.policy.is_inline is False

        bucket2 = results[1]
        assert bucket2.name == "bucket-1"
        assert bucket2.policy.name == "test-policy2"
        assert bucket2.policy.policy_type == "inline"
        assert bucket2.policy.document == {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}
        assert bucket2.policy.arn is None
        assert bucket2.policy.is_inline is True

    mock_file.assert_called_once_with("/path/to/buckets.json", 'r')

def test_collect_missing_required_field():
    test_data = {
        "policy1": {
            "name": "test-policy",
            # missing "policy_type" field
            "document": {}
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/buckets.json")

        with pytest.raises(KeyError):
            collector.collect()

def test_collect_empty_file():
    mock_file = mock_open(read_data="{}")

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/empty.json")
        results = collector.collect()

        assert len(results) == 0

def test_collect_invalid_json():
    mock_file = mock_open(read_data="invalid json")

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/invalid.json")

        with pytest.raises(json.JSONDecodeError):
            collector.collect()

def test_collect_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
        collector = FileS3Collector("/nonexistent/path.json")

        with pytest.raises(FileNotFoundError):
            collector.collect()

def test_collect_with_default_values():
    test_data = {
        "policy_key": {
            "policy_type": "managed",
            # missing name, document, arn and is_inline
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/buckets.json")
        results = collector.collect()

        assert len(results) == 1
        bucket = results[0]
        assert bucket.name == "bucket-0"
        assert bucket.policy.name == "policy_key"
        assert bucket.policy.document == {}
        assert bucket.policy.arn is None
        assert bucket.policy.is_inline is True