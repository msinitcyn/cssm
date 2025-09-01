from unittest.mock import patch, mock_open
import json
import pytest
from aws_scanner.engines.s3.file_s3_collector import FileS3Collector
from aws_scanner.engines.common.iam_policy_data import IamPolicyData

def test_collect_success():
    test_data = {
        "bucket1": {
            "bucket_name": "test-bucket1",
            "policy": {"Version": "2012-10-17", "Statement": []},
            "acl": "public-read",
            "block_public_access": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            },
            "server_access_logging": {"enabled": True},
            "versioning": {"status": "Enabled"},
            "encryption": {"server_side_encryption": "AES256"},
            "mfa_delete": True
        },
        "bucket2": {
            "name": "test-bucket2",
            "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]},
            "acl": "private",
            "mfa_delete": "false"
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/buckets.json")
        results = collector.collect()

        assert len(results) == 2

        bucket1 = results[0]
        assert bucket1.name == "test-bucket1"
        assert isinstance(bucket1.policy, IamPolicyData)
        assert bucket1.policy.name == "test-bucket1-bucket-policy"
        assert bucket1.policy.policy_type == "resource"
        assert bucket1.policy.document == {"Version": "2012-10-17", "Statement": []}
        assert bucket1.policy.arn is None
        assert bucket1.policy.is_inline is False
        assert len(bucket1.acl_grants) == 1
        assert bucket1.acl_grants[0]["Permission"] == "READ"
        assert bucket1.pab_config["BlockPublicAcls"] is False
        assert bucket1.server_access_logging == {"enabled": True}
        assert bucket1.versioning == {"status": "Enabled"}
        assert bucket1.encryption == {"server_side_encryption": "AES256"}
        assert bucket1.mfa_delete is True

        bucket2 = results[1]
        assert bucket2.name == "test-bucket2"
        assert bucket2.policy.name == "test-bucket2-bucket-policy"
        assert bucket2.policy.document == {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}
        assert len(bucket2.acl_grants) == 0
        assert bucket2.mfa_delete is False

    mock_file.assert_called_once_with("/path/to/buckets.json", 'r')

def test_collect_single_bucket():
    test_data = {
        "bucket_name": "single-bucket",
        "policy": {"Version": "2012-10-17", "Statement": []},
        "acl": "public-read-write"
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/bucket.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].name == "single-bucket"
        assert len(results[0].acl_grants) == 2
        assert results[0].acl_grants[0]["Permission"] == "READ"
        assert results[0].acl_grants[1]["Permission"] == "WRITE"

def test_collect_list_format():
    test_data = [
        {
            "bucket_name": "bucket-1",
            "policy": {"Version": "2012-10-17", "Statement": []},
            "acl": "private"
        },
        {
            "name": "bucket-2",
            "policy": {"Version": "2012-10-17", "Statement": []},
            "acl": "public-read"
        }
    ]

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/buckets.json")
        results = collector.collect()

        assert len(results) == 2
        assert results[0].name == "bucket-1"
        assert results[1].name == "bucket-2"

def test_collect_no_policy():
    test_data = {
        "bucket_name": "no-policy-bucket",
        "acl": "private"
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/bucket.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].policy is None

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

def test_acl_string_conversion():
    collector = FileS3Collector("/path/to/test.json")

    public_read_grants = collector._convert_acl_string_to_grants("public-read")
    assert len(public_read_grants) == 1
    assert public_read_grants[0]["Permission"] == "READ"

    public_read_write_grants = collector._convert_acl_string_to_grants("public-read-write")
    assert len(public_read_write_grants) == 2

    private_grants = collector._convert_acl_string_to_grants("private")
    assert len(private_grants) == 0

    unknown_grants = collector._convert_acl_string_to_grants("unknown")
    assert len(unknown_grants) == 0

def test_collect_with_pab_config_alias():
    test_data = {
        "bucket_name": "test-bucket",
        "pab_config": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/bucket.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].pab_config["BlockPublicAcls"] is True

def test_collect_fallback_bucket_names():
    test_data = {
        "bucket_without_name": {
            "acl": "private"
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileS3Collector("/path/to/bucket.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].name == "bucket-0"