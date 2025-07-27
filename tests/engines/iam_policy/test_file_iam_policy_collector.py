from unittest.mock import patch, mock_open
import json
import pytest
from aws_scanner.engines.iam_policy.file_iam_policy_collector import FileIamPolicyCollector

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
        collector = FileIamPolicyCollector("/path/to/policies.json")
        results = collector.collect()

        assert len(results) == 2

        policy1 = next(p for p in results if p.name == "test-policy1")
        assert policy1.policy_type == "managed"
        assert policy1.document == {"Version": "2012-10-17", "Statement": []}
        assert policy1.arn == "arn:aws:iam::123456789012:policy/test-policy1"
        assert policy1.is_inline is False

        policy2 = next(p for p in results if p.name == "test-policy2")
        assert policy2.policy_type == "inline"
        assert policy2.document == {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}
        assert policy2.arn is None
        assert policy2.is_inline is True

    mock_file.assert_called_once_with("/path/to/policies.json", 'r')

def test_collect_missing_required_field():
    test_data = {
        "policy1": {
            # missing "name" field
            "policy_type": "managed",
            "document": {}
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/policies.json")

        with pytest.raises(KeyError):
            collector.collect()

def test_collect_empty_file():
    mock_file = mock_open(read_data="{}")

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/empty.json")
        results = collector.collect()

        assert len(results) == 0

def test_collect_invalid_json():
    mock_file = mock_open(read_data="invalid json")

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/invalid.json")

        with pytest.raises(json.JSONDecodeError):
            collector.collect()

def test_collect_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
        collector = FileIamPolicyCollector("/nonexistent/path.json")

        with pytest.raises(FileNotFoundError):
            collector.collect()

def test_collect_with_default_values():
    test_data = {
        "policy1": {
            "name": "test-policy",
            "policy_type": "managed",
            # missing document, arn and is_inline
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/policies.json")
        results = collector.collect()

        assert len(results) == 1
        policy = results[0]
        assert policy.document == {}
        assert policy.arn is None
        assert policy.is_inline is True