import json
from unittest.mock import patch, mock_open
import pytest
from aws_scanner.engines.iam_policy.file_iam_policy_collector import FileIamPolicyCollector

def test_collect_missing_document_field():
    test_data = {
        "policy1": {
            "name": "test-policy",
            "policy_type": "managed",
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file), \
         patch("logging.warning") as mock_warning:

        collector = FileIamPolicyCollector("/path/to/policies.json")
        results = collector.collect()

        assert len(results) == 0
        mock_warning.assert_called_with("No policy document found for policy 'policy1', skipping")

def test_collect_with_missing_name_uses_fallback():
    test_data = {
        "policy1": {
            "policy_type": "managed",
            "document": {"Version": "2012-10-17", "Statement": []}
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/policies.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].name == "policy1"
        assert results[0].policy_type == "managed"

def test_collect_invalid_json():
    mock_file = mock_open(read_data="invalid json")

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/invalid.json")

        with pytest.raises(json.JSONDecodeError):
            collector.collect()

def test_collect_unsupported_format():
    mock_file = mock_open(read_data='"just a string"')

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/invalid.json")

        with pytest.raises(ValueError, match="Unsupported file format"):
            collector.collect()

def test_collect_mixed_valid_invalid_policies():
    test_data = {
        "valid_policy": {
            "name": "ValidPolicy",
            "policy_type": "attached",
            "document": {"Version": "2012-10-17", "Statement": []}
        },
        "invalid_policy": {
            "name": "InvalidPolicy",
            "policy_type": "attached",
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file), \
         patch("logging.warning") as mock_warning:

        collector = FileIamPolicyCollector("/path/to/policies.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].name == "ValidPolicy"

        mock_warning.assert_called_with("No policy document found for policy 'invalid_policy', skipping")

def test_collect_array_format():
    test_data = [
        {
            "name": "Policy1",
            "policy_type": "attached",
            "document": {"Version": "2012-10-17", "Statement": []}
        },
        {
            "name": "Policy2",
            "policy_type": "inline",
            "document": {"Version": "2012-10-17", "Statement": []}
        }
    ]

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/policies.json")
        results = collector.collect()

        assert len(results) == 2
        assert results[0].name == "Policy1"
        assert results[1].name == "Policy2"

def test_collect_single_policy_format():
    test_data = {
        "name": "SinglePolicy",
        "policy_type": "attached",
        "document": {"Version": "2012-10-17", "Statement": []}
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileIamPolicyCollector("/path/to/policies.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].name == "SinglePolicy"

def test_collect_aws_cli_metadata_format():
    test_data = {
        "Policies": [
            {
                "PolicyName": "AmazonS3ReadOnlyAccess",
                "Arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                "AttachmentCount": 5
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file), \
         patch("logging.warning") as mock_warning:

        collector = FileIamPolicyCollector("/path/to/policies.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].name == "AmazonS3ReadOnlyAccess"
        assert results[0].document == {}
        assert results[0].arn == "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"

        mock_warning.assert_called_with("Detected AWS CLI list-policies format. This contains metadata only, not policy documents. Use get-policy-version to get actual policy content.")