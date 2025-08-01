import json
from unittest.mock import patch, mock_open
from aws_scanner.engines.iam_role.file_iam_role_collector import FileIamRoleCollector


def test_collect_iam_roles_success():
    test_data = {
        "test-role-1": {
            "inline_policies": [
                {
                    "name": "inline-policy-1",
                    "policy_type": "inline",
                    "document": {"Version": "2012-10-17", "Statement": []},
                    "arn": None
                }
            ],
            "attached_policies": [
                {
                    "name": "test-policy",
                    "policy_type": "managed",
                    "document": {"Version": "2012-10-17", "Statement": []},
                    "arn": "arn:aws:iam::123456789012:policy/test-policy"
                }
            ],
            "trust_policy_document": {"Version": "2012-10-17"}
        },
        "test-role-2": {
            "inline_policies": [],
            "attached_policies": [],
            "trust_policy_document": {}
        }
    }
    
    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = FileIamRoleCollector("test_file.json")
        results = collector.collect()
        
        assert len(results) == 2
        assert results[0].name == "test-role-1"
        assert results[1].name == "test-role-2"
        assert len(results[0].inline_policies) == 1
        assert results[0].inline_policies[0].name == "inline-policy-1"
        assert results[0].inline_policies[0].is_inline is True
        assert len(results[1].inline_policies) == 0
        assert len(results[0].attached_policies) == 1
        assert results[0].attached_policies[0].name == "test-policy"
        assert results[0].attached_policies[0].is_inline is False
        assert len(results[1].attached_policies) == 0


def test_collect_iam_roles_empty_policies():
    test_data = {
        "test-role": {
            "inline_policies": [],
            "attached_policies": [],
            "trust_policy_document": {"Version": "2012-10-17"}
        }
    }
    
    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = FileIamRoleCollector("test_file.json")
        results = collector.collect()
        
        assert len(results) == 1
        assert results[0].name == "test-role"
        assert len(results[0].inline_policies) == 0
        assert len(results[0].attached_policies) == 0


def test_collect_iam_roles_missing_optional_fields():
    test_data = {
        "test-role": {
            "inline_policies": [
                {
                    "name": "inline-policy"
                }
            ],
            "attached_policies": [
                {
                    "name": "attached-policy"
                }
            ]
        }
    }
    
    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = FileIamRoleCollector("test_file.json")
        results = collector.collect()
        
        assert len(results) == 1
        assert results[0].name == "test-role"
        assert results[0].inline_policies[0].policy_type == "inline"
        assert results[0].inline_policies[0].document == {}
        assert results[0].inline_policies[0].arn is None
        assert results[0].attached_policies[0].policy_type == "managed"
        assert results[0].attached_policies[0].document == {}
        assert results[0].attached_policies[0].arn is None
        assert results[0].trust_policy_document == {}


def test_collect_iam_roles_file_not_found():
    collector = FileIamRoleCollector("nonexistent_file.json")
    
    try:
        collector.collect()
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass


def test_collect_iam_roles_invalid_json():
    with patch("builtins.open", mock_open(read_data="invalid json")):
        collector = FileIamRoleCollector("test_file.json")
        
        try:
            collector.collect()
            assert False, "Expected json.JSONDecodeError"
        except json.JSONDecodeError:
            pass