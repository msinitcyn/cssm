import json
from unittest.mock import patch, mock_open
from aws_scanner.engines.common.resource_definition import ResourceCollection, ResourceDefinition


def test_collect_returns_resource_collection():
    test_data = {
        "test-policy": {
            "name": "test-policy",
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        result = collector.collect()

        assert isinstance(result, ResourceCollection)


def test_iam_policy_becomes_resource_definition():
    test_data = {
        "test-policy": {
            "name": "TestPolicy",
            "document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*"
                    }
                ]
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        assert len(collection.resources) == 1
        policy = collection.get_by_id("test-policy")
        assert policy is not None
        assert policy.resource_type == "AWS::IAM::Policy"
        assert policy.logical_id == "test-policy"


def test_policy_properties_in_resource_definition():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }

    test_data = {
        "my-policy": {
            "name": "MyPolicy",
            "document": policy_document
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        policy = collection.get_by_id("my-policy")
        assert policy.properties["PolicyName"] == "MyPolicy"
        assert policy.properties["PolicyDocument"] == policy_document


def test_handles_single_policy_format_no_wrapper():
    test_data = {
        "name": "SinglePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": []
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        assert len(collection.resources) == 1
        policy = collection.get_by_id("SinglePolicy")
        assert policy is not None
        assert policy.properties["PolicyName"] == "SinglePolicy"


def test_handles_dict_format_with_keys():
    test_data = {
        "policy-key-1": {
            "name": "Policy1",
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        },
        "policy-key-2": {
            "name": "Policy2",
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        assert len(collection.resources) == 2

        policy1 = collection.get_by_id("policy-key-1")
        assert policy1 is not None
        assert policy1.properties["PolicyName"] == "Policy1"

        policy2 = collection.get_by_id("policy-key-2")
        assert policy2 is not None
        assert policy2.properties["PolicyName"] == "Policy2"


def test_handles_list_format():
    test_data = [
        {
            "name": "Policy1",
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        },
        {
            "name": "Policy2",
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        }
    ]

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        assert len(collection.resources) == 2

        policy1 = collection.get_by_id("Policy1")
        assert policy1 is not None
        assert policy1.properties["PolicyName"] == "Policy1"

        policy2 = collection.get_by_id("Policy2")
        assert policy2 is not None
        assert policy2.properties["PolicyName"] == "Policy2"


def test_handles_aws_cli_metadata_format():
    test_data = {
        "Policies": [
            {
                "PolicyName": "AmazonS3ReadOnlyAccess",
                "Arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
            },
            {
                "PolicyName": "AmazonEC2ReadOnlyAccess",
                "Arn": "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
            }
        ]
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))), \
         patch("logging.warning") as mock_warning:
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        assert len(collection.resources) == 2

        policy1 = collection.get_by_id("AmazonS3ReadOnlyAccess")
        assert policy1 is not None
        assert policy1.properties["PolicyName"] == "AmazonS3ReadOnlyAccess"
        assert policy1.properties["PolicyDocument"] == {}

        mock_warning.assert_called()


def test_handles_policies_with_missing_document_field():
    test_data = {
        "valid-policy": {
            "name": "ValidPolicy",
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        },
        "invalid-policy": {
            "name": "InvalidPolicy"
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))), \
         patch("logging.warning") as mock_warning:
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        assert len(collection.resources) == 1

        valid_policy = collection.get_by_id("valid-policy")
        assert valid_policy is not None

        invalid_policy = collection.get_by_id("invalid-policy")
        assert invalid_policy is None

        mock_warning.assert_called_with("No policy document found for policy 'invalid-policy', skipping")


def test_handles_policies_with_missing_name_field_uses_key_as_fallback():
    test_data = {
        "policy-key-1": {
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        assert len(collection.resources) == 1

        policy = collection.get_by_id("policy-key-1")
        assert policy is not None
        assert policy.properties["PolicyName"] == "policy-key-1"


def test_handles_policies_in_list_with_missing_name_uses_index_as_fallback():
    test_data = [
        {
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        },
        {
            "name": "NamedPolicy",
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        }
    ]

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        assert len(collection.resources) == 2

        policy0 = collection.get_by_id("policy-0")
        assert policy0 is not None
        assert policy0.properties["PolicyName"] == "policy-0"

        policy1 = collection.get_by_id("NamedPolicy")
        assert policy1 is not None
        assert policy1.properties["PolicyName"] == "NamedPolicy"


def test_can_retrieve_policy_from_collection_using_get_by_id():
    test_data = {
        "policy-1": {
            "name": "TestPolicy",
            "document": {
                "Version": "2012-10-17",
                "Statement": []
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        policy = collection.get_by_id("policy-1")
        assert policy is not None
        assert isinstance(policy, ResourceDefinition)
        assert policy.resource_type == "AWS::IAM::Policy"


def test_validate_against_wildcard_admin_example():
    with open("examples/iam/policies/wildcard_admin.json", "r") as f:
        test_data = json.load(f)

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("examples/iam/policies/wildcard_admin.json")
        collection = collector.collect()

        assert len(collection.resources) == 1

        policy = collection.get_by_id("BadPolicy")
        assert policy is not None
        assert policy.properties["PolicyName"] == "BadPolicy"
        assert policy.properties["PolicyDocument"]["Statement"][0]["Action"] == "*"


def test_validate_against_assume_role_wildcard_example():
    with open("examples/iam/policies/assume_role_wildcard.json", "r") as f:
        test_data = json.load(f)

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("examples/iam/policies/assume_role_wildcard.json")
        collection = collector.collect()

        assert len(collection.resources) == 1

        policy = collection.get_by_id("AssumeAnyRolePolicy")
        assert policy is not None
        assert policy.properties["PolicyName"] == "AssumeAnyRolePolicy"
        assert policy.properties["PolicyDocument"]["Statement"][0]["Action"] == "sts:AssumeRole"


def test_validate_against_privilege_escalation_example():
    with open("examples/iam/policies/privilege_escalation.json", "r") as f:
        test_data = json.load(f)

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("examples/iam/policies/privilege_escalation.json")
        collection = collector.collect()

        assert len(collection.resources) == 1

        policy = collection.get_by_id("DeveloperRole")
        assert policy is not None
        assert policy.properties["PolicyName"] == "DeveloperRole"
        assert "iam:CreateRole" in policy.properties["PolicyDocument"]["Statement"][0]["Action"]


def test_extract_name_from_multiple_field_variants():
    test_cases = [
        ({"name": "Policy1", "document": {}}, "Policy1"),
        ({"Name": "Policy2", "document": {}}, "Policy2"),
        ({"PolicyName": "Policy3", "document": {}}, "Policy3"),
        ({"policy_name": "Policy4", "document": {}}, "Policy4"),
    ]

    for test_data_single, expected_name in test_cases:
        test_data = {"key": test_data_single}

        with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
            from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

            collector = ResourceFileIamPolicyCollector("test_file.json")
            collection = collector.collect()

            policy = collection.get_by_id("key")
            assert policy.properties["PolicyName"] == expected_name


def test_extract_document_from_multiple_field_variants():
    doc = {"Version": "2012-10-17", "Statement": []}

    test_cases = [
        {"name": "P1", "document": doc},
        {"name": "P2", "Document": doc},
        {"name": "P3", "PolicyDocument": doc},
        {"name": "P4", "policy_document": doc},
    ]

    for i, test_data_single in enumerate(test_cases):
        test_data = {f"key-{i}": test_data_single}

        with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
            from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

            collector = ResourceFileIamPolicyCollector("test_file.json")
            collection = collector.collect()

            policy = collection.get_by_id(f"key-{i}")
            assert policy.properties["PolicyDocument"] == doc


def test_handles_stringified_json_documents():
    doc = {"Version": "2012-10-17", "Statement": []}

    test_data = {
        "policy-1": {
            "name": "StringifiedPolicy",
            "document": json.dumps(doc)
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector

        collector = ResourceFileIamPolicyCollector("test_file.json")
        collection = collector.collect()

        policy = collection.get_by_id("policy-1")
        assert policy.properties["PolicyDocument"] == doc