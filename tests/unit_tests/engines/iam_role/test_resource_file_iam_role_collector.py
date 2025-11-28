import json
from unittest.mock import mock_open, patch
from aws_scanner.engines.iam_role.resource_file_iam_role_collector import ResourceFileIamRoleCollector
from aws_scanner.engines.common.resource_definition import ResourceCollection


def test_collector_returns_resource_collection():
    test_data = {
        "test-role": {
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileIamRoleCollector("test_file.json")
        result = collector.collect()

        assert isinstance(result, ResourceCollection)


def test_iam_role_becomes_resource_definition_with_correct_type():
    test_data = {
        "test-role": {
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileIamRoleCollector("test_file.json")
        collection = collector.collect()

        resources = collection.get_resources_by_type("AWS::IAM::Role")
        assert len(resources) == 1
        assert resources[0].resource_type == "AWS::IAM::Role"
        assert resources[0].logical_id == "test-role"


def test_role_properties_in_resource_definition():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }

    test_data = {
        "my-role": {
            "assume_role_policy_document": assume_role_policy
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileIamRoleCollector("test_file.json")
        collection = collector.collect()

        role_resources = collection.get_resources_by_type("AWS::IAM::Role")
        assert len(role_resources) == 1

        role = role_resources[0]
        assert role.properties["RoleName"] == "my-role"
        assert role.properties["AssumeRolePolicyDocument"] == assume_role_policy


def test_inline_policies_become_separate_resource_definitions_with_references():
    inline_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }]
    }

    test_data = {
        "test-role": {
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            },
            "inline_policies": [
                {
                    "name": "inline-policy-1",
                    "document": inline_policy_doc
                }
            ]
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileIamRoleCollector("test_file.json")
        collection = collector.collect()

        policy_resources = collection.get_resources_by_type("AWS::IAM::Policy")
        assert len(policy_resources) == 1

        policy = policy_resources[0]
        assert policy.logical_id == "test-role-inline-policy-1"
        assert policy.properties["PolicyName"] == "inline-policy-1"
        assert policy.properties["PolicyDocument"] == inline_policy_doc

        role_resources = collection.get_resources_by_type("AWS::IAM::Role")
        role = role_resources[0]

        assert len(role.references) == 1
        assert role.references[0].target_logical_id == "test-role-inline-policy-1"
        assert role.references[0].reference_type == "inline_policy"


def test_attached_policies_become_separate_resource_definitions_with_references():
    test_data = {
        "test-role": {
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            },
            "attached_policies": [
                {
                    "name": "attached-policy-1"
                }
            ]
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileIamRoleCollector("test_file.json")
        collection = collector.collect()

        policy_resources = collection.get_resources_by_type("AWS::IAM::ManagedPolicy")
        assert len(policy_resources) == 1

        policy = policy_resources[0]
        assert policy.logical_id == "test-role-attached-policy-1"
        assert policy.properties["ManagedPolicyName"] == "attached-policy-1"

        role_resources = collection.get_resources_by_type("AWS::IAM::Role")
        role = role_resources[0]

        assert len(role.references) == 1
        assert role.references[0].target_logical_id == "test-role-attached-policy-1"
        assert role.references[0].reference_type == "managed_policy"


def test_can_retrieve_role_and_policies_from_collection():
    inline_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*"
        }]
    }

    test_data = {
        "complex-role": {
            "assume_role_policy_document": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            },
            "inline_policies": [
                {
                    "name": "inline-policy",
                    "document": inline_policy_doc
                }
            ],
            "attached_policies": [
                {
                    "name": "managed-policy"
                }
            ]
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileIamRoleCollector("test_file.json")
        collection = collector.collect()

        role = collection.get_by_id("complex-role")
        assert role is not None
        assert role.resource_type == "AWS::IAM::Role"
        assert len(role.references) == 2

        inline_policy = collection.get_by_id("complex-role-inline-policy")
        assert inline_policy is not None
        assert inline_policy.resource_type == "AWS::IAM::Policy"
        assert inline_policy.properties["PolicyDocument"] == inline_policy_doc

        managed_policy = collection.get_by_id("complex-role-managed-policy")
        assert managed_policy is not None
        assert managed_policy.resource_type == "AWS::IAM::ManagedPolicy"
        assert managed_policy.properties["ManagedPolicyName"] == "managed-policy"

        inline_ref = [ref for ref in role.references if ref.reference_type == "inline_policy"][0]
        assert inline_ref.target_logical_id == "complex-role-inline-policy"

        managed_ref = [ref for ref in role.references if ref.reference_type == "managed_policy"][0]
        assert managed_ref.target_logical_id == "complex-role-managed-policy"