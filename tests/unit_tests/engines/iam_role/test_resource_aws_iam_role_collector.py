from unittest.mock import MagicMock
import botocore.exceptions
import pytest
from aws_scanner.engines.iam_role.resource_aws_iam_role_collector import ResourceAwsIamRoleCollector
from aws_scanner.engines.common.resource_definition import ResourceCollection
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


def test_collect_returns_resource_collection():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "TestRole"}]}
    ]
    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
    }
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamRoleCollector(mock_wrapper)
    result = collector.collect()

    assert isinstance(result, ResourceCollection)


def test_role_becomes_resource_definition_with_correct_type():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "TestRole"}]}
    ]
    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
    }
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamRoleCollector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 1
    resource = result.resources["TestRole"]
    assert resource.resource_type == "AWS::IAM::Role"


def test_role_properties_include_name_and_trust_policy():
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ]
    }
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "TestRole"}]}
    ]
    mock_iam.get_role.return_value = {"Role": {"AssumeRolePolicyDocument": trust_policy}}
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamRoleCollector(mock_wrapper)
    result = collector.collect()

    resource = result.resources["TestRole"]
    assert resource.properties["RoleName"] == "TestRole"
    assert resource.properties["AssumeRolePolicyDocument"] == trust_policy


def test_inline_policies_extracted_as_separate_resources():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "TestRole"}]}
    ]
    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
    }
    mock_iam.list_role_policies.return_value = {"PolicyNames": ["InlinePolicy1"]}
    mock_iam.get_role_policy.return_value = {
        "PolicyDocument": {"Version": "2012-10-17", "Statement": []}
    }
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamRoleCollector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 2
    assert "TestRole" in result.resources
    assert "TestRole-InlinePolicy1" in result.resources

    inline_policy_resource = result.resources["TestRole-InlinePolicy1"]
    assert inline_policy_resource.resource_type == "AWS::IAM::Policy"
    assert inline_policy_resource.properties["PolicyName"] == "InlinePolicy1"


def test_attached_policies_extracted_as_separate_resources():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "TestRole"}]}
    ]
    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
    }
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [
            {"PolicyArn": "arn:aws:iam::123456789012:policy/AttachedPolicy1", "PolicyName": "AttachedPolicy1"}
        ]
    }
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamRoleCollector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 2
    assert "TestRole" in result.resources
    assert "TestRole-AttachedPolicy1" in result.resources

    attached_policy_resource = result.resources["TestRole-AttachedPolicy1"]
    assert attached_policy_resource.resource_type == "AWS::IAM::ManagedPolicy"
    assert attached_policy_resource.properties["PolicyName"] == "AttachedPolicy1"


def test_handles_get_role_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "TestRole"}]}
    ]
    mock_iam.get_role.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "Role not found"}},
        "GetRole"
    )
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamRoleCollector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 1
    resource = result.resources["TestRole"]
    assert resource.properties["AssumeRolePolicyDocument"] == {}


def test_handles_list_role_policies_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "TestRole"}]}
    ]
    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
    }
    mock_iam.list_role_policies.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "ListRolePolicies"
    )
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamRoleCollector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 1
    assert "TestRole" in result.resources


def test_handles_list_attached_role_policies_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "TestRole"}]}
    ]
    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
    }
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "ListAttachedRolePolicies"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamRoleCollector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 1
    assert "TestRole" in result.resources
