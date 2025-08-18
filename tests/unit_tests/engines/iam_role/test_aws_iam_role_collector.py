from unittest.mock import MagicMock
import botocore.exceptions
from aws_scanner.engines.iam_role.aws_iam_role_collector import AwsIamRoleCollector


def test_collect_iam_roles_success():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Roles": [
                {"RoleName": "test-role-1"},
                {"RoleName": "test-role-2"}
            ]
        }
    ]

    mock_iam.get_role.side_effect = [
        {"Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17"}}},
        {"Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17"}}}
    ]

    mock_iam.list_role_policies.side_effect = [
        {"PolicyNames": ["inline-policy-1"]},
        {"PolicyNames": []}
    ]
    mock_iam.get_role_policy.return_value = {
        "PolicyDocument": {"Version": "2012-10-17", "Statement": []}
    }

    mock_iam.list_attached_role_policies.side_effect = [
        {"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123456789012:policy/test-policy", "PolicyName": "test-policy"}]},
        {"AttachedPolicies": []}
    ]
    mock_iam.get_policy.return_value = {
        "Policy": {"DefaultVersionId": "v1"}
    }
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamRoleCollector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 2
    assert results[0].name == "test-role-1"
    assert results[1].name == "test-role-2"
    assert len(results[0].inline_policies) == 1
    assert results[0].inline_policies[0].name == "inline-policy-1"
    assert len(results[1].inline_policies) == 0
    assert len(results[0].attached_policies) == 1
    assert results[0].attached_policies[0].name == "test-policy"
    assert len(results[1].attached_policies) == 0


def test_collect_iam_roles_inline_policy_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "test-role"}]}
    ]

    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17"}}
    }

    mock_iam.list_role_policies.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied"}}, "list_role_policies"
    )
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamRoleCollector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].name == "test-role"
    assert len(results[0].inline_policies) == 1
    assert results[0].inline_policies[0].name == "<inline_policy_error>"
    assert results[0].inline_policies[0].is_inline is True


def test_collect_iam_roles_attached_policy_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "test-role"}]}
    ]

    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17"}}
    }

    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123456789012:policy/test-policy", "PolicyName": "test-policy"}]
    }
    mock_iam.get_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchEntity"}}, "get_policy"
    )

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamRoleCollector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].name == "test-role"
    assert len(results[0].attached_policies) == 1
    assert results[0].attached_policies[0].name == "test-policy"
    assert results[0].attached_policies[0].document == {}
    assert results[0].attached_policies[0].is_inline is False


def test_collect_iam_roles_list_attached_policies_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "test-role"}]}
    ]

    mock_iam.get_role.return_value = {
        "Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17"}}
    }

    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied"}}, "list_attached_role_policies"
    )

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamRoleCollector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].name == "test-role"
    assert len(results[0].attached_policies) == 0


def test_collect_iam_roles_get_role_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "test-role"}]}
    ]

    mock_iam.get_role.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchEntity"}}, "get_role"
    )

    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamRoleCollector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].name == "test-role"
    assert results[0].trust_policy_document == {}