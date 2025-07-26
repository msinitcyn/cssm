from unittest.mock import patch, MagicMock
import botocore.exceptions
from aws_scanner.core.configs import IamPolicyConfig


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

    # Mock inline policies
    mock_iam.list_role_policies.side_effect = [
        {"PolicyNames": ["inline-policy-1"]},
        {"PolicyNames": []}
    ]
    mock_iam.get_role_policy.return_value = {
        "PolicyDocument": {"Version": "2012-10-17", "Statement": []}
    }

    # Mock attached policies
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

    with patch("aws_scanner.engines.iam_role.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_role.collector import collect_iam_roles
        results = collect_iam_roles()

        assert len(results) == 2
        assert results[0].name == "test-role-1"
        assert results[1].name == "test-role-2"
        assert "inline-policy-1" in results[0].inline_policies
        assert len(results[1].inline_policies) == 0
        assert "test-policy" in results[0].attached_policies
        assert len(results[1].attached_policies) == 0


def test_collect_iam_roles_inline_policy_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "test-role"}]}
    ]

    mock_iam.list_role_policies.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied"}}, "list_role_policies"
    )
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    with patch("aws_scanner.engines.iam_role.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_role.collector import collect_iam_roles
        results = collect_iam_roles()

        assert len(results) == 1
        assert results[0].name == "test-role"
        assert "<inline_policy_error>" in results[0].inline_policies
        assert results[0].inline_policies["<inline_policy_error>"].is_inline is True


def test_collect_iam_roles_attached_policy_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "test-role"}]}
    ]

    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123456789012:policy/test-policy", "PolicyName": "test-policy"}]
    }
    mock_iam.get_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchEntity"}}, "get_policy"
    )

    with patch("aws_scanner.engines.iam_role.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_role.collector import collect_iam_roles
        results = collect_iam_roles()

        assert len(results) == 1
        assert results[0].name == "test-role"
        assert "test-policy" in results[0].attached_policies
        assert results[0].attached_policies["test-policy"].document == {}
        assert results[0].attached_policies["test-policy"].is_inline is False


def test_collect_iam_roles_list_attached_policies_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "test-role"}]}
    ]

    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied"}}, "list_attached_role_policies"
    )

    with patch("aws_scanner.engines.iam_role.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_role.collector import collect_iam_roles
        results = collect_iam_roles()

        assert len(results) == 1
        assert results[0].name == "test-role"
        assert len(results[0].attached_policies) == 0


def test_collect_iam_policies_all_scope():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-1", "PolicyName": "policy-1", "AttachmentCount": 1},
                {"Arn": "arn:aws:iam::123456789012:policy/policy-2", "PolicyName": "policy-2", "AttachmentCount": 0}
            ]
        }
    ]

    mock_iam.get_policy.side_effect = [
        {"Policy": {"DefaultVersionId": "v1"}},
        {"Policy": {"DefaultVersionId": "v2"}}
    ]
    mock_iam.get_policy_version.side_effect = [
        {"PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}},
        {"PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}}
    ]

    config = IamPolicyConfig(attached_only=False)

    with patch("aws_scanner.engines.iam_role.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_role.collector import collect_iam_policies
        results = collect_iam_policies(config)

        assert len(results) == 2
        assert "policy-1" in results
        assert "policy-2" in results
        assert results["policy-1"].arn == "arn:aws:iam::123456789012:policy/policy-1"
        assert results["policy-1"].is_inline is False
        mock_iam.get_paginator.assert_called_once_with("list_policies")


def test_collect_iam_policies_attached_only():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-1", "PolicyName": "policy-1", "AttachmentCount": 1},
                {"Arn": "arn:aws:iam::123456789012:policy/policy-2", "PolicyName": "policy-2", "AttachmentCount": 0}
            ]
        }
    ]

    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    config = IamPolicyConfig(attached_only=True)

    with patch("aws_scanner.engines.iam_role.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_role.collector import collect_iam_policies
        results = collect_iam_policies(config)

        assert len(results) == 1
        assert "policy-1" in results
        assert "policy-2" not in results


def test_collect_iam_policies_get_policy_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-1", "PolicyName": "policy-1", "AttachmentCount": 1}
            ]
        }
    ]

    mock_iam.get_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchEntity"}}, "get_policy"
    )

    config = IamPolicyConfig(attached_only=False)

    with patch("aws_scanner.engines.iam_role.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_role.collector import collect_iam_policies
        results = collect_iam_policies(config)

        assert len(results) == 1
        assert "policy-1" in results
        assert results["policy-1"].document == {}
        assert results["policy-1"].arn == "arn:aws:iam::123456789012:policy/policy-1"


def test_collect_iam_policies_empty_policies_list():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Policies": []}
    ]

    config = IamPolicyConfig(attached_only=False)

    with patch("aws_scanner.engines.iam_role.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_role.collector import collect_iam_policies
        results = collect_iam_policies(config)

        assert len(results) == 0