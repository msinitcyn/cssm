from unittest.mock import MagicMock
import botocore.exceptions
from aws_scanner.engines.iam_policy.aws_iam_policy_collector import AwsIamPolicyCollector
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


def test_collect_all_scope():
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

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper, attached_only=False)
    results = collector.collect()

    assert len(results) == 2
    assert any(policy.name == "policy-1" for policy in results)
    assert any(policy.name == "policy-2" for policy in results)

    policy1 = next(policy for policy in results if policy.name == "policy-1")
    assert policy1.arn == "arn:aws:iam::123456789012:policy/policy-1"
    assert policy1.name == "policy-1"
    assert policy1.policy_type == "attached"
    assert policy1.is_inline is False
    assert policy1.document == {"Version": "2012-10-17", "Statement": []}

    mock_iam.get_paginator.assert_called_once_with("list_policies")
    mock_iam.get_paginator.return_value.paginate.assert_called_once_with(Scope='All')


def test_collect_attached_only_true():
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

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper, attached_only=True)
    results = collector.collect()

    assert len(results) == 1
    assert any(policy.name == "policy-1" for policy in results)
    assert not any(policy.name == "policy-2" for policy in results)

    mock_iam.get_paginator.return_value.paginate.assert_called_once_with(Scope='Local')


def test_collect_get_policy_error():
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

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper)
    results = collector.collect()

    assert len(results) == 1
    policy1 = results[0]
    assert policy1.name == "policy-1"
    assert policy1.document == {}
    assert policy1.arn == "arn:aws:iam::123456789012:policy/policy-1"
    assert policy1.policy_type == "attached"
    assert policy1.is_inline is False


def test_collect_get_policy_version_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-1", "PolicyName": "policy-1", "AttachmentCount": 1}
            ]
        }
    ]

    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchEntity"}}, "get_policy_version"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper)
    results = collector.collect()

    assert len(results) == 1
    policy1 = results[0]
    assert policy1.document == {}
    assert policy1.arn == "arn:aws:iam::123456789012:policy/policy-1"


def test_collect_empty_policies_list():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Policies": []}
    ]

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper)
    results = collector.collect()

    assert len(results) == 0


def test_collect_missing_policies_key():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {}
    ]

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper)
    results = collector.collect()

    assert len(results) == 0


def test_collect_zero_attachment_count_with_attached_only():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-1", "PolicyName": "policy-1", "AttachmentCount": 0},
                {"Arn": "arn:aws:iam::123456789012:policy/policy-2", "PolicyName": "policy-2"}
            ]
        }
    ]

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper, attached_only=True)
    results = collector.collect()

    assert len(results) == 0


def test_collect_default_parameter():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-1", "PolicyName": "policy-1", "AttachmentCount": 0}
            ]
        }
    ]

    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].name == "policy-1"
    mock_iam.get_paginator.return_value.paginate.assert_called_once_with(Scope='All')


def test_collect_multiple_pages():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-1", "PolicyName": "policy-1", "AttachmentCount": 1}
            ]
        },
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-2", "PolicyName": "policy-2", "AttachmentCount": 1}
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

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = AwsIamPolicyCollector(mock_wrapper)
    results = collector.collect()

    assert len(results) == 2
    assert any(policy.name == "policy-1" for policy in results)
    assert any(policy.name == "policy-2" for policy in results)