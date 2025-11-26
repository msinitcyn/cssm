from unittest.mock import MagicMock
import botocore.exceptions
import pytest
from aws_scanner.engines.iam_policy.resource_aws_iam_policy_collector import ResourceAwsIamPolicyCollector
from aws_scanner.engines.common.resource_definition import ResourceCollection
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


def test_collect_returns_resource_collection():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/TestPolicy", "PolicyName": "TestPolicy"}
            ]
        }
    ]
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamPolicyCollector(mock_wrapper, attached_only=False)
    result = collector.collect()

    assert isinstance(result, ResourceCollection)


def test_policy_becomes_resource_definition_with_correct_type():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/TestPolicy", "PolicyName": "TestPolicy"}
            ]
        }
    ]
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamPolicyCollector(mock_wrapper, attached_only=False)
    result = collector.collect()

    assert len(result.resources) == 1
    resource = result.resources["TestPolicy"]
    assert resource.resource_type == "AWS::IAM::Policy"


def test_policy_properties_include_name_and_document():
    mock_iam = MagicMock()
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]
    }
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/TestPolicy", "PolicyName": "TestPolicy"}
            ]
        }
    ]
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {"PolicyVersion": {"Document": policy_doc}}

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamPolicyCollector(mock_wrapper, attached_only=False)
    result = collector.collect()

    resource = result.resources["TestPolicy"]
    assert resource.properties["PolicyName"] == "TestPolicy"
    assert resource.properties["PolicyDocument"] == policy_doc


def test_attached_only_true_filters_unattached():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/AttachedPolicy", "PolicyName": "AttachedPolicy", "AttachmentCount": 1},
                {"Arn": "arn:aws:iam::123456789012:policy/UnattachedPolicy", "PolicyName": "UnattachedPolicy", "AttachmentCount": 0}
            ]
        }
    ]
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamPolicyCollector(mock_wrapper, attached_only=True)
    result = collector.collect()

    assert len(result.resources) == 1
    assert "AttachedPolicy" in result.resources
    assert "UnattachedPolicy" not in result.resources


def test_attached_only_false_includes_all():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/AttachedPolicy", "PolicyName": "AttachedPolicy", "AttachmentCount": 1},
                {"Arn": "arn:aws:iam::123456789012:policy/UnattachedPolicy", "PolicyName": "UnattachedPolicy", "AttachmentCount": 0}
            ]
        }
    ]
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamPolicyCollector(mock_wrapper, attached_only=False)
    result = collector.collect()

    assert len(result.resources) == 2
    assert "AttachedPolicy" in result.resources
    assert "UnattachedPolicy" in result.resources


def test_handles_pagination():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/Policy1", "PolicyName": "Policy1"}
            ]
        },
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/Policy2", "PolicyName": "Policy2"}
            ]
        }
    ]
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamPolicyCollector(mock_wrapper, attached_only=False)
    result = collector.collect()

    assert len(result.resources) == 2
    assert "Policy1" in result.resources
    assert "Policy2" in result.resources


def test_handles_get_policy_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/FailPolicy", "PolicyName": "FailPolicy"}
            ]
        }
    ]
    mock_iam.get_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "Policy not found"}},
        "GetPolicy"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamPolicyCollector(mock_wrapper, attached_only=False)
    result = collector.collect()

    assert len(result.resources) == 0


def test_handles_get_policy_version_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/FailPolicy", "PolicyName": "FailPolicy"}
            ]
        }
    ]
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchEntity", "Message": "Version not found"}},
        "GetPolicyVersion"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_iam.return_value = mock_iam

    collector = ResourceAwsIamPolicyCollector(mock_wrapper, attached_only=False)
    result = collector.collect()

    assert len(result.resources) == 0
