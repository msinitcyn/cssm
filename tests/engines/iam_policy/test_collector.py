from unittest.mock import patch, MagicMock
import botocore.exceptions


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

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies(attached_only=False)

        assert len(results) == 2
        assert "policy-1" in results
        assert "policy-2" in results
        assert results["policy-1"].arn == "arn:aws:iam::123456789012:policy/policy-1"
        assert results["policy-1"].name == "policy-1"
        assert results["policy-1"].policy_type == "attached"
        assert results["policy-1"].is_inline is False
        assert results["policy-1"].document == {"Version": "2012-10-17", "Statement": []}

        mock_iam.get_paginator.assert_called_once_with("list_policies")
        mock_iam.get_paginator.return_value.paginate.assert_called_once_with(Scope='All')


def test_collect_iam_policies_attached_only_true():
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

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies(attached_only=True)

        assert len(results) == 1
        assert "policy-1" in results
        assert "policy-2" not in results

        mock_iam.get_paginator.return_value.paginate.assert_called_once_with(Scope='Local')


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

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies(attached_only=False)

        assert len(results) == 1
        assert "policy-1" in results
        assert results["policy-1"].document == {}
        assert results["policy-1"].arn == "arn:aws:iam::123456789012:policy/policy-1"
        assert results["policy-1"].name == "policy-1"
        assert results["policy-1"].policy_type == "attached"
        assert results["policy-1"].is_inline is False


def test_collect_iam_policies_get_policy_version_error():
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

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies(attached_only=False)

        assert len(results) == 1
        assert "policy-1" in results
        assert results["policy-1"].document == {}
        assert results["policy-1"].arn == "arn:aws:iam::123456789012:policy/policy-1"


def test_collect_iam_policies_empty_policies_list():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Policies": []}
    ]

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies(attached_only=False)

        assert len(results) == 0


def test_collect_iam_policies_missing_policies_key():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {}
    ]

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies(attached_only=False)

        assert len(results) == 0


def test_collect_iam_policies_zero_attachment_count_with_attached_only():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {
            "Policies": [
                {"Arn": "arn:aws:iam::123456789012:policy/policy-1", "PolicyName": "policy-1", "AttachmentCount": 0},
                {"Arn": "arn:aws:iam::123456789012:policy/policy-2", "PolicyName": "policy-2"}
            ]
        }
    ]

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies(attached_only=True)

        assert len(results) == 0


def test_collect_iam_policies_default_parameter():
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

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies()

        assert len(results) == 1
        assert "policy-1" in results
        mock_iam.get_paginator.return_value.paginate.assert_called_once_with(Scope='All')


def test_collect_iam_policies_multiple_pages():
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

    with patch("aws_scanner.engines.iam_policy.collector.boto3Wrapper") as mock_wrapper:
        mock_wrapper.get_iam.return_value = mock_iam

        from aws_scanner.engines.iam_policy.collector import collect_iam_policies
        results = collect_iam_policies(attached_only=False)

        assert len(results) == 2
        assert "policy-1" in results
        assert "policy-2" in results