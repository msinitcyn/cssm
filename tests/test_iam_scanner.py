import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from aws_scanner.scanners.iam_scanner import (
    is_policy_too_permissive,
    analyze_inline_policies,
    analyze_attached_policies,
    find_overpermissive_roles,
)

def test_api_error_handling_in_policy_analysis():
    # Mock IAM client
    mock_iam = MagicMock()

    # Simulate error in list_role_policies for inline policies
    inline_error = ClientError(
        {'Error': {'Code': 'AccessDenied', 'Message': 'Not authorized'}},
        'ListRolePolicies'
    )
    mock_iam.list_role_policies.side_effect = inline_error

    # Simulate error in list_attached_role_policies for attached policies
    attached_error = ClientError(
        {'Error': {'Code': 'Throttling', 'Message': 'Rate exceeded'}},
        'ListAttachedRolePolicies'
    )
    mock_iam.list_attached_role_policies.side_effect = attached_error

    # Mock paginator for find_overpermissive_roles
    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {'Roles': [{'RoleName': 'TestRole'}]}
    ]

    # Test analyze_inline_policies error reporting
    inline_findings = analyze_inline_policies(mock_iam, 'TestRole')
    assert len(inline_findings) == 1
    assert inline_findings[0]['role'] == 'TestRole'
    assert 'error' in inline_findings[0]
    assert 'AccessDenied' in inline_findings[0]['error']

    # Test analyze_attached_policies error reporting
    attached_findings = analyze_attached_policies(mock_iam, 'TestRole')
    assert len(attached_findings) == 1
    assert attached_findings[0]['role'] == 'TestRole'
    assert 'error' in attached_findings[0]
    assert 'Throttling' in attached_findings[0]['error']

    # Test find_overpermissive_roles aggregates errors from both
    mock_iam.list_role_policies.side_effect = inline_error
    mock_iam.list_attached_role_policies.side_effect = attached_error
    results = find_overpermissive_roles(iam=mock_iam)
    # Should contain both error findings
    assert any('AccessDenied' in finding.get('error', '') for finding in results)
    assert any('Throttling' in finding.get('error', '') for finding in results)

def test_is_policy_too_permissive_detects_wildcard():
    # Policy with Action="*" and Resource="*"
    policy_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    assert is_policy_too_permissive(policy_doc) is True

    # Policy with Action as list containing "*"
    policy_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:Describe*", "*"],
                "Resource": ["*", "arn:aws:s3:::bucket"]
            }
        ]
    }
    assert is_policy_too_permissive(policy_doc) is True

    # Policy with no wildcard
    policy_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:Describe*"],
                "Resource": ["arn:aws:s3:::bucket"]
            }
        ]
    }
    assert is_policy_too_permissive(policy_doc) is False

def test_analyze_inline_policies_detects_overpermissive():
    mock_iam = MagicMock()
    mock_iam.list_role_policies.return_value = {'PolicyNames': ['InlinePolicy1']}
    mock_iam.get_role_policy.return_value = {
        'PolicyDocument': {
            'Statement': [
                {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}
            ]
        }
    }
    findings = analyze_inline_policies(mock_iam, 'TestRole')
    assert len(findings) == 1
    finding = findings[0]
    assert finding['role'] == 'TestRole'
    assert finding['policy_type'] == 'inline'
    assert finding['policy_name'] == 'InlinePolicy1'
    assert 'Too permissive' in finding['issue']

def test_analyze_attached_policies_detects_overpermissive():
    mock_iam = MagicMock()
    mock_iam.list_attached_role_policies.return_value = {
        'AttachedPolicies': [
            {'PolicyName': 'AttachedPolicy1', 'PolicyArn': 'arn:aws:iam::123456789012:policy/AttachedPolicy1'}
        ]
    }
    mock_iam.get_policy.return_value = {
        'Policy': {'DefaultVersionId': 'v1'}
    }
    mock_iam.get_policy_version.return_value = {
        'PolicyVersion': {
            'Document': {
                'Statement': [
                    {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}
                ]
            }
        }
    }
    findings = analyze_attached_policies(mock_iam, 'TestRole')
    assert len(findings) == 1
    finding = findings[0]
    assert finding['role'] == 'TestRole'
    assert finding['policy_type'] == 'attached'
    assert finding['policy_name'] == 'AttachedPolicy1'
    assert finding['policy_arn'] == 'arn:aws:iam::123456789012:policy/AttachedPolicy1'
    assert 'Too permissive' in finding['issue']

def test_is_policy_too_permissive_handles_malformed_policy():
    # No Statement field
    policy_doc = {}
    assert is_policy_too_permissive(policy_doc) is False

    # Statement is not a list
    policy_doc = {'Statement': None}
    assert is_policy_too_permissive(policy_doc) is False

    # Statement with missing Effect
    policy_doc = {'Statement': [{}]}
    assert is_policy_too_permissive(policy_doc) is False

    # Statement with Effect != Allow
    policy_doc = {'Statement': [{'Effect': 'Deny', 'Action': '*', 'Resource': '*'}]}
    assert is_policy_too_permissive(policy_doc) is False

    # Statement with missing Action/Resource
    policy_doc = {'Statement': [{'Effect': 'Allow'}]}
    assert is_policy_too_permissive(policy_doc) is False

def test_find_overpermissive_roles_no_roles():
    mock_iam = MagicMock()
    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{'Roles': []}]
    results = find_overpermissive_roles(iam=mock_iam)
    assert results == []

def test_analyze_attached_policies_missing_policy_version():
    mock_iam = MagicMock()
    mock_iam.list_attached_role_policies.return_value = {
        'AttachedPolicies': [
            {'PolicyName': 'AttachedPolicy1', 'PolicyArn': 'arn:aws:iam::123456789012:policy/AttachedPolicy1'}
        ]
    }
    # get_policy returns a default version id that does not exist
    mock_iam.get_policy.return_value = {
        'Policy': {'DefaultVersionId': 'v999'}
    }
    # get_policy_version raises ClientError for missing version
    mock_iam.get_policy_version.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchEntity', 'Message': 'Policy version does not exist'}},
        'GetPolicyVersion'
    )
    findings = analyze_attached_policies(mock_iam, 'TestRole')
    assert len(findings) == 1
    finding = findings[0]
    assert finding['role'] == 'TestRole'
    assert finding['policy_type'] == 'attached'
    assert finding['policy_name'] == 'AttachedPolicy1'
    assert finding['policy_arn'] == 'arn:aws:iam::123456789012:policy/AttachedPolicy1'
    assert 'error' in finding
    assert 'NoSuchEntity' in finding['error']

