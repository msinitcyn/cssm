import pytest
from unittest.mock import patch, MagicMock
from aws_scanner.engines.common.resource_definition import ResourceDefinition


def test_analyze_iam_policy_from_resource_accepts_resource_definition():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="TestPolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "TestPolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    assert isinstance(findings, list)


def test_analyze_iam_policy_from_resource_extracts_policy_document():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="WildcardPolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "WildcardPolicy",
            "PolicyDocument": policy_document
        }
    )

    with patch("aws_scanner.engines.iam_policy.resource_analyzer.analyze_policy") as mock_analyze:
        mock_analyze.return_value = [{"type": "test_finding"}]

        from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

        analyze_iam_policy_from_resource(resource_def)

        mock_analyze.assert_called_once()
        call_args = mock_analyze.call_args[0][0]
        assert hasattr(call_args, 'document')
        assert call_args.document == policy_document


def test_analyze_iam_policy_from_resource_wildcard_all():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="BadPolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "BadPolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_POLICY_WILDCARD_ALL" in vulnerability_ids
    assert "IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION" in vulnerability_ids
    assert "IAM_POLICY_PRIVILEGE_ESCALATION" in vulnerability_ids
    assert "IAM_POLICY_ASSUME_ROLE_WILDCARD" in vulnerability_ids
    assert "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS" in vulnerability_ids


def test_analyze_iam_policy_from_resource_privilege_escalation():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreateRole",
                    "iam:AttachRolePolicy"
                ],
                "Resource": "*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="DeveloperRole",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "DeveloperRole",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_POLICY_PRIVILEGE_ESCALATION" in vulnerability_ids
    assert "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS" in vulnerability_ids


def test_analyze_iam_policy_from_resource_assume_role_wildcard():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="AssumeAnyRolePolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "AssumeAnyRolePolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_POLICY_ASSUME_ROLE_WILDCARD" in vulnerability_ids


def test_analyze_iam_policy_from_resource_sensitive_actions_without_conditions():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:DeleteObject"
                ],
                "Resource": "arn:aws:s3:::example-bucket/*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="S3WritePolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "S3WritePolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS" in vulnerability_ids


def test_analyze_iam_policy_from_resource_no_vulnerabilities():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/public/*",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "192.168.1.0/24"
                    }
                }
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="SafePolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "SafePolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_iam_policy_from_resource_multiple_statements():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/*"
            },
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="MultiStatementPolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "MultiStatementPolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_POLICY_ASSUME_ROLE_WILDCARD" in vulnerability_ids


def test_analyze_iam_policy_from_resource_backward_compatibility():
    from aws_scanner.engines.iam_policy.iam_policy_data import IamPolicyData
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_policy

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

    old_policy_data = IamPolicyData(
        name="TestPolicy",
        policy_type="attached",
        document=policy_document,
        arn="arn:aws:iam::123456789012:policy/TestPolicy",
        is_inline=False
    )

    resource_def = ResourceDefinition(
        logical_id="TestPolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "TestPolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    old_findings = analyze_policy(old_policy_data)
    new_findings = analyze_iam_policy_from_resource(resource_def)

    old_vuln_ids = sorted([f["id"] for f in old_findings])
    new_vuln_ids = sorted([f["id"] for f in new_findings])

    assert old_vuln_ids == new_vuln_ids
    assert len(old_findings) == len(new_findings)


def test_analyze_iam_policy_from_resource_notaction_wildcard_resource():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": "s3:DeleteBucket",
                "Resource": "*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="NotActionPolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "NotActionPolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_POLICY_NOTACTION_WILDCARD_RESOURCE" in vulnerability_ids


def test_analyze_iam_policy_from_resource_notresource_wildcard_action():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "NotResource": "arn:aws:s3:::protected-bucket/*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="NotResourcePolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "NotResourcePolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_POLICY_NOTRESOURCE_WILDCARD_ACTION" in vulnerability_ids


def test_analyze_iam_policy_from_resource_deny_statement_ignored():
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="DenyPolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "DenyPolicy",
            "PolicyDocument": policy_document
        }
    )

    from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource

    findings = analyze_iam_policy_from_resource(resource_def)

    assert len(findings) == 0