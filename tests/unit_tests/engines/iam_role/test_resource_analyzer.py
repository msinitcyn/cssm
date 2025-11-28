from aws_scanner.engines.common.resource_definition import ResourceDefinition


def test_analyze_iam_role_from_resource_accepts_resource_definition():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="LambdaExecutionRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "LambdaExecutionRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    assert isinstance(findings, list)


def test_analyze_iam_role_from_resource_extracts_assume_role_policy_document():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="BroadRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "BroadRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids


def test_analyze_iam_role_from_resource_broad_trust_policy_wildcard_principal():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="WildcardRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "WildcardRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids
    assert len(findings) == 1


def test_analyze_iam_role_from_resource_broad_trust_policy_aws_wildcard():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="AWSWildcardRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "AWSWildcardRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids


def test_analyze_iam_role_from_resource_restrictive_trust_policy():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="SecureRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "SecureRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_iam_role_from_resource_wildcard_with_restrictive_condition():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "192.168.1.0/24"
                    }
                }
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="ConditionalRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "ConditionalRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_iam_role_from_resource_wildcard_without_restrictive_condition():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "some-id"
                    }
                }
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="NonRestrictiveConditionRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "NonRestrictiveConditionRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids


def test_analyze_iam_role_from_resource_does_not_analyze_policies():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="RoleWithReferences",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "RoleWithReferences",
            "AssumeRolePolicyDocument": assume_role_policy,
            "ManagedPolicyArns": [
                "arn:aws:iam::aws:policy/AdministratorAccess"
            ]
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_iam_role_from_resource_deny_statement_ignored():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="DenyRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "DenyRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_iam_role_from_resource_multiple_statements():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            },
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="MultiStatementRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "MultiStatementRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids
    assert len(findings) == 1


def test_analyze_iam_role_from_resource_backward_compatibility_trust_policy_document_alias():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="AliasRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "AliasRole",
            "trust_policy_document": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids


def test_analyze_iam_role_from_resource_statement_as_dict():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole"
        }
    }

    resource_def = ResourceDefinition(
        logical_id="DictStatementRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "DictStatementRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids


def test_analyze_iam_role_from_resource_action_as_string():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="StringActionRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "StringActionRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids


def test_analyze_iam_role_from_resource_action_as_list():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["sts:AssumeRole"]
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="ListActionRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "ListActionRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "IAM_ROLE_BROAD_ASSUME_ROLE" in vulnerability_ids


def test_analyze_iam_role_from_resource_non_assume_role_action_ignored():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:GetCallerIdentity"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="NonAssumeRoleAction",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "NonAssumeRoleAction",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_iam_role_from_resource_specific_principal():
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:root"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    resource_def = ResourceDefinition(
        logical_id="SpecificPrincipalRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "SpecificPrincipalRole",
            "AssumeRolePolicyDocument": assume_role_policy
        }
    )

    from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource

    findings = analyze_iam_role_from_resource(resource_def)

    assert len(findings) == 0
