from aws_scanner.scanners.iam.policy_analyzer import analyze_policy, analyze_statement, is_restrictive
from aws_scanner.scanners.iam.iam_policy_data import IamPolicyData
from aws_scanner.core.vulnerabilities import VULNERABILITIES

def make_policy(document):
    return IamPolicyData(name="p", policy_type="inline", document=document, is_inline=True)

def test_analyze_policy_no_statements():
    policy = make_policy({})
    assert analyze_policy(policy) == []

def test_analyze_policy_non_allow():
    policy = make_policy({
        "Statement": {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }
    })
    assert analyze_policy(policy) == []

def test_analyze_policy_allow_and_risky():
    policy = make_policy({
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    })
    findings = analyze_policy(policy)
    assert findings
    assert findings[0]["issue"]["id"] == VULNERABILITIES["IAM_POLICY_WILDCARD_ALL"].id

def test_analyze_policy_multiple_statements():
    policy = make_policy({
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": ["ec2:Describe*"],
                "Resource": ["arn:aws:s3:::bucket"]
            }
        ]
    })
    findings = analyze_policy(policy)
    assert len(findings) == 1
    assert findings[0]["issue"]["id"] == VULNERABILITIES["IAM_POLICY_WILDCARD_ALL"].id

def test_analyze_statement_patterns():
    # Action=* and Resource=*
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
    }
    assert analyze_statement(stmt)["id"] == VULNERABILITIES["IAM_POLICY_WILDCARD_ALL"].id
    # NotAction + wildcard Resource
    stmt = {
        "Effect": "Allow",
        "NotAction": "ec2:Describe*",
        "Resource": "*"
    }
    assert analyze_statement(stmt)["id"] == VULNERABILITIES["IAM_POLICY_NOTACTION_WILDCARD_RESOURCE"].id
    # NotResource + wildcard Action
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "NotResource": "arn:aws:s3:::bucket"
    }
    assert analyze_statement(stmt)["id"] == VULNERABILITIES["IAM_POLICY_NOTRESOURCE_WILDCARD_ACTION"].id
    # Wildcard Action + Condition
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "arn:aws:s3:::bucket",
        "Condition": {
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
    }
    assert analyze_statement(stmt)["id"] == VULNERABILITIES["IAM_POLICY_WILDCARD_ACTION_CONDITION"].id
    # NotAction + Condition
    stmt = {
        "Effect": "Allow",
        "NotAction": "ec2:Describe*",
        "Resource": "arn:aws:s3:::bucket",
        "Condition": {
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
    }
    assert analyze_statement(stmt)["id"] == VULNERABILITIES["IAM_POLICY_NOTACTION_CONDITION"].id
    # Safe statement
    stmt = {
        "Effect": "Allow",
        "Action": ["ec2:Describe*"],
        "Resource": ["arn:aws:s3:::bucket"]
    }
    assert analyze_statement(stmt) is None

def test_is_restrictive_true():
    cond = {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}
    assert is_restrictive(cond) is True

def test_is_restrictive_false():
    cond = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    assert is_restrictive(cond) is False

def test_analyze_statement_wildcard_without_restrictive_condition():
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "arn:aws:s3:::bucket"
        # No Condition
    }
    assert analyze_statement(stmt)["id"] == VULNERABILITIES["IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION"].id

def test_analyze_statement_wildcard_with_mfa_condition():
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "arn:aws:s3:::bucket",
        "Condition": {
            "Bool": {
                "aws:MultiFactorAuthPresent": "true"
            }
        }
    }
    assert analyze_statement(stmt)["id"] == VULNERABILITIES["IAM_POLICY_WILDCARD_ACTION_CONDITION"].id
