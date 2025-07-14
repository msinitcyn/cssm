from aws_scanner.scanners.iam.policy_analyzer import analyze_policy, analyze_statement
from aws_scanner.scanners.iam.iam_policy_data import IamPolicyData

def make_policy(document):
    return IamPolicyData(name="p", policy_type="inline", document=document, is_inline=True)

def test_analyze_policy_no_statements():
    policy = make_policy({})
    assert analyze_policy(policy) == []

def test_analyze_policy_non_allow():
    policy = make_policy({"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}})
    assert analyze_policy(policy) == []

def test_analyze_policy_allow_and_risky():
    policy = make_policy({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    findings = analyze_policy(policy)
    assert findings
    assert "Too permissive" in findings[0]["issue"]

def test_analyze_policy_multiple_statements():
    policy = make_policy({
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": ["arn:aws:s3:::bucket"]}
        ]
    })
    findings = analyze_policy(policy)
    assert len(findings) == 1
    assert "Too permissive" in findings[0]["issue"]

def test_analyze_statement_patterns():
    # Action=* and Resource=*
    stmt = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    assert "Too permissive" in analyze_statement(stmt)
    # NotAction + wildcard Resource
    stmt = {"Effect": "Allow", "NotAction": "ec2:Describe*", "Resource": "*"}
    assert "NotAction + wildcard Resource" in analyze_statement(stmt)
    # NotResource + wildcard Action
    stmt = {"Effect": "Allow", "Action": "*", "NotResource": "arn:aws:s3:::bucket"}
    assert "NotResource + wildcard Action" in analyze_statement(stmt)
    # Wildcard Action + Condition
    stmt = {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    assert "Wildcard Action + Condition" in analyze_statement(stmt)
    # NotAction + Condition
    stmt = {"Effect": "Allow", "NotAction": "ec2:Describe*", "Resource": "arn:aws:s3:::bucket", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    assert "NotAction + Condition" in analyze_statement(stmt)
    # Safe statement
    stmt = {"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": ["arn:aws:s3:::bucket"]}
    assert analyze_statement(stmt) is None
