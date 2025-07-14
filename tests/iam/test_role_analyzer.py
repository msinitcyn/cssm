from aws_scanner.scanners.iam.role_analyzer import analyze_iam_role
from aws_scanner.scanners.iam.iam_role_data import IamRoleData
from aws_scanner.scanners.iam.iam_policy_data import IamPolicyData

def make_policy(name, policy_type, is_inline, doc):
    return IamPolicyData(
        name=name,
        policy_type=policy_type,
        is_inline=is_inline,
        document=doc
    )

def test_analyze_iam_role_no_policies():
    role = IamRoleData(name="RoleX")
    assert analyze_iam_role(role) == []

def test_analyze_iam_role_inline_and_attached():
    # Inline policy: risky
    inline_policy = make_policy("Inline1", "inline", True, {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    # Attached policy: safe
    attached_policy = make_policy("Attached1", "attached", False, {"Statement": {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "arn:aws:s3:::bucket"}})
    role = IamRoleData(
        name="RoleY",
        inline_policies={"Inline1": inline_policy},
        attached_policies={"Attached1": attached_policy}
    )
    findings = analyze_iam_role(role)
    assert any(f["policy_type"] == "inline" and f["policy_name"] == "Inline1" for f in findings)
    assert not any(f["policy_type"] == "attached" and f["policy_name"] == "Attached1" for f in findings)

def test_analyze_iam_role_multiple_findings():
    # Both policies risky
    inline_policy = make_policy("Inline2", "inline", True, {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    attached_policy = make_policy("Attached2", "attached", False, {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    role = IamRoleData(
        name="RoleZ",
        inline_policies={"Inline2": inline_policy},
        attached_policies={"Attached2": attached_policy}
    )
    findings = analyze_iam_role(role)
    assert any(f["policy_type"] == "inline" and f["policy_name"] == "Inline2" for f in findings)
    assert any(f["policy_type"] == "attached" and f["policy_name"] == "Attached2" for f in findings)
    for f in findings:
        assert f["role"] == "RoleZ"
