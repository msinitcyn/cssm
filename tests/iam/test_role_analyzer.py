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
    result = analyze_iam_role(role)
    assert result["role"] == "RoleX"
    assert result["policies"] == []

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
    result = analyze_iam_role(role)
    assert result["role"] == "RoleY"
    policies = {p["name"]: p for p in result["policies"]}
    assert "Inline1" in policies
    assert "Attached1" in policies
    # Inline1 should have issues, Attached1 should not
    assert len(policies["Inline1"]["issues"]) > 0
    assert policies["Inline1"]["type"] == "inline"
    assert policies["Attached1"]["issues"] == []
    assert policies["Attached1"]["type"] == "attached"

def test_analyze_iam_role_multiple_findings():
    # Both policies risky
    inline_policy = make_policy("Inline2", "inline", True, {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    attached_policy = make_policy("Attached2", "attached", False, {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    role = IamRoleData(
        name="RoleZ",
        inline_policies={"Inline2": inline_policy},
        attached_policies={"Attached2": attached_policy}
    )
    result = analyze_iam_role(role)
    assert result["role"] == "RoleZ"
    policies = {p["name"]: p for p in result["policies"]}
    assert "Inline2" in policies
    assert "Attached2" in policies
    assert len(policies["Inline2"]["issues"]) > 0
    assert len(policies["Attached2"]["issues"]) > 0
    assert policies["Inline2"]["type"] == "inline"
    assert policies["Attached2"]["type"] == "attached"

def test_analyze_iam_role_trust_policy_issue():
    # Trust policy allows broad sts:AssumeRole with no restrictive condition
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }
        ]
    }
    role = IamRoleData(name="RoleTrust", trust_policy_document=trust_policy)
    result = analyze_iam_role(role)
    assert result["role"] == "RoleTrust"
    assert result["trust_policy_issues"], "Should detect a trust policy issue"
    issue = result["trust_policy_issues"][0]
    assert issue["id"] == "IAM_ROLE_BROAD_ASSUME_ROLE"
    assert "AssumeRole" in issue["description"]
