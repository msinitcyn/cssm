from unittest.mock import patch
from aws_scanner.engines.iam_role.iam_role_data import IamRoleData
from aws_scanner.engines.common.iam_policy_data import IamPolicyData


def test_analyze_assume_role_policy_broad_principal_no_condition():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": "*"
        }
    }

    with patch("aws_scanner.engines.iam_role.analyzer.VULNERABILITIES") as mock_vuln:
        mock_finding = {"type": "IAM_ROLE_BROAD_ASSUME_ROLE", "data": "test"}
        mock_vuln.__getitem__.return_value.instantiate.return_value = mock_finding

        from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
        findings = analyze_assume_role_policy(trust_policy)

        assert len(findings) == 1
        assert findings[0] == mock_finding


def test_analyze_assume_role_policy_broad_principal_aws_wildcard():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": "*"}
        }
    }

    with patch("aws_scanner.engines.iam_role.analyzer.VULNERABILITIES") as mock_vuln:
        mock_finding = {"type": "IAM_ROLE_BROAD_ASSUME_ROLE", "data": "test"}
        mock_vuln.__getitem__.return_value.instantiate.return_value = mock_finding

        from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
        findings = analyze_assume_role_policy(trust_policy)

        assert len(findings) == 1


def test_analyze_assume_role_policy_broad_principal_with_restrictive_condition():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": "*",
            "Condition": {"StringEquals": {"aws:userid": "specific-user"}}
        }
    }

    with patch("aws_scanner.engines.iam_role.analyzer.is_restrictive") as mock_restrictive:
        mock_restrictive.return_value = True

        from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
        findings = analyze_assume_role_policy(trust_policy)

        assert len(findings) == 0


def test_analyze_assume_role_policy_broad_principal_with_non_restrictive_condition():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "*"}}
        }
    }

    with patch("aws_scanner.engines.iam_role.analyzer.is_restrictive") as mock_restrictive:
        mock_restrictive.return_value = False

        with patch("aws_scanner.engines.iam_role.analyzer.VULNERABILITIES") as mock_vuln:
            mock_finding = {"type": "IAM_ROLE_BROAD_ASSUME_ROLE", "data": "test"}
            mock_vuln.__getitem__.return_value.instantiate.return_value = mock_finding

            from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
            findings = analyze_assume_role_policy(trust_policy)

            assert len(findings) == 1


def test_analyze_assume_role_policy_specific_principal():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": "arn:aws:iam::123456789012:user/specific-user"}
        }
    }

    from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
    findings = analyze_assume_role_policy(trust_policy)

    assert len(findings) == 0


def test_analyze_assume_role_policy_deny_effect():
    trust_policy = {
        "Statement": {
            "Effect": "Deny",
            "Action": "sts:AssumeRole",
            "Principal": "*"
        }
    }

    from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
    findings = analyze_assume_role_policy(trust_policy)

    assert len(findings) == 0


def test_analyze_assume_role_policy_different_action():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Principal": "*"
        }
    }

    from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
    findings = analyze_assume_role_policy(trust_policy)

    assert len(findings) == 0


def test_analyze_assume_role_policy_multiple_actions_with_assume_role():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "sts:AssumeRole"],
            "Principal": "*"
        }
    }

    with patch("aws_scanner.engines.iam_role.analyzer.VULNERABILITIES") as mock_vuln:
        mock_finding = {"type": "IAM_ROLE_BROAD_ASSUME_ROLE", "data": "test"}
        mock_vuln.__getitem__.return_value.instantiate.return_value = mock_finding

        from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
        findings = analyze_assume_role_policy(trust_policy)

        assert len(findings) == 1


def test_analyze_assume_role_policy_multiple_statements():
    trust_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/specific-user"}
            },
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": "*"
            }
        ]
    }

    with patch("aws_scanner.engines.iam_role.analyzer.VULNERABILITIES") as mock_vuln:
        mock_finding = {"type": "IAM_ROLE_BROAD_ASSUME_ROLE", "data": "test"}
        mock_vuln.__getitem__.return_value.instantiate.return_value = mock_finding

        from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
        findings = analyze_assume_role_policy(trust_policy)

        assert len(findings) == 1


def test_analyze_assume_role_policy_single_statement_as_dict():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": "*"
        }
    }

    with patch("aws_scanner.engines.iam_role.analyzer.VULNERABILITIES") as mock_vuln:
        mock_finding = {"type": "IAM_ROLE_BROAD_ASSUME_ROLE", "data": "test"}
        mock_vuln.__getitem__.return_value.instantiate.return_value = mock_finding

        from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
        findings = analyze_assume_role_policy(trust_policy)

        assert len(findings) == 1


def test_analyze_assume_role_policy_empty_statements():
    trust_policy = {"Statement": []}

    from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
    findings = analyze_assume_role_policy(trust_policy)

    assert len(findings) == 0


def test_analyze_assume_role_policy_no_statements():
    trust_policy = {}

    from aws_scanner.engines.iam_role.analyzer import analyze_assume_role_policy
    findings = analyze_assume_role_policy(trust_policy)

    assert len(findings) == 0


def test_analyze_iam_role_with_trust_policy_only():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": "*"
        }
    }

    role_data = IamRoleData(
        name="test-role",
        trust_policy_document=trust_policy
    )

    with patch("aws_scanner.engines.iam_role.analyzer.VULNERABILITIES") as mock_vuln:
        mock_finding = {"type": "IAM_ROLE_BROAD_ASSUME_ROLE", "data": "test"}
        mock_vuln.__getitem__.return_value.instantiate.return_value = mock_finding

        from aws_scanner.engines.iam_role.analyzer import analyze_iam_role
        findings = analyze_iam_role(role_data)

        assert len(findings) == 1


def test_analyze_iam_role_with_inline_policies():
    inline_policy = IamPolicyData(
        name="inline-policy",
        policy_type="inline",
        document={"Version": "2012-10-17", "Statement": []},
        is_inline=True
    )

    role_data = IamRoleData(
        name="test-role",
        inline_policies=[inline_policy]
    )

    with patch("aws_scanner.engines.iam_role.analyzer.analyze_policy") as mock_analyze:
        mock_analyze.return_value = [{"type": "test_finding"}]

        from aws_scanner.engines.iam_role.analyzer import analyze_iam_role
        findings = analyze_iam_role(role_data)

        assert len(findings) == 1
        assert findings[0]["policy_name"] == "inline-policy"
        assert findings[0]["policy_type"] == "inline"


def test_analyze_iam_role_with_attached_policies():
    attached_policy = IamPolicyData(
        name="attached-policy",
        policy_type="attached",
        document={"Version": "2012-10-17", "Statement": []},
        arn="arn:aws:iam::123456789012:policy/attached-policy",
        is_inline=False
    )

    role_data = IamRoleData(
        name="test-role",
        attached_policies=[attached_policy]
    )

    with patch("aws_scanner.engines.iam_role.analyzer.analyze_policy") as mock_analyze:
        mock_analyze.return_value = [{"type": "test_finding"}]

        from aws_scanner.engines.iam_role.analyzer import analyze_iam_role
        findings = analyze_iam_role(role_data)

        assert len(findings) == 1
        assert findings[0]["policy_name"] == "attached-policy"
        assert findings[0]["policy_type"] == "attached"


def test_analyze_iam_role_comprehensive():
    trust_policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": "*"
        }
    }

    inline_policy = IamPolicyData(
        name="inline-policy",
        policy_type="inline",
        document={"Version": "2012-10-17", "Statement": []},
        is_inline=True
    )

    attached_policy = IamPolicyData(
        name="attached-policy",
        policy_type="attached",
        document={"Version": "2012-10-17", "Statement": []},
        arn="arn:aws:iam::123456789012:policy/attached-policy",
        is_inline=False
    )

    role_data = IamRoleData(
        name="test-role",
        trust_policy_document=trust_policy,
        inline_policies=[inline_policy],
        attached_policies=[attached_policy]
    )

    with patch("aws_scanner.engines.iam_role.analyzer.VULNERABILITIES") as mock_vuln:
        mock_trust_finding = {"type": "IAM_ROLE_BROAD_ASSUME_ROLE", "data": "trust"}
        mock_vuln.__getitem__.return_value.instantiate.return_value = mock_trust_finding

        with patch("aws_scanner.engines.iam_role.analyzer.analyze_policy") as mock_analyze:
            mock_analyze.return_value = [{"type": "policy_finding"}]

            from aws_scanner.engines.iam_role.analyzer import analyze_iam_role
            findings = analyze_iam_role(role_data)

            assert len(findings) == 3
            trust_findings = [f for f in findings if f.get("type") == "IAM_ROLE_BROAD_ASSUME_ROLE"]
            policy_findings = [f for f in findings if f.get("type") == "policy_finding"]
            assert len(trust_findings) == 1
            assert len(policy_findings) == 2


def test_analyze_iam_role_no_trust_policy():
    role_data = IamRoleData(name="test-role")

    from aws_scanner.engines.iam_role.analyzer import analyze_iam_role
    findings = analyze_iam_role(role_data)

    assert len(findings) == 0


def test_analyze_iam_role_multiple_policy_findings():
    inline_policy = IamPolicyData(
        name="inline-policy",
        policy_type="inline",
        document={"Version": "2012-10-17", "Statement": []},
        is_inline=True
    )

    role_data = IamRoleData(
        name="test-role",
        inline_policies=[inline_policy]
    )

    with patch("aws_scanner.engines.iam_role.analyzer.analyze_policy") as mock_analyze:
        mock_analyze.return_value = [
            {"type": "finding1"},
            {"type": "finding2"}
        ]

        from aws_scanner.engines.iam_role.analyzer import analyze_iam_role
        findings = analyze_iam_role(role_data)

        assert len(findings) == 2
        for finding in findings:
            assert finding["policy_name"] == "inline-policy"
            assert finding["policy_type"] == "inline"