from unittest.mock import patch, MagicMock, call
from aws_scanner.engines.common.iam_policy_data import IamPolicyData


def test_is_restrictive_with_source_ip():
    from aws_scanner.engines.common.policy_analyzer_utils import is_restrictive

    condition = {
        "IpAddress": {
            "aws:SourceIp": "192.168.1.0/24"
        }
    }

    assert is_restrictive(condition) is True


def test_is_restrictive_with_vpc_source_ip():
    from aws_scanner.engines.common.policy_analyzer_utils import is_restrictive

    condition = {
        "IpAddress": {
            "aws:VpcSourceIp": "10.0.0.0/16"
        }
    }

    assert is_restrictive(condition) is True


def test_is_restrictive_with_source_vpc():
    from aws_scanner.engines.common.policy_analyzer_utils import is_restrictive

    condition = {
        "StringEquals": {
            "aws:SourceVpc": "vpc-12345678"
        }
    }

    assert is_restrictive(condition) is True


def test_is_restrictive_with_principal_org_id():
    from aws_scanner.engines.common.policy_analyzer_utils import is_restrictive

    condition = {
        "StringEquals": {
            "aws:PrincipalOrgId": "o-example12345"
        }
    }

    assert is_restrictive(condition) is True


def test_is_restrictive_with_non_restrictive_key():
    from aws_scanner.engines.common.policy_analyzer_utils import is_restrictive

    condition = {
        "StringEquals": {
            "aws:userid": "AIDACKCEVSQ6C2EXAMPLE"
        }
    }

    assert is_restrictive(condition) is False


def test_is_restrictive_with_non_dict_condition():
    from aws_scanner.engines.common.policy_analyzer_utils import is_restrictive

    assert is_restrictive("not a dict") is False
    assert is_restrictive(None) is False
    assert is_restrictive([]) is False


def test_is_restrictive_with_non_dict_cond_block():
    from aws_scanner.engines.common.policy_analyzer_utils import is_restrictive

    condition = {
        "StringEquals": "not a dict"
    }

    assert is_restrictive(condition) is False


def test_analyze_statement_wildcard_all():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_ALL")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_PRIVILEGE_ESCALATION")
        assert mock_vuln.instantiate.call_count == 3


def test_analyze_statement_notaction_wildcard_resource():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "NotAction": "s3:DeleteBucket",
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_called_with("IAM_POLICY_NOTACTION_WILDCARD_RESOURCE")
        mock_vuln.instantiate.assert_called_once_with("policy", raw_data=stmt)


def test_analyze_statement_notresource_wildcard_action():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "NotResource": "arn:aws:s3:::sensitive-bucket/*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_NOTRESOURCE_WILDCARD_ACTION")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION")
        assert mock_vuln.instantiate.call_count == 2


def test_analyze_statement_wildcard_action_condition():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "arn:aws:s3:::bucket/*",
        "Condition": {
            "StringEquals": {
                "s3:prefix": "home/"
            }
        }
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_ACTION_CONDITION")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION")
        assert mock_vuln.instantiate.call_count == 2


def test_analyze_statement_notaction_condition():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "NotAction": "s3:DeleteBucket",
        "Resource": "arn:aws:s3:::bucket/*",
        "Condition": {
            "StringEquals": {
                "s3:prefix": "home/"
            }
        }
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_called_with("IAM_POLICY_NOTACTION_CONDITION")
        mock_vuln.instantiate.assert_called_once_with("policy", raw_data=stmt)


def test_analyze_statement_wildcard_without_restrictive_condition():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "arn:aws:s3:::bucket/*",
        "Condition": {
            "StringEquals": {
                "s3:prefix": "home/"
            }
        }
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        with patch("aws_scanner.engines.common.policy_analyzer_utils.is_restrictive", return_value=False):
            mock_vuln = MagicMock()
            mock_vulns.__getitem__.return_value = mock_vuln

            analyze_statement(stmt)

            assert mock_vulns.__getitem__.call_count == 2
            mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_ACTION_CONDITION")
            mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION")

            assert mock_vuln.instantiate.call_count == 2
            mock_vuln.instantiate.assert_has_calls([
                call("policy", raw_data=stmt),
                call("policy", raw_data=stmt)
            ])


def test_analyze_statement_no_findings():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::bucket/*"
    }

    findings = analyze_statement(stmt)

    assert len(findings) == 0


def test_analyze_statement_with_action_list():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "*"],
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_ALL")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_PRIVILEGE_ESCALATION")
        assert mock_vuln.instantiate.call_count == 3


def test_analyze_statement_with_resource_list():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": ["arn:aws:s3:::bucket/*", "*"]
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_ALL")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_PRIVILEGE_ESCALATION")
        assert mock_vuln.instantiate.call_count == 3


def test_analyze_statement_empty_action_resource():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow"
    }

    findings = analyze_statement(stmt)

    assert len(findings) == 0


def test_analyze_policy_single_statement():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_policy

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    }

    policy = IamPolicyData(
        name="test-policy",
        policy_type="attached",
        arn="arn:aws:iam::123456789012:policy/test-policy",
        document=policy_doc,
        is_inline=False
    )

    with patch("aws_scanner.engines.common.policy_analyzer_utils.analyze_statement") as mock_analyze:
        mock_analyze.return_value = ["finding1"]

        findings = analyze_policy(policy)

        assert len(findings) == 1
        mock_analyze.assert_called_once_with(policy_doc["Statement"])


def test_analyze_policy_multiple_statements():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_policy

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}
        ]
    }

    policy = IamPolicyData(
        name="test-policy",
        policy_type="attached",
        arn="arn:aws:iam::123456789012:policy/test-policy",
        document=policy_doc,
        is_inline=False
    )

    with patch("aws_scanner.engines.common.policy_analyzer_utils.analyze_statement") as mock_analyze:
        mock_analyze.side_effect = [["finding1"], []]

        findings = analyze_policy(policy)

        assert len(findings) == 1
        assert mock_analyze.call_count == 2


def test_analyze_policy_deny_statement_ignored():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_policy

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}
        ]
    }

    policy = IamPolicyData(
        name="test-policy",
        policy_type="attached",
        arn="arn:aws:iam::123456789012:policy/test-policy",
        document=policy_doc,
        is_inline=False
    )

    with patch("aws_scanner.engines.common.policy_analyzer_utils.analyze_statement") as mock_analyze:
        mock_analyze.return_value = []

        analyze_policy(policy)

        mock_analyze.assert_called_once_with(policy_doc["Statement"][1])


def test_analyze_policy_no_statements():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_policy

    policy_doc = {
        "Version": "2012-10-17"
    }

    policy = IamPolicyData(
        name="test-policy",
        policy_type="attached",
        arn="arn:aws:iam::123456789012:policy/test-policy",
        document=policy_doc,
        is_inline=False
    )

    findings = analyze_policy(policy)

    assert len(findings) == 0


def test_analyze_policy_empty_statements():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_policy

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": []
    }

    policy = IamPolicyData(
        name="test-policy",
        policy_type="attached",
        arn="arn:aws:iam::123456789012:policy/test-policy",
        document=policy_doc,
        is_inline=False
    )

    findings = analyze_policy(policy)

    assert len(findings) == 0

def test_privilege_escalation_specific():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement
    from unittest.mock import patch, MagicMock

    test_stmt = {
        "Effect": "Allow",
        "Action": ["iam:CreateRole", "iam:AttachRolePolicy"],
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln_class = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln_class

        findings = analyze_statement(test_stmt)

        mock_vulns.__getitem__.assert_called_once_with("IAM_POLICY_PRIVILEGE_ESCALATION")
        mock_vuln_class.instantiate.assert_called_once_with("policy", raw_data=test_stmt)
        assert len(findings) == 1