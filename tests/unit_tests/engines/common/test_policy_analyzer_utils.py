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
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_ASSUME_ROLE_WILDCARD")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")
        assert mock_vuln.instantiate.call_count == 5


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
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_ASSUME_ROLE_WILDCARD")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")
        assert mock_vuln.instantiate.call_count == 4


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
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")
        assert mock_vuln.instantiate.call_count == 3


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

            assert mock_vulns.__getitem__.call_count == 3
            mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_ACTION_CONDITION")
            mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION")
            mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")

            assert mock_vuln.instantiate.call_count == 3
            mock_vuln.instantiate.assert_has_calls([
                call("policy", raw_data=stmt),
                call("policy", raw_data=stmt),
                call("policy", raw_data=stmt)
            ])


def test_analyze_statement_no_findings():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "s3:ListBucket",
        "Resource": "arn:aws:s3:::bucket"
    }

    findings = analyze_statement(stmt)

    assert len(findings) == 0


def test_analyze_statement_with_action_list():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": ["s3:PutObject", "*"],
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_ALL")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_PRIVILEGE_ESCALATION")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_ASSUME_ROLE_WILDCARD")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")
        assert mock_vuln.instantiate.call_count == 5


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
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_ASSUME_ROLE_WILDCARD")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")
        assert mock_vuln.instantiate.call_count == 5


def test_analyze_statement_empty_action_resource():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow"
    }

    findings = analyze_statement(stmt)

    assert len(findings) == 0


def test_assume_role_wildcard_exact_match():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_ASSUME_ROLE_WILDCARD")
        mock_vuln.instantiate.assert_called_with("policy", raw_data=stmt)


def test_assume_role_wildcard_with_restrictive_condition():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*",
        "Condition": {
            "IpAddress": {
                "aws:SourceIp": "192.168.1.0/24"
            }
        }
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        assume_role_calls = [call for call in mock_vulns.__getitem__.call_args_list
                           if call[0][0] == "IAM_POLICY_ASSUME_ROLE_WILDCARD"]
        assert len(assume_role_calls) == 0


def test_assume_role_wildcard_with_non_restrictive_condition():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "*",
        "Condition": {
            "StringEquals": {
                "aws:RequestedRegion": "us-east-1"
            }
        }
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_ASSUME_ROLE_WILDCARD")
        mock_vuln.instantiate.assert_called_with("policy", raw_data=stmt)


def test_assume_role_wildcard_in_action_list():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "sts:AssumeRole"],
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_ASSUME_ROLE_WILDCARD")


def test_assume_role_wildcard_with_sts_wildcard():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "sts:*",
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_ASSUME_ROLE_WILDCARD")


def test_assume_role_no_wildcard_resource():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": "arn:aws:iam::123456789012:role/SpecificRole"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        assume_role_calls = [call for call in mock_vulns.__getitem__.call_args_list
                           if call[0][0] == "IAM_POLICY_ASSUME_ROLE_WILDCARD"]
        assert len(assume_role_calls) == 0


def test_has_assume_role_wildcard_function():
    from aws_scanner.engines.common.policy_analyzer_utils import has_assume_role_wildcard

    assert has_assume_role_wildcard(["sts:AssumeRole"], ["*"], [], None) is True
    assert has_assume_role_wildcard(["sts:AssumeRole"], ["arn:aws:iam::123:role/Role"], [], None) is False
    assert has_assume_role_wildcard(["s3:GetObject"], ["*"], [], None) is False
    assert has_assume_role_wildcard(["sts:AssumeRole"], [], ["arn:aws:s3:::bucket/*"], None) is True

    restrictive_condition = {
        "IpAddress": {
            "aws:SourceIp": "192.168.1.0/24"
        }
    }
    assert has_assume_role_wildcard(["sts:AssumeRole"], ["*"], [], restrictive_condition) is False
    assert has_assume_role_wildcard(["sts:AssumeRole"], [], ["arn:aws:s3:::bucket/*"], restrictive_condition) is False


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

    test_stmt = {
        "Effect": "Allow",
        "Action": ["iam:CreateRole", "iam:AttachRolePolicy"],
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln_class = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln_class

        analyze_statement(test_stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_PRIVILEGE_ESCALATION")
        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")

        privilege_escalation_calls = [
            call for call in mock_vulns.__getitem__.call_args_list
            if call[0][0] == "IAM_POLICY_PRIVILEGE_ESCALATION"
        ]
        assert len(privilege_escalation_calls) == 1

        sensitive_actions_calls = [
            call for call in mock_vulns.__getitem__.call_args_list
            if call[0][0] == "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS"
        ]
        assert len(sensitive_actions_calls) == 1


# NEW TESTS FOR SENSITIVE ACTIONS WITHOUT CONDITIONS


def test_sensitive_actions_without_conditions():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject"
        ],
        "Resource": "arn:aws:s3:::sensitive-bucket/*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")

        sensitive_action_calls = [
            call for call in mock_vulns.__getitem__.call_args_list
            if call[0][0] == "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS"
        ]
        assert len(sensitive_action_calls) == 1


def test_sensitive_actions_with_restrictive_conditions():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": [
            "s3:GetObject",
            "s3:PutObject"
        ],
        "Resource": "arn:aws:s3:::sensitive-bucket/*",
        "Condition": {
            "IpAddress": {
                "aws:SourceIp": "203.0.113.0/24"
            },
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        sensitive_action_calls = [
            call for call in mock_vulns.__getitem__.call_args_list
            if call[0][0] == "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS"
        ]
        assert len(sensitive_action_calls) == 0


def test_sensitive_actions_with_non_restrictive_conditions():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": [
            "s3:DeleteObject"
        ],
        "Resource": "arn:aws:s3:::sensitive-bucket/*",
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

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")


def test_non_sensitive_actions_without_conditions():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": [
            "s3:ListBucket",
            "ec2:DescribeInstances"
        ],
        "Resource": "*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        sensitive_action_calls = [
            call for call in mock_vulns.__getitem__.call_args_list
            if call[0][0] == "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS"
        ]
        assert len(sensitive_action_calls) == 0


def test_wildcard_actions_include_sensitive():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "arn:aws:s3:::bucket/*"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")


def test_has_sensitive_actions_without_conditions_function():
    from aws_scanner.engines.common.policy_analyzer_utils import has_sensitive_actions_without_conditions

    actions = ["s3:GetObject", "s3:PutObject"]
    assert has_sensitive_actions_without_conditions(actions, None) is True

    restrictive_condition = {
        "IpAddress": {
            "aws:SourceIp": "192.168.1.0/24"
        }
    }
    assert has_sensitive_actions_without_conditions(actions, restrictive_condition) is False

    non_sensitive_actions = ["s3:ListBucket", "ec2:DescribeInstances"]
    assert has_sensitive_actions_without_conditions(non_sensitive_actions, None) is False

    wildcard_actions = ["s3:*"]
    assert has_sensitive_actions_without_conditions(wildcard_actions, None) is True

    iam_actions = ["iam:CreateUser", "iam:AttachUserPolicy"]
    assert has_sensitive_actions_without_conditions(iam_actions, None) is True


def test_iam_sensitive_actions():
    from aws_scanner.engines.common.policy_analyzer_utils import analyze_statement

    stmt = {
        "Effect": "Allow",
        "Action": [
            "iam:CreateRole",
            "iam:AttachRolePolicy"
        ],
        "Resource": "arn:aws:iam::123456789012:role/MyRole"
    }

    with patch("aws_scanner.engines.common.policy_analyzer_utils.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vulns.__getitem__.return_value = mock_vuln

        analyze_statement(stmt)

        mock_vulns.__getitem__.assert_any_call("IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS")

        sensitive_actions_calls = [
            call for call in mock_vulns.__getitem__.call_args_list
            if call[0][0] == "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS"
        ]
        assert len(sensitive_actions_calls) == 1

        privilege_escalation_calls = [
            call for call in mock_vulns.__getitem__.call_args_list
            if call[0][0] == "IAM_POLICY_PRIVILEGE_ESCALATION"
        ]
        assert len(privilege_escalation_calls) == 0