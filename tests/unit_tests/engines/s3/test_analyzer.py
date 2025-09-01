from unittest.mock import patch, MagicMock

def test_classify_bucket_group_acl_and_policy():
    from aws_scanner.engines.s3.analyzer import classify_bucket_group

    pab = {"IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    assert classify_bucket_group(pab) == "ACL+Policy"


def test_classify_bucket_group_acl_only():
    from aws_scanner.engines.s3.analyzer import classify_bucket_group

    pab = {"IgnorePublicAcls": False, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    assert classify_bucket_group(pab) == "ACL-only"


def test_classify_bucket_group_policy_only():
    from aws_scanner.engines.s3.analyzer import classify_bucket_group

    pab = {"IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    assert classify_bucket_group(pab) == "Policy-only"

    pab = {"IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": False}
    assert classify_bucket_group(pab) == "Policy-only"


def test_classify_bucket_group_blocked():
    from aws_scanner.engines.s3.analyzer import classify_bucket_group

    pab = {"IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    assert classify_bucket_group(pab) == "Blocked"


def test_classify_bucket_group_missing_keys():
    from aws_scanner.engines.s3.analyzer import classify_bucket_group

    pab = {}
    assert classify_bucket_group(pab) == "ACL+Policy"


def test_analyze_acl_public_grant():
    from aws_scanner.engines.s3.analyzer import analyze_acl

    bucket_data = MagicMock()
    bucket_data.pab_config = {"IgnorePublicAcls": False}
    bucket_data.acl_grants = [
        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
    ]

    assert analyze_acl(bucket_data) is True


def test_analyze_acl_no_public_grant():
    from aws_scanner.engines.s3.analyzer import analyze_acl

    bucket_data = MagicMock()
    bucket_data.pab_config = {"IgnorePublicAcls": False}
    bucket_data.acl_grants = [
        {"Grantee": {"Type": "CanonicalUser", "ID": "123"}, "Permission": "FULL_CONTROL"}
    ]

    assert analyze_acl(bucket_data) is False


def test_analyze_acl_ignore_public_acls():
    from aws_scanner.engines.s3.analyzer import analyze_acl

    bucket_data = MagicMock()
    bucket_data.pab_config = {"IgnorePublicAcls": True}
    bucket_data.acl_grants = [
        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
    ]

    assert analyze_acl(bucket_data) is False


def test_analyze_acl_none_grants():
    from aws_scanner.engines.s3.analyzer import analyze_acl

    bucket_data = MagicMock()
    bucket_data.pab_config = {"IgnorePublicAcls": False}
    bucket_data.acl_grants = None

    assert analyze_acl(bucket_data) is False


def test_analyze_policy_public_policy():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is True
    assert has_condition is False


def test_analyze_policy_with_condition():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*",
                    "Condition": {"StringEquals": {"s3:ExistingObjectTag/public": "yes"}}
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is False
    assert has_condition is True


def test_analyze_policy_blocked():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject"
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is False
    assert has_condition is False


def test_analyze_policy_deny_effect():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject"
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is False
    assert has_condition is False


def test_analyze_policy_non_public_principal():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:GetObject"
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is False
    assert has_condition is False


def test_analyze_policy_aws_star_principal():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject"
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is True
    assert has_condition is False


def test_analyze_policy_wrong_action():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:PutObject"
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is False
    assert has_condition is False


def test_analyze_policy_action_list():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:PutObject", "s3:GetObject"]
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is True
    assert has_condition is False


def test_analyze_policy_s3_star_action():
    from aws_scanner.engines.s3.analyzer import analyze_policy
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*"
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is True
    assert has_condition is False


def test_analyze_policy_none_policy():
    from aws_scanner.engines.s3.analyzer import analyze_policy

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = None

    is_public, has_condition = analyze_policy(bucket_data)
    assert is_public is False
    assert has_condition is False


def test_is_cors_rule_overpermissive_origins():
    from aws_scanner.engines.s3.analyzer import is_cors_rule_overpermissive

    rule = {"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}
    assert is_cors_rule_overpermissive(rule) is True


def test_is_cors_rule_overpermissive_headers():
    from aws_scanner.engines.s3.analyzer import is_cors_rule_overpermissive

    rule = {"AllowedOrigins": ["https://example.com"], "AllowedHeaders": ["*"]}
    assert is_cors_rule_overpermissive(rule) is True


def test_is_cors_rule_overpermissive_methods():
    from aws_scanner.engines.s3.analyzer import is_cors_rule_overpermissive

    rule = {"AllowedOrigins": ["https://example.com"], "AllowedMethods": ["*"]}
    assert is_cors_rule_overpermissive(rule) is True


def test_is_cors_rule_not_overpermissive():
    from aws_scanner.engines.s3.analyzer import is_cors_rule_overpermissive

    rule = {"AllowedOrigins": ["https://example.com"], "AllowedMethods": ["GET", "POST"]}
    assert is_cors_rule_overpermissive(rule) is False


def test_is_cors_rule_missing_keys():
    from aws_scanner.engines.s3.analyzer import is_cors_rule_overpermissive

    rule = {}
    assert is_cors_rule_overpermissive(rule) is False


def test_check_acl_vulnerability_found():
    from aws_scanner.engines.s3.analyzer import check_acl_vulnerability

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.pab_config = {"IgnorePublicAcls": False}
    bucket_data.acl_grants = [
        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
    ]

    with patch("aws_scanner.engines.s3.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "S3_PUBLIC_ACL"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_acl_vulnerability(bucket_data)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with("test-bucket")


def test_check_acl_vulnerability_not_found():
    from aws_scanner.engines.s3.analyzer import check_acl_vulnerability

    bucket_data = MagicMock()
    bucket_data.pab_config = {"IgnorePublicAcls": False}
    bucket_data.acl_grants = []

    findings = check_acl_vulnerability(bucket_data)
    assert len(findings) == 0


def test_check_policy_vulnerabilities_public_policy():
    from aws_scanner.engines.s3.analyzer import check_policy_vulnerabilities
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject"
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    with patch("aws_scanner.engines.s3.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "S3_PUBLIC_POLICY"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_policy_vulnerabilities(bucket_data)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with("test-bucket")


def test_check_policy_vulnerabilities_conditional_policy():
    from aws_scanner.engines.s3.analyzer import check_policy_vulnerabilities
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.pab_config = {"BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Condition": {"StringEquals": {"s3:ExistingObjectTag/public": "yes"}}
                }
            ]
        },
        arn=None,
        is_inline=False
    )

    with patch("aws_scanner.engines.s3.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "S3_POTENTIALLY_PUBLIC_POLICY_CONDITION"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_policy_vulnerabilities(bucket_data)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with("test-bucket")


def test_check_policy_vulnerabilities_no_findings():
    from aws_scanner.engines.s3.analyzer import check_policy_vulnerabilities

    bucket_data = MagicMock()
    bucket_data.pab_config = {"BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    bucket_data.policy = None

    findings = check_policy_vulnerabilities(bucket_data)
    assert len(findings) == 0


def test_check_cors_vulnerabilities_found():
    from aws_scanner.engines.s3.analyzer import check_cors_vulnerabilities

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.cors_config = {
        "CORSRules": [
            {"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]},
            {"AllowedOrigins": ["https://example.com"], "AllowedMethods": ["POST"]}
        ]
    }

    with patch("aws_scanner.engines.s3.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "S3_PUBLIC_CORS"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_cors_vulnerabilities(bucket_data)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with(
            "test-bucket",
            raw_data={"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}
        )


def test_check_cors_vulnerabilities_none_config():
    from aws_scanner.engines.s3.analyzer import check_cors_vulnerabilities

    bucket_data = MagicMock()
    bucket_data.cors_config = None

    findings = check_cors_vulnerabilities(bucket_data)
    assert len(findings) == 0


def test_check_cors_vulnerabilities_no_rules():
    from aws_scanner.engines.s3.analyzer import check_cors_vulnerabilities

    bucket_data = MagicMock()
    bucket_data.cors_config = {"CORSRules": []}

    findings = check_cors_vulnerabilities(bucket_data)
    assert len(findings) == 0


def test_check_website_vulnerability_found():
    from aws_scanner.engines.s3.analyzer import check_website_vulnerability

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.website_config = {"IndexDocument": {"Suffix": "index.html"}}

    with patch("aws_scanner.engines.s3.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "S3_PUBLIC_WEBSITE"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_website_vulnerability(bucket_data)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with("test-bucket")


def test_check_website_vulnerability_none_config():
    from aws_scanner.engines.s3.analyzer import check_website_vulnerability

    bucket_data = MagicMock()
    bucket_data.website_config = None

    findings = check_website_vulnerability(bucket_data)
    assert len(findings) == 0


def test_check_logging_vulnerability_found():
    from aws_scanner.engines.s3.analyzer import check_logging_vulnerability

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.server_access_logging = {"enabled": False}

    findings = check_logging_vulnerability(bucket_data)

    assert len(findings) == 1
    assert findings[0]["id"] == "S3_NO_ACCESS_LOGGING"
    assert findings[0]["entity_name"] == "test-bucket"


def test_check_versioning_vulnerability_found():
    from aws_scanner.engines.s3.analyzer import check_versioning_vulnerability

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.versioning = {"status": "Suspended"}

    findings = check_versioning_vulnerability(bucket_data)

    assert len(findings) == 1
    assert findings[0]["id"] == "S3_VERSIONING_SUSPENDED"
    assert findings[0]["entity_name"] == "test-bucket"


def test_check_encryption_vulnerability_found():
    from aws_scanner.engines.s3.analyzer import check_encryption_vulnerability

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.encryption = {"server_side_encryption": "none"}

    findings = check_encryption_vulnerability(bucket_data)

    assert len(findings) == 1
    assert findings[0]["id"] == "S3_NO_ENCRYPTION"
    assert findings[0]["entity_name"] == "test-bucket"


def test_check_mfa_delete_vulnerability_found():
    from aws_scanner.engines.s3.analyzer import check_mfa_delete_vulnerability

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.mfa_delete = False

    findings = check_mfa_delete_vulnerability(bucket_data)

    assert len(findings) == 1
    assert findings[0]["id"] == "S3_MFA_DELETE_DISABLED"
    assert findings[0]["entity_name"] == "test-bucket"


def test_analyze_s3_bucket_multiple_findings():
    from aws_scanner.engines.s3.analyzer import analyze_s3_bucket
    from aws_scanner.engines.common.iam_policy_data import IamPolicyData

    bucket_data = MagicMock()
    bucket_data.name = "test-bucket"
    bucket_data.pab_config = {"IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    bucket_data.acl_grants = [
        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
    ]
    bucket_data.policy = IamPolicyData(
        name="test-policy",
        policy_type="resource",
        document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject"
                }
            ]
        },
        arn=None,
        is_inline=False
    )
    bucket_data.cors_config = {
        "CORSRules": [{"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}]
    }
    bucket_data.website_config = {"IndexDocument": {"Suffix": "index.html"}}
    bucket_data.server_access_logging = {}
    bucket_data.versioning = {"status": "Suspended"}
    bucket_data.encryption = {}
    bucket_data.mfa_delete = False

    with patch("aws_scanner.engines.s3.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "vulnerability"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = analyze_s3_bucket(bucket_data)

        assert len(findings) == 8


def test_analyze_s3_bucket_no_findings():
    from aws_scanner.engines.s3.analyzer import analyze_s3_bucket

    bucket_data = MagicMock()
    bucket_data.pab_config = {"IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    bucket_data.acl_grants = []
    bucket_data.policy = None
    bucket_data.cors_config = None
    bucket_data.website_config = None
    bucket_data.server_access_logging = {"enabled": True}
    bucket_data.versioning = {"status": "Enabled"}
    bucket_data.encryption = {"server_side_encryption": "AES256"}
    bucket_data.mfa_delete = True

    findings = analyze_s3_bucket(bucket_data)
    assert len(findings) == 0