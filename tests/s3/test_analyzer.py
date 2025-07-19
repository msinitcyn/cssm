from types import SimpleNamespace

import aws_scanner.scanners.s3.analyzer as analyzer
from aws_scanner.core.vulnerabilities import VULNERABILITIES

def make_bucket_data(
    name="test-bucket",
    pab_config=None,
    acl_grants=None,
    policy_doc=None,
    cors_config=None,
    website_config=None
):
    return SimpleNamespace(
        name=name,
        pab_config=pab_config or {},
        acl_grants=acl_grants,
        policy_doc=policy_doc,
        cors_config=cors_config,
        website_config=website_config
    )

def test_classify_bucket_group():
    pab = {"IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    assert analyzer.classify_bucket_group(pab) == "ACL+Policy"
    pab = {"IgnorePublicAcls": False, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    assert analyzer.classify_bucket_group(pab) == "ACL-only"
    pab = {"IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    assert analyzer.classify_bucket_group(pab) == "Policy-only"
    pab = {"IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    assert analyzer.classify_bucket_group(pab) == "Blocked"

def test_analyze_acl_ignore_public_acls():
    bucket = make_bucket_data(pab_config={"IgnorePublicAcls": True}, acl_grants=[
        {"Grantee": {"URI": analyzer.ALL_USERS_URI}}
    ])
    assert not analyzer.analyze_acl(bucket)

def test_analyze_acl_no_public_grant():
    bucket = make_bucket_data(pab_config={}, acl_grants=[
        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}}
    ])
    assert not analyzer.analyze_acl(bucket)

def test_analyze_acl_with_public_grant():
    bucket = make_bucket_data(pab_config={}, acl_grants=[
        {"Grantee": {"URI": analyzer.ALL_USERS_URI}}
    ])
    assert analyzer.analyze_acl(bucket)

def test_analyze_policy_blocked():
    bucket = make_bucket_data(pab_config={"BlockPublicPolicy": True, "RestrictPublicBuckets": True}, policy_doc={
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        ]
    })
    is_public, has_condition = analyzer.analyze_policy(bucket)
    assert not is_public
    assert not has_condition

def test_analyze_policy_public_policy():
    bucket = make_bucket_data(pab_config={}, policy_doc={
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        ]
    })
    is_public, has_condition = analyzer.analyze_policy(bucket)
    assert is_public
    assert not has_condition

def test_analyze_policy_with_condition():
    bucket = make_bucket_data(pab_config={}, policy_doc={
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}}
        ]
    })
    is_public, has_condition = analyzer.analyze_policy(bucket)
    assert not is_public
    assert has_condition

def test_analyze_policy_non_public():
    bucket = make_bucket_data(pab_config={}, policy_doc={
        "Statement": [
            {"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}
        ]
    })
    is_public, has_condition = analyzer.analyze_policy(bucket)
    assert not is_public
    assert not has_condition

def test_analyze_s3_bucket_public_acl():
    bucket = make_bucket_data(
        name="bucket1",
        pab_config={},
        acl_grants=[{"Grantee": {"URI": analyzer.ALL_USERS_URI}}],
        policy_doc=None,
        cors_config=None,
        website_config=None
    )
    result = analyzer.analyze_s3_bucket(bucket)
    finding_ids = [f["id"] for f in result["findings"]]
    assert result["bucket"] == "bucket1"
    assert result["group"] == "ACL+Policy"
    assert VULNERABILITIES["S3_PUBLIC_ACL"].id in finding_ids
    assert VULNERABILITIES["S3_PUBLIC_POLICY"].id not in finding_ids

def test_analyze_s3_bucket_public_policy():
    bucket = make_bucket_data(
        name="bucket2",
        pab_config={},
        acl_grants=None,
        policy_doc={"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]},
        cors_config=None,
        website_config=None
    )
    result = analyzer.analyze_s3_bucket(bucket)
    finding_ids = [f["id"] for f in result["findings"]]
    assert result["bucket"] == "bucket2"
    assert result["group"] == "ACL+Policy"
    assert VULNERABILITIES["S3_PUBLIC_POLICY"].id in finding_ids
    assert VULNERABILITIES["S3_PUBLIC_ACL"].id not in finding_ids

def test_analyze_s3_bucket_potentially_public_condition():
    bucket = make_bucket_data(
        name="bucket3",
        pab_config={},
        acl_grants=None,
        policy_doc={"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}}]},
        cors_config=None,
        website_config=None
    )
    result = analyzer.analyze_s3_bucket(bucket)
    finding_ids = [f["id"] for f in result["findings"]]
    assert result["bucket"] == "bucket3"
    assert result["group"] == "ACL+Policy"
    assert VULNERABILITIES["S3_POTENTIALLY_PUBLIC_POLICY_CONDITION"].id in finding_ids
    assert VULNERABILITIES["S3_PUBLIC_POLICY"].id not in finding_ids
    assert VULNERABILITIES["S3_PUBLIC_ACL"].id not in finding_ids

def test_analyze_s3_bucket_private():
    bucket = make_bucket_data(
        name="bucket4",
        pab_config={},
        acl_grants=None,
        policy_doc=None,
        cors_config=None,
        website_config=None
    )
    result = analyzer.analyze_s3_bucket(bucket)
    finding_ids = [f["id"] for f in result["findings"]]
    assert result["bucket"] == "bucket4"
    assert result["group"] == "ACL+Policy"
    assert finding_ids == []

def test_analyze_s3_bucket_multiple_cors_findings():
    bucket = make_bucket_data(
        name="bucket_with_multiple_cors",
        pab_config={},
        acl_grants=None,
        policy_doc=None,
        cors_config={
            "CORSRules": [
                {"AllowedOrigins": ["*"]},
                {"AllowedOrigins": ["https://example.com"]},
                {"AllowedOrigins": ["*"]},
            ]
        },
        website_config=None
    )
    result = analyzer.analyze_s3_bucket(bucket)

    findings = [
        f for f in result["findings"]
        if f["id"] == VULNERABILITIES["S3_PUBLIC_CORS"].id
    ]
    assert len(findings) == 2, "Expected two overpermissive CORS findings"
    for f in findings:
        assert f["entity_name"] == "bucket_with_multiple_cors"


def test_analyze_s3_bucket_website():
    bucket = make_bucket_data(
        name="bucket6",
        pab_config={},
        acl_grants=None,
        policy_doc=None,
        cors_config=None,
        website_config={"IndexDocument": "index.html"}
    )
    result = analyzer.analyze_s3_bucket(bucket)
    finding_ids = [f["id"] for f in result["findings"]]
    assert VULNERABILITIES["S3_PUBLIC_WEBSITE"].id in finding_ids
