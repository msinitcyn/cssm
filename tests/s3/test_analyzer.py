import pytest
from types import SimpleNamespace

import aws_scanner.scanners.s3.analyzer as analyzer

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
    # Both ACL and Policy allowed
    pab = {"IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    assert analyzer.classify_bucket_group(pab) == "ACL+Policy"
    # Only ACL allowed
    pab = {"IgnorePublicAcls": False, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    assert analyzer.classify_bucket_group(pab) == "ACL-only"
    # Only Policy allowed
    pab = {"IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    assert analyzer.classify_bucket_group(pab) == "Policy-only"
    # Blocked
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

def test_get_access_vectors_acl_policy():
    bucket = make_bucket_data(cors_config=None, website_config=None)
    vectors = analyzer.get_access_vectors(True, True, bucket)
    assert "ACL" in vectors and "Policy" in vectors

def test_get_access_vectors_with_cors_and_website():
    bucket = make_bucket_data(cors_config={"CORSRules": []}, website_config={"IndexDocument": "index.html"})
    vectors = analyzer.get_access_vectors(True, False, bucket)
    assert "ACL" in vectors and "CORS" in vectors and "Website" in vectors

def test_get_access_vectors_none():
    bucket = make_bucket_data()
    vectors = analyzer.get_access_vectors(False, False, bucket)
    assert vectors == []

def test_score_risk_high_due_to_cors():
    report = {"public": True}
    bucket = make_bucket_data(cors_config={"CORSRules": [{"AllowedOrigins": ["*"]}]})
    assert analyzer.score_risk(report, bucket) == "high"

def test_score_risk_medium_due_to_website():
    report = {"public": True}
    bucket = make_bucket_data(cors_config={}, website_config={"IndexDocument": "index.html"})
    assert analyzer.score_risk(report, bucket) == "medium"

def test_score_risk_medium_default():
    report = {"public": True}
    bucket = make_bucket_data(cors_config={}, website_config=None)
    assert analyzer.score_risk(report, bucket) == "medium"

def test_score_risk_low_potentially_public():
    report = {"potentially_public": True}
    bucket = make_bucket_data()
    assert analyzer.score_risk(report, bucket) == "low"

def test_score_risk_low_default():
    report = {}
    bucket = make_bucket_data()
    assert analyzer.score_risk(report, bucket) == "low"

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
    assert result["bucket"] == "bucket1"
    assert result["group"] == "ACL+Policy"
    assert "ACL" in result["access_vector"]
    assert result["public"]
    assert result["risk"] == "medium"

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
    assert result["bucket"] == "bucket2"
    assert result["group"] == "ACL+Policy"
    assert "Policy" in result["access_vector"]
    assert result["public"]
    assert result["risk"] == "medium"

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
    assert result["bucket"] == "bucket3"
    assert result["group"] == "ACL+Policy"
    assert result["potentially_public"]
    assert result["access_vector"] == ["Policy"]
    assert result["reason"] == "Condition present"
    assert result["risk"] == "low"

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
    assert result["bucket"] == "bucket4"
    assert result["group"] == "ACL+Policy"
    assert result["access_vector"] is None
    assert not result["public"]
    assert result["risk"] == "low"