import sys, os
import pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
from aws_scanner.scanners.s3 import analyzer

class DummyBucketData:
    def __init__(self, name="bucket", pab_config=None, acl_grants=None, policy_doc=None, cors_config=None):
        self.name = name
        self.pab_config = pab_config or {}
        self.acl_grants = acl_grants or []
        self.policy_doc = policy_doc or {}
        self.cors_config = cors_config or {}

def test_analyze_public_acl():
    acl = [{"Grantee": {"URI": analyzer.ALL_USERS_URI}}]
    bucket = DummyBucketData(acl_grants=acl)
    result = analyzer.analyze_s3_bucket(bucket)
    assert result["public"] is True
    assert result["access_vector"] == "ACL"
    assert result["risk"] in ("medium", "high", "low")

def test_analyze_public_policy():
    policy = {"Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject"
    }]}
    bucket = DummyBucketData(policy_doc=policy)
    result = analyzer.analyze_s3_bucket(bucket)
    assert result["public"] is True
    assert result["access_vector"] == "Policy"
    assert result["risk"] in ("medium", "high", "low")

def test_analyze_potentially_public_policy():
    policy = {"Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}
    }]}
    bucket = DummyBucketData(policy_doc=policy)
    result = analyzer.analyze_s3_bucket(bucket)
    assert result.get("potentially_public") is True
    assert result["access_vector"] == "Policy"
    assert result["reason"] == "Condition present"
    assert result["risk"] == "low"

def test_analyze_blocked():
    pab = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    bucket = DummyBucketData(pab_config=pab)
    result = analyzer.analyze_s3_bucket(bucket)
    assert result["group"] == "Blocked"
    assert result["public"] is False
    assert result["risk"] == "low"

def test_score_risk_high():
    cors = {"CORSRules": [{"AllowedOrigins": ["*"]}]}
    report = {"public": True}
    bucket = DummyBucketData(cors_config=cors)
    assert analyzer.score_risk(report, bucket) == "high"

def test_score_risk_medium():
    cors = {"CORSRules": [{"AllowedOrigins": ["https://example.com"]}]}
    report = {"public": True}
    bucket = DummyBucketData(cors_config=cors)
    assert analyzer.score_risk(report, bucket) == "medium"

def test_score_risk_low():
    report = {"potentially_public": True}
    bucket = DummyBucketData()
    assert analyzer.score_risk(report, bucket) == "low"
    report = {}
    assert analyzer.score_risk(report, bucket) == "low"
