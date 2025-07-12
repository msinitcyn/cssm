import sys, os
import pytest
from unittest.mock import MagicMock, patch
import botocore
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
from aws_scanner.scanners.s3.collector import collect_s3_bucket_data
from aws_scanner.scanners.s3.s3_bucket_data import S3BucketData

class DummyClientError(botocore.exceptions.ClientError):
    def __init__(self, code):
        super().__init__({'Error': {'Code': code}}, 'operation')

def make_s3_mock(
    pab=None, pab_exc=None,
    acl=None, acl_exc=None,
    policy=None, policy_exc=None,
    cors=None, cors_exc=None,
    website=None, website_exc=None
):
    s3 = MagicMock()
    if pab_exc:
        s3.get_public_access_block.side_effect = pab_exc
    else:
        s3.get_public_access_block.return_value = pab
    if acl_exc:
        s3.get_bucket_acl.side_effect = acl_exc
    else:
        s3.get_bucket_acl.return_value = acl
    if policy_exc:
        s3.get_bucket_policy.side_effect = policy_exc
    else:
        s3.get_bucket_policy.return_value = policy
    if cors_exc:
        s3.get_bucket_cors.side_effect = cors_exc
    else:
        s3.get_bucket_cors.return_value = cors
    if website_exc:
        s3.get_bucket_website.side_effect = website_exc
    else:
        s3.get_bucket_website.return_value = website
    return s3

def test_all_methods_success():
    s3 = make_s3_mock(
        pab={"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}},
        acl={"Grants": ["grant1"]},
        policy={"Policy": '{"Statement": [1]}'},
        cors={"CORSRules": ["rule1"]},
        website={"IndexDocument": "index.html"}
    )
    data = collect_s3_bucket_data(s3, "bucket1")
    assert data.name == "bucket1"
    assert data.pab_config == {"BlockPublicAcls": True}
    assert data.acl_grants == ["grant1"]
    assert data.policy_doc == {"Statement": [1]}
    assert data.cors_config == {"CORSRules": ["rule1"]}
    assert data.website_config == {"IndexDocument": "index.html"}

def test_public_access_block_no_such_block():
    s3 = make_s3_mock(
        pab_exc=DummyClientError("NoSuchPublicAccessBlock"),
        acl={"Grants": []},
        policy={"Policy": None},
        cors={},
        website={}
    )
    data = collect_s3_bucket_data(s3, "bucket2")
    assert data.pab_config == {}

def test_acl_and_policy_client_error():
    s3 = make_s3_mock(
        pab={"PublicAccessBlockConfiguration": {}},
        acl_exc=DummyClientError("SomeError"),
        policy_exc=DummyClientError("SomeError"),
        cors={},
        website={}
    )
    data = collect_s3_bucket_data(s3, "bucket3")
    assert data.acl_grants == []
    assert data.policy_doc == {}

def test_all_methods_client_error():
    s3 = make_s3_mock(
        pab_exc=DummyClientError("SomeError"),
        acl_exc=DummyClientError("SomeError"),
        policy_exc=DummyClientError("SomeError"),
        cors_exc=DummyClientError("SomeError"),
        website_exc=DummyClientError("SomeError")
    )
    with pytest.raises(botocore.exceptions.ClientError):
        collect_s3_bucket_data(s3, "bucket4")

def test_policy_none():
    s3 = make_s3_mock(
        pab={"PublicAccessBlockConfiguration": {}},
        acl={"Grants": []},
        policy={"Policy": None},
        cors={},
        website={}
    )
    data = collect_s3_bucket_data(s3, "bucket5")
    assert data.policy_doc == {}
