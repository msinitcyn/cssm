import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
from aws_scanner.scanners import s3_scanner

# --- get_public_access_block_config ---
def test_get_public_access_block_config_normal():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    result = s3_scanner.get_public_access_block_config(s3, 'bucket')
    assert result == {'BlockPublicAcls': True}

def test_get_public_access_block_config_no_block():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlock'}}, 'GetPublicAccessBlock')
    result = s3_scanner.get_public_access_block_config(s3, 'bucket')
    assert result == {}

def test_get_public_access_block_config_other_error():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 'GetPublicAccessBlock')
    with pytest.raises(ClientError):
        s3_scanner.get_public_access_block_config(s3, 'bucket')

# --- analyze_pab_flags ---
def test_analyze_pab_flags_all_false():
    pab = {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    result = s3_scanner.analyze_pab_flags(pab)
    assert result == {"can_use_acl": True, "can_use_policy": True, "group": "ACL+Policy"}

def test_analyze_pab_flags_acl_only():
    pab = {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    result = s3_scanner.analyze_pab_flags(pab)
    assert result["can_use_acl"] is True
    assert result["can_use_policy"] is False
    assert result["group"] == "ACL-only"

def test_analyze_pab_flags_policy_only():
    pab = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    result = s3_scanner.analyze_pab_flags(pab)
    assert result["can_use_acl"] is False
    assert result["can_use_policy"] is True
    assert result["group"] == "Policy-only"

def test_analyze_pab_flags_blocked():
    pab = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    result = s3_scanner.analyze_pab_flags(pab)
    assert result["can_use_acl"] is False
    assert result["can_use_policy"] is False
    assert result["group"] == "Blocked"

# --- check_bucket_acl ---
def test_check_bucket_acl_public():
    s3 = MagicMock()
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': s3_scanner.ALL_USERS_URI}}]
    }
    assert s3_scanner.check_bucket_acl(s3, 'bucket') is True

def test_check_bucket_acl_private():
    s3 = MagicMock()
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    assert s3_scanner.check_bucket_acl(s3, 'bucket') is False

def test_check_bucket_acl_no_such_bucket():
    s3 = MagicMock()
    s3.get_bucket_acl.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucket'}}, 'GetBucketAcl')
    assert s3_scanner.check_bucket_acl(s3, 'bucket') is False

def test_check_bucket_acl_other_error():
    s3 = MagicMock()
    s3.get_bucket_acl.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 'GetBucketAcl')
    with pytest.raises(ClientError):
        s3_scanner.check_bucket_acl(s3, 'bucket')

# --- check_bucket_policy ---
def test_check_bucket_policy_public():
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    result = s3_scanner.check_bucket_policy(s3, 'bucket')
    assert result == {"public": True}

def test_check_bucket_policy_potentially_public():
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}}]}'
    }
    result = s3_scanner.check_bucket_policy(s3, 'bucket')
    assert result == {"potentially_public": True, "reason": "has condition"}

def test_check_bucket_policy_private():
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    result = s3_scanner.check_bucket_policy(s3, 'bucket')
    assert result == {}

def test_check_bucket_policy_error():
    s3 = MagicMock()
    s3.get_bucket_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
    result = s3_scanner.check_bucket_policy(s3, 'bucket')
    assert result == {}

# --- is_bucket_public ---
def test_is_bucket_public_acl():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {}
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': s3_scanner.ALL_USERS_URI}}]
    }
    s3.get_bucket_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
    result = s3_scanner.is_bucket_public(s3, 'bucket')
    assert result["public"] is True
    assert result["access_vector"] == "ACL"

def test_is_bucket_public_policy():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {}
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    result = s3_scanner.is_bucket_public(s3, 'bucket')
    assert result["public"] is True
    assert result["access_vector"] == "Policy"

def test_is_bucket_public_potentially_public():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {}
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4/32"}}}]}'
    }
    result = s3_scanner.is_bucket_public(s3, 'bucket')
    assert result["potentially_public"] is True
    assert result["reason"] == "has condition"
    assert result["access_vector"] == "Policy"

def test_is_bucket_public_private():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {}
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    result = s3_scanner.is_bucket_public(s3, 'bucket')
    assert result["public"] is False

# --- find_public_s3_buckets ---
def make_s3_list_buckets(names):
    return {"Buckets": [{"Name": n} for n in names]}

@patch('aws_scanner.scanners.s3_scanner.boto3.client')
def test_find_public_s3_buckets_all_private(mock_boto_client):
    mock_s3 = MagicMock()
    mock_boto_client.return_value = mock_s3
    mock_s3.list_buckets.return_value = make_s3_list_buckets(["bucket1", "bucket2"])
    mock_s3.get_public_access_block.return_value = {}
    mock_s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    mock_s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    result = s3_scanner.find_public_s3_buckets()
    assert all(r["public"] is False for r in result)
    assert {r["bucket"] for r in result} == {"bucket1", "bucket2"}

@patch('aws_scanner.scanners.s3_scanner.boto3.client')
def test_find_public_s3_buckets_some_public(mock_boto_client):
    mock_s3 = MagicMock()
    mock_boto_client.return_value = mock_s3
    mock_s3.list_buckets.return_value = make_s3_list_buckets(["bucket1", "bucket2"])
    def acl_side_effect(Bucket):
        if Bucket == "bucket1":
            return {'Grants': [{'Grantee': {'URI': s3_scanner.ALL_USERS_URI}}]}
        return {'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]}
    mock_s3.get_public_access_block.return_value = {}
    mock_s3.get_bucket_acl.side_effect = acl_side_effect
    mock_s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    result = s3_scanner.find_public_s3_buckets()
    buckets = {r["bucket"]: r for r in result}
    assert buckets["bucket1"]["public"] is True
    assert buckets["bucket2"]["public"] is False

@patch('aws_scanner.scanners.s3_scanner.boto3.client')
def test_find_public_s3_buckets_with_error(mock_boto_client):
    mock_s3 = MagicMock()
    mock_boto_client.return_value = mock_s3
    mock_s3.list_buckets.return_value = make_s3_list_buckets(["bucket1", "bucket2"])
    def acl_side_effect(Bucket):
        if Bucket == 'bucket1':
            raise ClientError({'Error': {'Code': 'AccessDenied'}}, 'GetBucketAcl')
        return {'Grants': [{'Grantee': {'URI': s3_scanner.ALL_USERS_URI}}]}
    mock_s3.get_public_access_block.return_value = {}
    mock_s3.get_bucket_acl.side_effect = acl_side_effect
    mock_s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    result = s3_scanner.find_public_s3_buckets()
    buckets = {r["bucket"]: r for r in result}
    assert "error" in buckets["bucket1"]
    assert buckets["bucket2"]["public"] is True

@patch('aws_scanner.scanners.s3_scanner.boto3.client')
def test_find_public_s3_buckets_list_error(mock_boto_client):
    mock_s3 = MagicMock()
    mock_boto_client.return_value = mock_s3
    mock_s3.list_buckets.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'ListBuckets')
    result = s3_scanner.find_public_s3_buckets()
    assert result[0]["bucket"] == "<list_error>"
    assert "error" in result[0]
