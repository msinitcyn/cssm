import pytest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from aws_scanner.scanners.s3_scanner import (
    check_public_access_block,
    check_bucket_acl,
    check_bucket_policy,
    is_bucket_public,
    find_public_s3_buckets,
)

# --- check_public_access_block ---
def test_check_public_access_block_blocked():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': False,
            'BlockPublicPolicy': False,
            'RestrictPublicBuckets': False
        }
    }
    assert check_public_access_block(s3, 'bucket') is False

def test_check_public_access_block_no_block():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': False,
            'IgnorePublicAcls': False,
            'BlockPublicPolicy': False,
            'RestrictPublicBuckets': False
        }
    }
    assert check_public_access_block(s3, 'bucket') is None

def test_check_public_access_block_no_such_block():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlock'}}, 'GetPublicAccessBlock')
    assert check_public_access_block(s3, 'bucket') is None

def test_check_public_access_block_other_error():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 'GetPublicAccessBlock')
    assert check_public_access_block(s3, 'bucket') is False

# --- check_bucket_acl ---
def test_check_bucket_acl_public():
    s3 = MagicMock()
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]
    }
    assert check_bucket_acl(s3, 'bucket') is True

def test_check_bucket_acl_private():
    s3 = MagicMock()
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    assert check_bucket_acl(s3, 'bucket') is False

def test_check_bucket_acl_error():
    s3 = MagicMock()
    s3.get_bucket_acl.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied'}}, 'GetBucketAcl')
    with pytest.raises(ClientError):
        check_bucket_acl(s3, 'bucket')

# --- check_bucket_policy ---
def test_check_bucket_policy_public():
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    assert check_bucket_policy(s3, 'bucket') is True

def test_check_bucket_policy_private():
    s3 = MagicMock()
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    assert check_bucket_policy(s3, 'bucket') is False

def test_check_bucket_policy_error():
    s3 = MagicMock()
    s3.get_bucket_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
    assert check_bucket_policy(s3, 'bucket') is False

# --- is_bucket_public ---
def test_is_bucket_public_blocked():
    s3 = MagicMock()
    s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    assert is_bucket_public(s3, 'bucket') is False

def test_is_bucket_public_acl_public():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlock'}}, 'GetPublicAccessBlock')
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]
    }
    s3.get_bucket_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
    assert is_bucket_public(s3, 'bucket') is True

def test_is_bucket_public_policy_public():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlock'}}, 'GetPublicAccessBlock')
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    assert is_bucket_public(s3, 'bucket') is True

def test_is_bucket_public_private():
    s3 = MagicMock()
    s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlock'}}, 'GetPublicAccessBlock')
    s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    s3.get_bucket_policy.return_value = {
        'Policy': '{"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}]}'
    }
    assert is_bucket_public(s3, 'bucket') is False

# --- find_public_s3_buckets ---
@patch('aws_scanner.scanners.s3_scanner.boto3.client')
def test_find_public_s3_buckets_all_private(mock_boto_client):
    mock_s3 = MagicMock()
    mock_boto_client.return_value = mock_s3
    mock_paginator = MagicMock()
    mock_s3.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {'Buckets': [{'Name': 'bucket1'}]},
        {'Buckets': [{'Name': 'bucket2'}]}
    ]
    mock_s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlock'}}, 'GetPublicAccessBlock')
    mock_s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]
    }
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
    result = find_public_s3_buckets()
    assert result == [
        {'bucket': 'bucket1', 'public': False},
        {'bucket': 'bucket2', 'public': False}
    ]

@patch('aws_scanner.scanners.s3_scanner.boto3.client')
def test_find_public_s3_buckets_some_public(mock_boto_client):
    mock_s3 = MagicMock()
    mock_boto_client.return_value = mock_s3
    mock_paginator = MagicMock()
    mock_s3.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {'Buckets': [{'Name': 'bucket1'}]},
        {'Buckets': [{'Name': 'bucket2'}]}
    ]
    mock_s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlock'}}, 'GetPublicAccessBlock')
    mock_s3.get_bucket_acl.side_effect = [
        {'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]},
        {'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'}}]}
    ]
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
    result = find_public_s3_buckets()
    assert result == [
        {'bucket': 'bucket1', 'public': True},
        {'bucket': 'bucket2', 'public': False}
    ]

@patch('aws_scanner.scanners.s3_scanner.boto3.client')
def test_find_public_s3_buckets_with_error(mock_boto_client):
    mock_s3 = MagicMock()
    mock_boto_client.return_value = mock_s3
    mock_paginator = MagicMock()
    mock_s3.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {'Buckets': [{'Name': 'bucket1'}]},
        {'Buckets': [{'Name': 'bucket2'}]}
    ]
    def acl_side_effect(Bucket):
        if Bucket == 'bucket1':
            raise ClientError({'Error': {'Code': 'AccessDenied'}}, 'GetBucketAcl')
        return {'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]}
    mock_s3.get_public_access_block.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchPublicAccessBlock'}}, 'GetPublicAccessBlock')
    mock_s3.get_bucket_acl.side_effect = acl_side_effect
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
    result = find_public_s3_buckets()
    assert result[0]['bucket'] == 'bucket1'
    assert 'error' in result[0]
    assert result[1] == {'bucket': 'bucket2', 'public': True}
