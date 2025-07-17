from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.scanners.s3.collector import collect_s3_bucket_data
from aws_scanner.scanners.s3.s3_bucket_data import S3BucketData

class DummyClientError(ClientError):
    def __init__(self, code):
        super().__init__({'Error': {'Code': code}}, 'operation')

def test_collect_single_bucket_success():
    original_get_s3 = Boto3Wrapper.get_s3
    mock_s3 = MagicMock()
    Boto3Wrapper.get_s3 = MagicMock(return_value=mock_s3)

    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}}
    mock_s3.get_bucket_acl.return_value = {'Grants': ['grant1']}
    mock_s3.get_bucket_policy.return_value = {'Policy': '{"Statement": []}'}
    mock_s3.get_bucket_cors.return_value = {'CORSRules': ['rule1']}
    mock_s3.get_bucket_website.return_value = {'IndexDocument': 'index.html'}

    results = collect_s3_bucket_data('test-bucket')
    assert len(results) == 1
    assert isinstance(results[0], S3BucketData)
    assert results[0].name == 'test-bucket'
    assert results[0].pab_config == {'BlockPublicAcls': True}
    assert results[0].acl_grants == ['grant1']
    assert results[0].policy_doc == {'Statement': []}
    assert results[0].cors_config == {'CORSRules': ['rule1']}
    assert results[0].website_config == {'IndexDocument': 'index.html'}

    Boto3Wrapper.get_s3 = original_get_s3

def test_collect_all_buckets_with_errors():
    original_get_s3 = Boto3Wrapper.get_s3
    mock_s3 = MagicMock()
    Boto3Wrapper.get_s3 = MagicMock(return_value=mock_s3)

    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'bucket1'}, {'Name': 'bucket2'}]}
    mock_s3.get_public_access_block.side_effect = [
        DummyClientError('NoSuchPublicAccessBlock'),
        {'PublicAccessBlockConfiguration': {}}
    ]
    mock_s3.get_bucket_acl.side_effect = [
        DummyClientError('AccessDenied'),
        {'Grants': []}
    ]
    mock_s3.get_bucket_policy.side_effect = [
        {'Policy': None},
        DummyClientError('NoSuchBucketPolicy')
    ]

    results = collect_s3_bucket_data()
    assert len(results) == 2
    assert results[0].pab_config == {}
    assert results[0].acl_grants == []
    assert results[1].pab_config == {}
    assert results[1].acl_grants == []

    Boto3Wrapper.get_s3 = original_get_s3

def test_list_buckets_error():
    original_get_s3 = Boto3Wrapper.get_s3
    mock_s3 = MagicMock()
    Boto3Wrapper.get_s3 = MagicMock(return_value=mock_s3)

    mock_s3.list_buckets.side_effect = ClientError({'Error': {'Code': 'AccessDenied'}}, 'ListBuckets')

    results = collect_s3_bucket_data()
    assert results == []

    Boto3Wrapper.get_s3 = original_get_s3

def test_public_access_block_error():
    original_get_s3 = Boto3Wrapper.get_s3
    mock_s3 = MagicMock()
    Boto3Wrapper.get_s3 = MagicMock(return_value=mock_s3)

    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'bucket1'}]}
    mock_s3.get_public_access_block.side_effect = DummyClientError('AccessDenied')

    results = collect_s3_bucket_data()
    assert len(results) == 0

    Boto3Wrapper.get_s3 = original_get_s3

def test_policy_parsing():
    original_get_s3 = Boto3Wrapper.get_s3
    mock_s3 = MagicMock()
    Boto3Wrapper.get_s3 = MagicMock(return_value=mock_s3)

    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'bucket1'}]}
    mock_s3.get_bucket_policy.return_value = {'Policy': '{"Version": "2012-10-17"}'}

    results = collect_s3_bucket_data()
    assert len(results) == 1
    assert results[0].policy_doc == {'Version': '2012-10-17'}

    Boto3Wrapper.get_s3 = original_get_s3