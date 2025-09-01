from unittest.mock import MagicMock
import botocore.exceptions

def test_collect_s3_bucket_data_without_bucket_name():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        'Buckets': [
            {'Name': 'test-bucket-1'},
            {'Name': 'test-bucket-2'}
        ]
    }
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    mock_s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'Type': 'CanonicalUser'}}]
    }
    mock_s3.get_bucket_policy.return_value = {
        'Policy': '{"Version": "2012-10-17"}'
    }
    mock_s3.get_bucket_cors.return_value = {'CORSRules': []}
    mock_s3.get_bucket_website.return_value = {'IndexDocument': {'Suffix': 'index.html'}}
    mock_s3.get_bucket_logging.return_value = {'LoggingEnabled': {'TargetBucket': 'log-bucket'}}
    mock_s3.get_bucket_versioning.return_value = {'Status': 'Enabled', 'MfaDelete': 'Disabled'}
    mock_s3.get_bucket_encryption.return_value = {'ServerSideEncryptionConfiguration': {'Rules': []}}

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_s3.return_value = mock_s3

    from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
    collector = AwsS3Collector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 2
    assert results[0].name == "test-bucket-1"
    assert results[1].name == "test-bucket-2"
    assert results[0].pab_config == {'BlockPublicAcls': True}
    assert results[0].acl_grants == [{'Grantee': {'Type': 'CanonicalUser'}}]
    assert results[0].policy.document == {"Version": "2012-10-17"}
    assert results[0].server_access_logging == {'TargetBucket': 'log-bucket'}
    assert results[0].versioning == {'Status': 'Enabled', 'MfaDelete': 'Disabled'}
    assert results[0].encryption == {'Rules': []}
    assert results[0].mfa_delete is False

    mock_s3.list_buckets.assert_called_once()

def test_collect_s3_bucket_data_with_bucket_name():
    mock_s3 = MagicMock()
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': False}
    }
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.return_value = {'Policy': None}
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.return_value = None
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.return_value = {}

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_s3.return_value = mock_s3

    from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
    collector = AwsS3Collector(mock_boto3_wrapper)
    results = collector._collect_s3_bucket_data(bucket_name="specific-bucket")

    assert len(results) == 1
    assert results[0].name == "specific-bucket"
    assert results[0].pab_config == {'BlockPublicAcls': False}

    mock_s3.list_buckets.assert_not_called()

def test_collect_s3_bucket_data_list_buckets_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.side_effect = botocore.exceptions.ClientError(
        error_response={'Error': {'Code': 'AccessDenied'}},
        operation_name='ListBuckets'
    )

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_s3.return_value = mock_s3

    from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
    collector = AwsS3Collector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 0

def test_collect_s3_bucket_data_no_such_public_access_block():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.side_effect = botocore.exceptions.ClientError(
        error_response={'Error': {'Code': 'NoSuchPublicAccessBlock'}},
        operation_name='GetPublicAccessBlock'
    )
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.return_value = {'Policy': None}
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.return_value = None
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.return_value = {}

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_s3.return_value = mock_s3

    from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
    collector = AwsS3Collector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].pab_config == {}

def test_collect_s3_bucket_data_public_access_block_other_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.side_effect = botocore.exceptions.ClientError(
        error_response={'Error': {'Code': 'AccessDenied'}},
        operation_name='GetPublicAccessBlock'
    )

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_s3.return_value = mock_s3

    from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
    collector = AwsS3Collector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 0

def test_collect_s3_bucket_data_policy_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        error_response={'Error': {'Code': 'NoSuchBucketPolicy'}},
        operation_name='GetBucketPolicy'
    )
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.return_value = None
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.return_value = {}

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_s3.return_value = mock_s3

    from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
    collector = AwsS3Collector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].policy is None

def test_collect_s3_bucket_data_invalid_json_policy():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.return_value = {'Policy': 'invalid-json'}
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.return_value = None
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.return_value = {}

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_s3.return_value = mock_s3

    from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
    collector = AwsS3Collector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].policy is None

def test_mfa_delete_enabled():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {}}
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.return_value = {'Policy': None}
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.return_value = None
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {'MfaDelete': 'Enabled'}
    mock_s3.get_bucket_encryption.return_value = {}

    mock_boto3_wrapper = MagicMock()
    mock_boto3_wrapper.get_s3.return_value = mock_s3

    from aws_scanner.engines.s3.aws_s3_collector import AwsS3Collector
    collector = AwsS3Collector(mock_boto3_wrapper)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].mfa_delete is True