from unittest.mock import patch, MagicMock
import pytest
import botocore.exceptions
import json

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

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 2
        assert results[0].name == "test-bucket-1"
        assert results[1].name == "test-bucket-2"
        assert results[0].pab_config == {'BlockPublicAcls': True}
        assert results[0].acl_grants == [{'Grantee': {'Type': 'CanonicalUser'}}]
        assert results[0].policy_doc == {"Version": "2012-10-17"}

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

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data(bucket_name="specific-bucket")

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

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

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

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 1
        assert results[0].pab_config == {}


def test_collect_s3_bucket_data_public_access_block_other_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.side_effect = botocore.exceptions.ClientError(
        error_response={'Error': {'Code': 'AccessDenied'}},
        operation_name='GetPublicAccessBlock'
    )

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 0  # Bucket skipped due to error


def test_collect_s3_bucket_data_acl_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    mock_s3.get_bucket_acl.side_effect = botocore.exceptions.ClientError(
        error_response={'Error': {'Code': 'AccessDenied'}},
        operation_name='GetBucketAcl'
    )
    mock_s3.get_bucket_policy.return_value = {'Policy': None}
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.return_value = None

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 1
        assert results[0].acl_grants == []


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

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 1
        assert results[0].policy_doc == {}


def test_collect_s3_bucket_data_cors_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.return_value = {'Policy': None}
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        error_response={'Error': {'Code': 'NoSuchCORSConfiguration'}},
        operation_name='GetBucketCors'
    )
    mock_s3.get_bucket_website.return_value = None

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 1
        assert results[0].cors_config == {}


def test_collect_s3_bucket_data_website_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.return_value = {'Policy': None}
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        error_response={'Error': {'Code': 'NoSuchWebsiteConfiguration'}},
        operation_name='GetBucketWebsite'
    )

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 1
        assert results[0].website_config == {}


def test_collect_s3_bucket_data_empty_policy_string():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}
    }
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.return_value = {'Policy': ''}
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.return_value = None

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 1
        assert results[0].policy_doc == {}


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

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data

        # Should raise JSONDecodeError due to invalid JSON
        with pytest.raises(json.JSONDecodeError):
            collect_s3_bucket_data()


def test_collect_s3_bucket_data_missing_buckets_key():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {}  # Missing 'Buckets' key

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 0


def test_collect_s3_bucket_data_boto3_wrapper_failure():
    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.side_effect = Exception("AWS initialization failed")

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data

        with pytest.raises(Exception, match="AWS initialization failed"):
            collect_s3_bucket_data()


def test_collect_s3_bucket_data_all_operations_successful():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'full-test-bucket'}]}
    mock_s3.get_public_access_block.return_value = {
        'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': False,
            'RestrictPublicBuckets': False
        }
    }
    mock_s3.get_bucket_acl.return_value = {
        'Grants': [
            {'Grantee': {'Type': 'CanonicalUser', 'ID': '123'}, 'Permission': 'FULL_CONTROL'}
        ]
    }
    mock_s3.get_bucket_policy.return_value = {
        'Policy': '{"Version": "2012-10-17", "Statement": []}'
    }
    mock_s3.get_bucket_cors.return_value = {
        'CORSRules': [
            {'AllowedMethods': ['GET'], 'AllowedOrigins': ['*']}
        ]
    }
    mock_s3.get_bucket_website.return_value = {
        'IndexDocument': {'Suffix': 'index.html'},
        'ErrorDocument': {'Key': 'error.html'}
    }

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        assert len(results) == 1
        bucket = results[0]
        assert bucket.name == "full-test-bucket"
        assert bucket.pab_config['BlockPublicAcls'] is True
        assert len(bucket.acl_grants) == 1
        assert bucket.policy_doc['Version'] == "2012-10-17"
        assert len(bucket.cors_config['CORSRules']) == 1
        assert bucket.website_config['IndexDocument']['Suffix'] == 'index.html'


def test_collect_s3_bucket_data_multiple_buckets_mixed_results():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        'Buckets': [
            {'Name': 'bucket-success'},
            {'Name': 'bucket-pab-error'},
            {'Name': 'bucket-partial'}
        ]
    }

    # Configure different responses for different buckets
    def get_pab_side_effect(Bucket):
        if Bucket == 'bucket-pab-error':
            raise botocore.exceptions.ClientError(
                error_response={'Error': {'Code': 'AccessDenied'}},
                operation_name='GetPublicAccessBlock'
            )
        elif Bucket == 'bucket-success':
            return {'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}}
        else:  # bucket-partial
            raise botocore.exceptions.ClientError(
                error_response={'Error': {'Code': 'NoSuchPublicAccessBlock'}},
                operation_name='GetPublicAccessBlock'
            )

    mock_s3.get_public_access_block.side_effect = get_pab_side_effect
    mock_s3.get_bucket_acl.return_value = {'Grants': []}
    mock_s3.get_bucket_policy.return_value = {'Policy': None}
    mock_s3.get_bucket_cors.return_value = None
    mock_s3.get_bucket_website.return_value = None

    with patch("aws_scanner.engines.s3.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_s3.return_value = mock_s3

        from aws_scanner.engines.s3.collector import collect_s3_bucket_data
        results = collect_s3_bucket_data()

        # Only successful and partial buckets should be returned
        assert len(results) == 2
        bucket_names = [b.name for b in results]
        assert 'bucket-success' in bucket_names
        assert 'bucket-partial' in bucket_names
        assert 'bucket-pab-error' not in bucket_names