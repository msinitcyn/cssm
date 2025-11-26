from unittest.mock import MagicMock
import botocore.exceptions
import pytest
from aws_scanner.engines.s3.resource_aws_s3_collector import ResourceAwsS3Collector
from aws_scanner.engines.common.resource_definition import ResourceCollection
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


def test_collect_returns_resource_collection():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    assert isinstance(result, ResourceCollection)


def test_bucket_becomes_resource_definition_with_correct_type():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 1
    resource = result.resources["test-bucket"]
    assert resource.resource_type == "AWS::S3::Bucket"


def test_bucket_properties_include_name_and_pab():
    pab_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True
    }
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": pab_config}
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    resource = result.resources["test-bucket"]
    assert resource.properties["BucketName"] == "test-bucket"
    assert resource.properties["PublicAccessBlockConfiguration"] == pab_config


def test_bucket_properties_include_acl_policy_cors():
    acl_grants = [{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]
    policy_doc = {"Version": "2012-10-17", "Statement": []}
    cors_config = {"CorsRules": [{"AllowedOrigins": ["*"]}]}

    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    mock_s3.get_bucket_acl.return_value = {"Grants": acl_grants}
    mock_s3.get_bucket_policy.return_value = {"Policy": '{"Version": "2012-10-17", "Statement": []}'}
    mock_s3.get_bucket_cors.return_value = {"CORSRules": cors_config["CorsRules"]}
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    resource = result.resources["test-bucket"]
    assert resource.properties["AclGrants"] == acl_grants
    assert resource.properties["Policy"] == policy_doc
    assert resource.properties["CorsConfiguration"] == cors_config


def test_handles_no_such_bucket_policy_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 1
    resource = result.resources["test-bucket"]
    assert resource.properties.get("Policy") is None


def test_handles_no_such_public_access_block_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    mock_s3.get_public_access_block.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "GetPublicAccessBlock"
    )
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    assert len(result.resources) == 1
    resource = result.resources["test-bucket"]
    assert resource.properties.get("PublicAccessBlockConfiguration") is None


def test_bucket_name_parameter_scans_specific_bucket():
    mock_s3 = MagicMock()
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper, bucket_name="specific-bucket")
    result = collector.collect()

    mock_s3.list_buckets.assert_not_called()
    assert len(result.resources) == 1
    assert "specific-bucket" in result.resources


def test_no_bucket_name_parameter_scans_all_buckets():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "bucket1"}, {"Name": "bucket2"}]}
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    mock_s3.list_buckets.assert_called_once()
    assert len(result.resources) == 2
    assert "bucket1" in result.resources
    assert "bucket2" in result.resources


def test_bucket_properties_include_encryption_and_logging():
    encryption_config = {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
    logging_config = {"LoggingEnabled": {"TargetBucket": "log-bucket"}}

    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchWebsiteConfiguration"}}, "GetBucketWebsite"
    )
    mock_s3.get_bucket_logging.return_value = {"LoggingEnabled": logging_config["LoggingEnabled"]}
    mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    mock_s3.get_bucket_encryption.return_value = encryption_config

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    resource = result.resources["test-bucket"]
    assert resource.properties["BucketEncryption"] == encryption_config
    assert resource.properties["LoggingConfiguration"] == logging_config
    assert resource.properties["VersioningConfiguration"] == {"Status": "Enabled"}


def test_bucket_properties_include_website_and_mfa_delete():
    website_config = {"IndexDocument": {"Suffix": "index.html"}}

    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    mock_s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {}}
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_policy.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy"}}, "GetBucketPolicy"
    )
    mock_s3.get_bucket_cors.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "NoSuchCORSConfiguration"}}, "GetBucketCors"
    )
    mock_s3.get_bucket_website.return_value = website_config
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_versioning.return_value = {"Status": "Enabled", "MFADelete": "Enabled"}
    mock_s3.get_bucket_encryption.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}, "GetBucketEncryption"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_s3.return_value = mock_s3

    collector = ResourceAwsS3Collector(mock_wrapper)
    result = collector.collect()

    resource = result.resources["test-bucket"]
    assert resource.properties["WebsiteConfiguration"] == website_config
    assert resource.properties["MfaDelete"] is True
