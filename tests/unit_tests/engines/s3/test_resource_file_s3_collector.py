import json
from unittest.mock import patch, mock_open
from aws_scanner.engines.s3.resource_file_s3_collector import ResourceFileS3Collector
from aws_scanner.core.resource_collection import ResourceCollection


def test_collect_returns_resource_collection():
    test_data = {
        "test-bucket": {
            "acl_grants": [],
            "policy": None,
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        assert isinstance(result, ResourceCollection)


def test_bucket_becomes_resource_definition():
    test_data = {
        "test-bucket": {
            "acl_grants": [],
            "policy": None,
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        bucket_def = result.get_resource("test-bucket")
        assert bucket_def is not None
        assert bucket_def.resource_type == "AWS::S3::Bucket"
        assert bucket_def.logical_id == "test-bucket"


def test_bucket_properties():
    test_data = {
        "test-bucket": {
            "acl_grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ"
                }
            ],
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::test-bucket/*"
                    }
                ]
            },
            "public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        bucket_def = result.get_resource("test-bucket")
        assert bucket_def.properties["BucketName"] == "test-bucket"
        assert bucket_def.properties["AclGrants"] == test_data["test-bucket"]["acl_grants"]
        assert bucket_def.properties["BucketPolicy"] == test_data["test-bucket"]["policy"]
        assert bucket_def.properties["PublicAccessBlockConfiguration"] == test_data["test-bucket"]["public_access_block"]


def test_multiple_buckets():
    test_data = {
        "bucket-1": {
            "acl_grants": [],
            "policy": None,
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        },
        "bucket-2": {
            "acl_grants": [],
            "policy": None,
            "public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        assert len(result.resources) == 2
        bucket1 = result.get_resource("bucket-1")
        bucket2 = result.get_resource("bucket-2")
        assert bucket1 is not None
        assert bucket2 is not None
        assert bucket1.properties["BucketName"] == "bucket-1"
        assert bucket2.properties["BucketName"] == "bucket-2"


def test_bucket_with_missing_optional_fields():
    test_data = {
        "minimal-bucket": {
            "acl_grants": [],
            "policy": None,
            "public_access_block": None
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        bucket_def = result.get_resource("minimal-bucket")
        assert bucket_def is not None
        assert bucket_def.properties["BucketName"] == "minimal-bucket"
        assert bucket_def.properties["AclGrants"] == []
        assert bucket_def.properties["BucketPolicy"] is None
        assert bucket_def.properties["PublicAccessBlockConfiguration"] is None