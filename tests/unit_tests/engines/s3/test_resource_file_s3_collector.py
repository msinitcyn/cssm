import json
import pytest
from unittest.mock import patch, mock_open
from aws_scanner.engines.s3.resource_file_s3_collector import ResourceFileS3Collector
from aws_scanner.engines.common.resource_definition import ResourceCollection


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

        bucket_def = result.get_by_id("test-bucket")
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

        bucket_def = result.get_by_id("test-bucket")
        assert bucket_def.properties["BucketName"] == "test-bucket"
        assert bucket_def.properties["AclGrants"] == test_data["test-bucket"]["acl_grants"]
        assert bucket_def.properties["Policy"] == test_data["test-bucket"]["policy"]
        assert bucket_def.properties["PublicAccessBlockConfiguration"] == test_data["test-bucket"]["public_access_block"]


@pytest.mark.skip(reason="File collector no longer creates separate BucketPolicy resources")
def test_bucket_policy_becomes_separate_resource_definition():
    test_data = {
        "test-bucket": {
            "acl_grants": [],
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
            "public_access_block": None
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        policy_def = result.get_by_id("test-bucket-bucket-policy")
        assert policy_def is not None
        assert policy_def.resource_type == "AWS::S3::BucketPolicy"
        assert policy_def.properties["PolicyDocument"] == test_data["test-bucket"]["policy"]


@pytest.mark.skip(reason="File collector no longer creates bucket references")
def test_bucket_references_policy():
    test_data = {
        "test-bucket": {
            "acl_grants": [],
            "policy": {
                "Version": "2012-10-17",
                "Statement": []
            },
            "public_access_block": None
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        bucket_def = result.get_by_id("test-bucket")
        assert len(bucket_def.references) == 1
        assert bucket_def.references[0].target_logical_id == "test-bucket-bucket-policy"


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
        bucket1 = result.get_by_id("bucket-1")
        bucket2 = result.get_by_id("bucket-2")
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

        bucket_def = result.get_by_id("minimal-bucket")
        assert bucket_def is not None
        assert bucket_def.properties["BucketName"] == "minimal-bucket"
        assert bucket_def.properties["AclGrants"] == []
        assert bucket_def.properties["Policy"] is None
        assert bucket_def.properties["PublicAccessBlockConfiguration"] == {}


def test_acl_string_public_read_converts_to_grants():
    test_data = {
        "test-bucket": {
            "acl": "public-read",
            "policy": None,
            "public_access_block": None
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        bucket_def = result.get_by_id("test-bucket")
        acl_grants = bucket_def.properties["AclGrants"]

        assert len(acl_grants) == 1
        assert acl_grants[0]["Permission"] == "READ"
        assert acl_grants[0]["Grantee"]["Type"] == "Group"
        assert acl_grants[0]["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AllUsers"


def test_acl_string_public_read_write_converts_to_grants():
    test_data = {
        "test-bucket": {
            "acl": "public-read-write",
            "policy": None,
            "public_access_block": None
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        bucket_def = result.get_by_id("test-bucket")
        acl_grants = bucket_def.properties["AclGrants"]

        assert len(acl_grants) == 2
        assert acl_grants[0]["Permission"] == "READ"
        assert acl_grants[1]["Permission"] == "WRITE"
        assert all(g["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AllUsers" for g in acl_grants)


def test_acl_string_private_converts_to_empty_grants():
    test_data = {
        "test-bucket": {
            "acl": "private",
            "policy": None,
            "public_access_block": None
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        bucket_def = result.get_by_id("test-bucket")
        acl_grants = bucket_def.properties["AclGrants"]

        assert len(acl_grants) == 0


def test_acl_array_passthrough_preserved():
    custom_grants = [
        {
            "Grantee": {"Type": "CanonicalUser", "ID": "user123"},
            "Permission": "FULL_CONTROL"
        }
    ]

    test_data = {
        "test-bucket": {
            "acl": custom_grants,
            "policy": None,
            "public_access_block": None
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()

        bucket_def = result.get_by_id("test-bucket")
        acl_grants = bucket_def.properties["AclGrants"]

        assert acl_grants == custom_grants


def test_pab_alias_block_public_access():
    pab_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False
    }

    test_data = {
        "test-bucket": {
            "acl": "private",
            "policy": None,
            "block_public_access": pab_config
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()
        bucket_def = result.get_by_id("test-bucket")
        assert bucket_def.properties["PublicAccessBlockConfiguration"] == pab_config


def test_pab_alias_pab_config():
    pab_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False
    }

    test_data = {
        "test-bucket": {
            "acl": "private",
            "policy": None,
            "pab_config": pab_config
        }
    }

    with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
        collector = ResourceFileS3Collector("test_file.json")
        result = collector.collect()
        bucket_def = result.get_by_id("test-bucket")
        assert bucket_def.properties["PublicAccessBlockConfiguration"] == pab_config