import pytest
from aws_scanner.engines.common.resource_definition import ResourceDefinition


def test_analyze_s3_bucket_from_resource_accepts_resource_definition():
    resource_def = ResourceDefinition(
        logical_id="MyBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "my-secure-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    assert isinstance(findings, list)


def test_analyze_s3_bucket_from_resource_public_acl():
    resource_def = ResourceDefinition(
        logical_id="PublicBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "public-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            },
            "AclGrants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                }
            ]
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_ACL" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_public_acl_ignored_by_pab():
    resource_def = ResourceDefinition(
        logical_id="ProtectedBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "protected-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            },
            "AclGrants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                }
            ]
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_ACL" not in vulnerability_ids


def test_analyze_s3_bucket_from_resource_public_cors():
    resource_def = ResourceDefinition(
        logical_id="CorsBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "cors-bucket",
            "CorsConfiguration": {
                "CorsRules": [
                    {
                        "AllowedOrigins": ["*"],
                        "AllowedMethods": ["GET", "POST"],
                        "AllowedHeaders": ["*"]
                    }
                ]
            }
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_CORS" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_multiple_cors_rules():
    resource_def = ResourceDefinition(
        logical_id="MultipleCorsBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "multiple-cors-bucket",
            "CorsConfiguration": {
                "CorsRules": [
                    {
                        "AllowedOrigins": ["https://example.com"],
                        "AllowedMethods": ["GET"],
                        "AllowedHeaders": ["Authorization"]
                    },
                    {
                        "AllowedOrigins": ["*"],
                        "AllowedMethods": ["GET", "POST"],
                        "AllowedHeaders": ["*"]
                    },
                    {
                        "AllowedOrigins": ["https://another-example.com"],
                        "AllowedMethods": ["PUT"],
                        "AllowedHeaders": ["Content-Type"]
                    },
                    {
                        "AllowedOrigins": ["https://trusted.com"],
                        "AllowedMethods": ["*"],
                        "AllowedHeaders": ["*"]
                    }
                ]
            }
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    cors_findings = [f for f in findings if f["id"] == "S3_PUBLIC_CORS"]

    assert "S3_PUBLIC_CORS" in vulnerability_ids
    assert len(cors_findings) == 2


def test_analyze_s3_bucket_from_resource_website_hosting():
    resource_def = ResourceDefinition(
        logical_id="WebsiteBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "website-bucket",
            "WebsiteConfiguration": {
                "IndexDocument": "index.html",
                "ErrorDocument": "error.html"
            }
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_WEBSITE" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_no_encryption():
    resource_def = ResourceDefinition(
        logical_id="UnencryptedBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "unencrypted-bucket"
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_NO_ENCRYPTION" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_no_logging():
    resource_def = ResourceDefinition(
        logical_id="NoLoggingBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "no-logging-bucket"
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_NO_ACCESS_LOGGING" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_versioning_suspended():
    resource_def = ResourceDefinition(
        logical_id="SuspendedVersioningBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "suspended-versioning-bucket",
            "VersioningConfiguration": {
                "Status": "Suspended"
            }
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_VERSIONING_SUSPENDED" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_mfa_delete_disabled():
    resource_def = ResourceDefinition(
        logical_id="NoMfaDeleteBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "no-mfa-delete-bucket",
            "MfaDelete": False
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_MFA_DELETE_DISABLED" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_secure_configuration():
    resource_def = ResourceDefinition(
        logical_id="SecureBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "secure-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            },
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    {
                        "ServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            },
            "VersioningConfiguration": {
                "Status": "Enabled"
            },
            "LoggingConfiguration": {
                "DestinationBucketName": "log-bucket",
                "LogFilePrefix": "logs/"
            },
            "MfaDelete": True
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_s3_bucket_from_resource_does_not_analyze_bucket_policy():
    resource_def = ResourceDefinition(
        logical_id="BucketWithPolicy",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "bucket-with-policy",
            "BucketPolicy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::bucket-with-policy/*"
                    }
                ]
            }
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_POLICY" not in vulnerability_ids


def test_analyze_s3_bucket_from_resource_multiple_vulnerabilities():
    resource_def = ResourceDefinition(
        logical_id="VulnerableBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "vulnerable-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            },
            "AclGrants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                }
            ],
            "WebsiteConfiguration": {
                "IndexDocument": "index.html"
            },
            "MfaDelete": False
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_ACL" in vulnerability_ids
    assert "S3_PUBLIC_WEBSITE" in vulnerability_ids
    assert "S3_NO_ENCRYPTION" in vulnerability_ids
    assert "S3_NO_ACCESS_LOGGING" in vulnerability_ids
    assert "S3_MFA_DELETE_DISABLED" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_partial_pab_config():
    resource_def = ResourceDefinition(
        logical_id="PartialPABBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "partial-pab-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True
            },
            "AclGrants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                }
            ],
            "Policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::partial-pab-bucket/*"
                    }
                ]
            }
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_ACL" not in vulnerability_ids
    assert "S3_PUBLIC_POLICY" in vulnerability_ids


def test_analyze_s3_bucket_from_resource_null_cors():
    resource_def = ResourceDefinition(
        logical_id="NullCorsBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "null-cors-bucket",
            "CorsConfiguration": None
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_CORS" not in vulnerability_ids


def test_analyze_s3_bucket_from_resource_empty_cors_rules():
    resource_def = ResourceDefinition(
        logical_id="EmptyCorsRulesBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "empty-cors-rules-bucket",
            "CorsConfiguration": {
                "CorsRules": []
            }
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_CORS" not in vulnerability_ids


def test_analyze_s3_bucket_from_resource_null_pab():
    resource_def = ResourceDefinition(
        logical_id="NullPABBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "null-pab-bucket",
            "PublicAccessBlockConfiguration": None,
            "AclGrants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                    },
                    "Permission": "READ"
                }
            ]
        }
    )

    from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource

    findings = analyze_s3_bucket_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "S3_PUBLIC_ACL" in vulnerability_ids
