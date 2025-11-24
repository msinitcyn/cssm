import pytest
from unittest.mock import patch, MagicMock
from aws_scanner.engines.common.resource_definition import ResourceDefinition, ResourceCollection
from aws_scanner.core.resource_orchestrator import analyze_resources


@pytest.fixture
def iam_role_resource():
    return ResourceDefinition(
        logical_id="MyRole",
        resource_type="AWS::IAM::Role",
        properties={
            "RoleName": "MyRole",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
        }
    )


@pytest.fixture
def iam_policy_resource():
    return ResourceDefinition(
        logical_id="MyPolicy",
        resource_type="AWS::IAM::Policy",
        properties={
            "PolicyName": "MyPolicy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
        }
    )


@pytest.fixture
def s3_bucket_resource():
    return ResourceDefinition(
        logical_id="MyBucket",
        resource_type="AWS::S3::Bucket",
        properties={
            "BucketName": "my-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "BlockPublicPolicy": False,
                "IgnorePublicAcls": False,
                "RestrictPublicBuckets": False
            }
        }
    )


@pytest.fixture
def security_group_resource():
    return ResourceDefinition(
        logical_id="MySecurityGroup",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupName": "MySecurityGroup",
            "GroupDescription": "My security group",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )


@pytest.fixture
def unknown_resource():
    return ResourceDefinition(
        logical_id="MyUnknownResource",
        resource_type="AWS::Unknown::Resource",
        properties={}
    )


def test_analyze_resources_accepts_resource_collection():
    collection = ResourceCollection()
    result = analyze_resources(collection)
    assert isinstance(result, list)


def test_analyze_resources_routes_iam_role(iam_role_resource):
    collection = ResourceCollection()
    collection.add_resource(iam_role_resource)

    with patch('aws_scanner.core.resource_orchestrator.analyze_iam_role_from_resource') as mock_analyze:
        mock_analyze.return_value = [{"id": "IAM_ROLE_001", "severity": "high"}]

        result = analyze_resources(collection)

        mock_analyze.assert_called_once_with(iam_role_resource)
        assert len(result) == 1
        assert result[0]["id"] == "IAM_ROLE_001"


def test_analyze_resources_routes_iam_policy(iam_policy_resource):
    collection = ResourceCollection()
    collection.add_resource(iam_policy_resource)

    with patch('aws_scanner.core.resource_orchestrator.analyze_iam_policy_from_resource') as mock_analyze:
        mock_analyze.return_value = [{"id": "IAM_POL_001", "severity": "critical"}]

        result = analyze_resources(collection)

        mock_analyze.assert_called_once_with(iam_policy_resource)
        assert len(result) == 1
        assert result[0]["id"] == "IAM_POL_001"


def test_analyze_resources_routes_s3_bucket(s3_bucket_resource):
    collection = ResourceCollection()
    collection.add_resource(s3_bucket_resource)

    with patch('aws_scanner.core.resource_orchestrator.analyze_s3_bucket_from_resource') as mock_analyze:
        mock_analyze.return_value = [{"id": "S3_001", "severity": "high"}]

        result = analyze_resources(collection)

        mock_analyze.assert_called_once_with(s3_bucket_resource)
        assert len(result) == 1
        assert result[0]["id"] == "S3_001"


def test_analyze_resources_routes_security_group(security_group_resource):
    collection = ResourceCollection()
    collection.add_resource(security_group_resource)

    with patch('aws_scanner.core.resource_orchestrator.analyze_sg_from_resource') as mock_analyze:
        mock_analyze.return_value = [{"id": "SG_001", "severity": "medium"}]

        result = analyze_resources(collection)

        mock_analyze.assert_called_once_with(security_group_resource)
        assert len(result) == 1
        assert result[0]["id"] == "SG_001"


def test_analyze_resources_aggregates_findings_from_multiple_resources(
    iam_role_resource, iam_policy_resource, s3_bucket_resource, security_group_resource
):
    collection = ResourceCollection()
    collection.add_resource(iam_role_resource)
    collection.add_resource(iam_policy_resource)
    collection.add_resource(s3_bucket_resource)
    collection.add_resource(security_group_resource)

    with patch('aws_scanner.core.resource_orchestrator.analyze_iam_role_from_resource') as mock_role, \
         patch('aws_scanner.core.resource_orchestrator.analyze_iam_policy_from_resource') as mock_policy, \
         patch('aws_scanner.core.resource_orchestrator.analyze_s3_bucket_from_resource') as mock_s3, \
         patch('aws_scanner.core.resource_orchestrator.analyze_sg_from_resource') as mock_sg:

        mock_role.return_value = [{"id": "IAM_ROLE_001"}]
        mock_policy.return_value = [{"id": "IAM_POL_001"}, {"id": "IAM_POL_002"}]
        mock_s3.return_value = [{"id": "S3_001"}]
        mock_sg.return_value = [{"id": "SG_001"}]

        result = analyze_resources(collection)

        assert len(result) == 5
        finding_ids = [f["id"] for f in result]
        assert "IAM_ROLE_001" in finding_ids
        assert "IAM_POL_001" in finding_ids
        assert "IAM_POL_002" in finding_ids
        assert "S3_001" in finding_ids
        assert "SG_001" in finding_ids


def test_analyze_resources_handles_unknown_resource_type(unknown_resource):
    collection = ResourceCollection()
    collection.add_resource(unknown_resource)

    result = analyze_resources(collection)

    assert result == []


def test_analyze_resources_skips_unknown_and_processes_known(
    iam_policy_resource, unknown_resource
):
    collection = ResourceCollection()
    collection.add_resource(iam_policy_resource)
    collection.add_resource(unknown_resource)

    with patch('aws_scanner.core.resource_orchestrator.analyze_iam_policy_from_resource') as mock_analyze:
        mock_analyze.return_value = [{"id": "IAM_POL_001"}]

        result = analyze_resources(collection)

        assert len(result) == 1
        assert result[0]["id"] == "IAM_POL_001"


def test_analyze_resources_handles_empty_collection():
    collection = ResourceCollection()
    result = analyze_resources(collection)
    assert result == []


def test_analyze_resources_handles_analyzer_returning_empty_list(iam_role_resource):
    collection = ResourceCollection()
    collection.add_resource(iam_role_resource)

    with patch('aws_scanner.core.resource_orchestrator.analyze_iam_role_from_resource') as mock_analyze:
        mock_analyze.return_value = []

        result = analyze_resources(collection)

        assert result == []


def test_analyze_resources_routes_managed_policy(iam_policy_resource):
    iam_policy_resource.resource_type = "AWS::IAM::ManagedPolicy"
    collection = ResourceCollection()
    collection.add_resource(iam_policy_resource)

    with patch('aws_scanner.core.resource_orchestrator.analyze_iam_policy_from_resource') as mock_analyze:
        mock_analyze.return_value = [{"id": "IAM_POL_001"}]

        result = analyze_resources(collection)

        mock_analyze.assert_called_once_with(iam_policy_resource)
        assert len(result) == 1
