import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path

from aws_scanner.engines.cloudformation.cloudformation_scanner import scan_cloudformation_template
from aws_scanner.engines.common.resource_definition import ResourceCollection, ResourceDefinition


@pytest.fixture
def sample_template_content():
    return """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: TestRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
"""


def test_scan_cloudformation_template_uses_cloudformation_reader(sample_template_content):
    with patch('aws_scanner.engines.cloudformation.cloudformation_scanner.CloudFormationReader') as mock_reader_class, \
         patch('aws_scanner.engines.cloudformation.cloudformation_scanner.resource_orchestrator') as mock_orchestrator, \
         patch('builtins.open', mock_open(read_data=sample_template_content)), \
         patch('pathlib.Path.exists', return_value=True):

        mock_reader = MagicMock()
        mock_collection = ResourceCollection()
        mock_reader.read.return_value = mock_collection
        mock_reader_class.return_value = mock_reader
        mock_orchestrator.analyze_resources.return_value = []

        scan_cloudformation_template("template.yaml")

        mock_reader_class.assert_called_once()
        mock_reader.read.assert_called_once_with(sample_template_content)


def test_scan_cloudformation_template_calls_resource_orchestrator(sample_template_content):
    with patch('aws_scanner.engines.cloudformation.cloudformation_scanner.CloudFormationReader') as mock_reader_class, \
         patch('aws_scanner.engines.cloudformation.cloudformation_scanner.resource_orchestrator') as mock_orchestrator, \
         patch('builtins.open', mock_open(read_data=sample_template_content)), \
         patch('pathlib.Path.exists', return_value=True):

        mock_reader = MagicMock()
        mock_collection = ResourceCollection()
        mock_reader.read.return_value = mock_collection
        mock_reader_class.return_value = mock_reader
        mock_orchestrator.analyze_resources.return_value = []

        scan_cloudformation_template("template.yaml")

        mock_orchestrator.analyze_resources.assert_called_once_with(mock_collection)


def test_scan_cloudformation_template_formats_results_by_resource_type(sample_template_content):
    with patch('aws_scanner.engines.cloudformation.cloudformation_scanner.CloudFormationReader') as mock_reader_class, \
         patch('aws_scanner.engines.cloudformation.cloudformation_scanner.resource_orchestrator') as mock_orchestrator, \
         patch('builtins.open', mock_open(read_data=sample_template_content)), \
         patch('pathlib.Path.exists', return_value=True):

        mock_reader = MagicMock()
        mock_collection = ResourceCollection()
        mock_reader.read.return_value = mock_collection
        mock_reader_class.return_value = mock_reader

        mock_findings = [
            {"id": "IAM_001", "entity_type": "iam_role", "entity_name": "TestRole"},
            {"id": "S3_001", "entity_type": "s3_bucket", "entity_name": "TestBucket"},
            {"id": "SG_001", "entity_type": "security_group", "entity_name": "TestSG"}
        ]
        mock_orchestrator.analyze_resources.return_value = mock_findings

        results = scan_cloudformation_template("template.yaml")

        assert "iam_roles" in results
        assert "s3_buckets" in results
        assert "security_groups" in results


def test_scan_cloudformation_template_extracts_inline_policies_from_roles(sample_template_content):
    template_with_inline_policy = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: TestRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: InlinePolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: '*'
                Resource: '*'
"""

    with patch('aws_scanner.engines.cloudformation.cloudformation_scanner.CloudFormationReader') as mock_reader_class, \
         patch('aws_scanner.engines.cloudformation.cloudformation_scanner.resource_orchestrator') as mock_orchestrator, \
         patch('builtins.open', mock_open(read_data=template_with_inline_policy)), \
         patch('pathlib.Path.exists', return_value=True):

        mock_reader = MagicMock()
        mock_collection = ResourceCollection()

        role_resource = ResourceDefinition(
            logical_id="MyRole",
            resource_type="AWS::IAM::Role",
            properties={
                "RoleName": "TestRole",
                "Policies": [
                    {
                        "PolicyName": "InlinePolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                        }
                    }
                ]
            }
        )
        mock_collection.add_resource(role_resource)

        mock_reader.read.return_value = mock_collection
        mock_reader_class.return_value = mock_reader
        mock_orchestrator.analyze_resources.return_value = []

        scan_cloudformation_template("template.yaml")

        call_args = mock_orchestrator.analyze_resources.call_args[0][0]

        assert len(call_args.resources) >= 2


def test_scan_cloudformation_template_handles_s3_bucket_policies(sample_template_content):
    template_with_bucket_policy = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: TestBucket
  MyBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref MyBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: '*'
            Action: 's3:GetObject'
            Resource: '*'
"""

    with patch('aws_scanner.engines.cloudformation.cloudformation_scanner.CloudFormationReader') as mock_reader_class, \
         patch('aws_scanner.engines.cloudformation.cloudformation_scanner.resource_orchestrator') as mock_orchestrator, \
         patch('builtins.open', mock_open(read_data=template_with_bucket_policy)), \
         patch('pathlib.Path.exists', return_value=True):

        mock_reader = MagicMock()
        mock_collection = ResourceCollection()

        bucket_resource = ResourceDefinition(
            logical_id="MyBucket",
            resource_type="AWS::S3::Bucket",
            properties={"BucketName": "TestBucket"}
        )
        bucket_policy_resource = ResourceDefinition(
            logical_id="MyBucketPolicy",
            resource_type="AWS::S3::BucketPolicy",
            properties={
                "Bucket": {"Ref": "MyBucket"},
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]
                }
            }
        )
        mock_collection.add_resource(bucket_resource)
        mock_collection.add_resource(bucket_policy_resource)

        mock_reader.read.return_value = mock_collection
        mock_reader_class.return_value = mock_reader
        mock_orchestrator.analyze_resources.return_value = []

        scan_cloudformation_template("template.yaml")

        call_args = mock_orchestrator.analyze_resources.call_args[0][0]

        assert len(call_args.resources) >= 2


def test_scan_cloudformation_template_file_not_found():
    with patch('pathlib.Path.exists', return_value=False):
        with pytest.raises(FileNotFoundError, match="CloudFormation template not found"):
            scan_cloudformation_template("nonexistent.yaml")


def test_scan_cloudformation_template_backward_compatibility():
    with patch('aws_scanner.engines.cloudformation.cloudformation_scanner.CloudFormationReader') as mock_reader_class, \
         patch('aws_scanner.engines.cloudformation.cloudformation_scanner.resource_orchestrator') as mock_orchestrator, \
         patch('builtins.open', mock_open(read_data="template")), \
         patch('pathlib.Path.exists', return_value=True):

        mock_reader = MagicMock()
        mock_collection = ResourceCollection()
        mock_reader.read.return_value = mock_collection
        mock_reader_class.return_value = mock_reader

        mock_findings = [
            {"id": "IAM_POLICY_WILDCARD_ALL", "entity_type": "iam_role", "entity_name": "Role1"},
            {"id": "S3_PUBLIC_POLICY", "entity_type": "s3_bucket", "entity_name": "Bucket1"},
        ]
        mock_orchestrator.analyze_resources.return_value = mock_findings

        results = scan_cloudformation_template("template.yaml")

        assert isinstance(results, dict)
        assert "iam_roles" in results
        assert "s3_buckets" in results
