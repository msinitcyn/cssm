import pytest


def test_read_yaml_template():
    yaml_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: test-role
"""

    from aws_scanner.engines.cloudformation.reader import CloudFormationReader

    reader = CloudFormationReader()
    collection = reader.read(yaml_content)

    assert len(collection.resources) == 2

    bucket = collection.get_by_id("MyBucket")
    assert bucket is not None
    assert bucket.resource_type == "AWS::S3::Bucket"
    assert bucket.properties["BucketName"] == "test-bucket"

    role = collection.get_by_id("MyRole")
    assert role is not None
    assert role.resource_type == "AWS::IAM::Role"
    assert role.properties["RoleName"] == "test-role"


def test_read_json_template():
    json_content = """
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "test-bucket"
      }
    },
    "MySecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupName": "test-sg",
        "GroupDescription": "Test security group"
      }
    }
  }
}
"""

    from aws_scanner.engines.cloudformation.reader import CloudFormationReader

    reader = CloudFormationReader()
    collection = reader.read(json_content)

    assert len(collection.resources) == 2

    bucket = collection.get_by_id("MyBucket")
    assert bucket is not None
    assert bucket.resource_type == "AWS::S3::Bucket"

    sg = collection.get_by_id("MySecurityGroup")
    assert sg is not None
    assert sg.resource_type == "AWS::EC2::SecurityGroup"


def test_filter_resources_by_type():
    yaml_content = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: test-role
  MySecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Test SG
"""

    from aws_scanner.engines.cloudformation.reader import CloudFormationReader

    reader = CloudFormationReader()
    collection = reader.read(yaml_content)

    s3_buckets = collection.get_resources_by_type("AWS::S3::Bucket")
    assert len(s3_buckets) == 1
    assert s3_buckets[0].logical_id == "MyBucket"

    iam_roles = collection.get_resources_by_type("AWS::IAM::Role")
    assert len(iam_roles) == 1
    assert iam_roles[0].logical_id == "MyRole"

    security_groups = collection.get_resources_by_type("AWS::EC2::SecurityGroup")
    assert len(security_groups) == 1
    assert security_groups[0].logical_id == "MySecurityGroup"


def test_read_yaml_with_intrinsic_functions():
    yaml_content = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${AWS::StackName}-bucket'
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: !GetAtt MyBucket.Arn
"""

    from aws_scanner.engines.cloudformation.reader import CloudFormationReader

    reader = CloudFormationReader()
    collection = reader.read(yaml_content)

    assert len(collection.resources) == 2

    bucket = collection.get_by_id("MyBucket")
    assert bucket is not None

    role = collection.get_by_id("MyRole")
    assert role is not None


def test_read_template_with_non_resource_sections():
    yaml_content = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Test template
Parameters:
  BucketName:
    Type: String
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
  MyRole:
    Type: AWS::IAM::Role
Outputs:
  BucketArn:
    Value: !GetAtt MyBucket.Arn
"""

    from aws_scanner.engines.cloudformation.reader import CloudFormationReader

    reader = CloudFormationReader()
    collection = reader.read(yaml_content)

    assert len(collection.resources) == 2
    assert collection.get_by_id("MyBucket") is not None
    assert collection.get_by_id("MyRole") is not None


def test_read_empty_resources():
    yaml_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources: {}
"""

    from aws_scanner.engines.cloudformation.reader import CloudFormationReader

    reader = CloudFormationReader()
    collection = reader.read(yaml_content)

    assert len(collection.resources) == 0


def test_read_invalid_yaml():
    invalid_yaml = """
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
  - InvalidSyntax
"""

    from aws_scanner.engines.cloudformation.reader import CloudFormationReader

    reader = CloudFormationReader()

    with pytest.raises(Exception):
        reader.read(invalid_yaml)


def test_read_invalid_json():
    invalid_json = """
{
  "Resources": {
    "MyBucket": {
      "Type": "AWS::S3::Bucket"
    }
  }
  "Invalid"
}
"""

    from aws_scanner.engines.cloudformation.reader import CloudFormationReader

    reader = CloudFormationReader()

    with pytest.raises(Exception):
        reader.read(invalid_json)