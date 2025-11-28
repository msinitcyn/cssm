import pytest
from aws_scanner.engines.cloudformation.resource_file_cloudformation_collector import ResourceFileCloudFormationCollector
from aws_scanner.engines.common.resource_definition import ResourceCollection


def test_collect_returns_resource_collection(tmp_path):
    template_file = tmp_path / "template.yaml"
    template_file.write_text("""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    collection = collector.collect()
    
    assert isinstance(collection, ResourceCollection)


def test_yaml_template_parsing(tmp_path):
    template_file = tmp_path / "template.yaml"
    template_file.write_text("""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-test-bucket
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    collection = collector.collect()
    
    assert len(collection.resources) == 1
    assert "MyBucket" in collection.resources
    bucket = collection.resources["MyBucket"]
    assert bucket.resource_type == "AWS::S3::Bucket"
    assert bucket.properties["BucketName"] == "my-test-bucket"


def test_json_template_parsing(tmp_path):
    template_file = tmp_path / "template.json"
    template_file.write_text("""{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "my-json-bucket"
      }
    }
  }
}""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    collection = collector.collect()
    
    assert len(collection.resources) == 1
    bucket = collection.resources["MyBucket"]
    assert bucket.resource_type == "AWS::S3::Bucket"
    assert bucket.properties["BucketName"] == "my-json-bucket"


def test_resources_section_extraction(tmp_path):
    template_file = tmp_path / "template.yaml"
    template_file.write_text("""
AWSTemplateFormatVersion: '2010-09-09'
Description: Test template
Parameters:
  BucketParam:
    Type: String
Resources:
  Bucket1:
    Type: AWS::S3::Bucket
  Bucket2:
    Type: AWS::S3::Bucket
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    collection = collector.collect()
    
    assert len(collection.resources) == 2
    assert "Bucket1" in collection.resources
    assert "Bucket2" in collection.resources


def test_inline_iam_policies_extracted_as_separate_resources(tmp_path):
    template_file = tmp_path / "template.yaml"
    template_file.write_text("""
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
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: InlinePolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: '*'
                Resource: '*'
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    collection = collector.collect()
    
    assert "MyRole" in collection.resources
    role = collection.resources["MyRole"]
    assert role.resource_type == "AWS::IAM::Role"
    
    policy_resources = [r for r in collection.resources.values() if r.resource_type == "AWS::IAM::Policy"]
    assert len(policy_resources) == 1
    
    policy = policy_resources[0]
    assert policy.properties["PolicyName"] == "InlinePolicy"
    assert policy.properties["PolicyDocument"]["Statement"][0]["Action"] == "*"


def test_s3_bucket_policies_extracted_as_separate_resources(tmp_path):
    template_file = tmp_path / "template.yaml"
    template_file.write_text("""
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
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
            Resource: 'arn:aws:s3:::test-bucket/*'
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    collection = collector.collect()
    
    assert "MyBucket" in collection.resources
    assert "MyBucketPolicy" in collection.resources
    
    policy_resources = [r for r in collection.resources.values() if r.resource_type == "AWS::IAM::Policy"]
    assert len(policy_resources) == 1
    
    policy = policy_resources[0]
    assert "PolicyDocument" in policy.properties
    assert policy.properties["PolicyDocument"]["Statement"][0]["Principal"] == "*"


def test_handles_file_not_found_error():
    collector = ResourceFileCloudFormationCollector("/nonexistent/template.yaml")
    
    with pytest.raises(FileNotFoundError):
        collector.collect()


def test_handles_invalid_yaml(tmp_path):
    template_file = tmp_path / "invalid.yaml"
    template_file.write_text("""
This is not: [valid yaml: content
  - with: broken
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    
    with pytest.raises(Exception):
        collector.collect()


def test_handles_invalid_json(tmp_path):
    template_file = tmp_path / "invalid.json"
    template_file.write_text("""{
  "broken": "json,
  "missing": "closing brace"
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    
    with pytest.raises(Exception):
        collector.collect()


def test_handles_templates_with_no_resources_section(tmp_path):
    template_file = tmp_path / "no-resources.yaml"
    template_file.write_text("""
AWSTemplateFormatVersion: '2010-09-09'
Description: Template without resources
Parameters:
  Param1:
    Type: String
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    collection = collector.collect()
    
    assert len(collection.resources) == 0


def test_handles_cloudformation_intrinsic_functions(tmp_path):
    template_file = tmp_path / "intrinsics.yaml"
    template_file.write_text("""
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${AWS::StackName}-bucket'
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Join ['-', ['test', !Ref MyBucket]]
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
""")
    
    collector = ResourceFileCloudFormationCollector(str(template_file))
    collection = collector.collect()
    
    assert len(collection.resources) == 2
    assert "MyBucket" in collection.resources
    assert "MyRole" in collection.resources


def test_backward_compatibility_with_existing_examples():
    collector = ResourceFileCloudFormationCollector("examples/cloudformation/vulnerable_stack.yaml")
    
    collection = collector.collect()
    
    assert len(collection.resources) > 0
    resource_types = {r.resource_type for r in collection.resources.values()}
    assert "AWS::IAM::Role" in resource_types or "AWS::S3::Bucket" in resource_types or "AWS::EC2::SecurityGroup" in resource_types
