from unittest.mock import MagicMock
import botocore.exceptions
import pytest
from aws_scanner.engines.sg.resource_aws_security_group_collector import ResourceAwsSecurityGroupCollector
from aws_scanner.engines.common.resource_definition import ResourceCollection
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


def test_collect_returns_resource_collection():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-123",
                "GroupName": "test-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_ec2.return_value = mock_ec2

    collector = ResourceAwsSecurityGroupCollector(mock_wrapper, regions=["us-east-1"])
    result = collector.collect()

    assert isinstance(result, ResourceCollection)


def test_sg_becomes_resource_definition_with_correct_type():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-123",
                "GroupName": "test-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_ec2.return_value = mock_ec2

    collector = ResourceAwsSecurityGroupCollector(mock_wrapper, regions=["us-east-1"])
    result = collector.collect()

    assert len(result.resources) == 1
    resource = result.resources["sg-123"]
    assert resource.resource_type == "AWS::EC2::SecurityGroup"


def test_sg_properties_include_id_name_ingress():
    ingress_rules = [
        {
            "FromPort": 80,
            "ToPort": 80,
            "IpProtocol": "tcp",
            "CidrIp": "0.0.0.0/0"
        }
    ]

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-123",
                "GroupName": "test-sg",
                "OwnerId": "123456789012",
                "IpPermissions": ingress_rules
            }
        ]
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_ec2.return_value = mock_ec2

    collector = ResourceAwsSecurityGroupCollector(mock_wrapper, regions=["us-east-1"])
    result = collector.collect()

    resource = result.resources["sg-123"]
    assert resource.properties["GroupId"] == "sg-123"
    assert resource.properties["GroupName"] == "test-sg"
    assert resource.properties["SecurityGroupIngress"] == ingress_rules


def test_handles_regions_parameter():
    mock_ec2_us_east = MagicMock()
    mock_ec2_us_east.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-123",
                "GroupName": "us-east-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_ec2_us_west = MagicMock()
    mock_ec2_us_west.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-456",
                "GroupName": "us-west-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)

    def get_ec2_for_region(region=None):
        if region == "us-east-1":
            return mock_ec2_us_east
        elif region == "us-west-2":
            return mock_ec2_us_west
        return MagicMock()

    mock_wrapper.get_ec2.side_effect = get_ec2_for_region

    collector = ResourceAwsSecurityGroupCollector(mock_wrapper, regions=["us-east-1", "us-west-2"])
    result = collector.collect()

    assert len(result.resources) == 2
    assert "sg-123" in result.resources
    assert "sg-456" in result.resources


def test_handles_describe_security_groups_error():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
        "DescribeSecurityGroups"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_ec2.return_value = mock_ec2

    collector = ResourceAwsSecurityGroupCollector(mock_wrapper, regions=["us-east-1"])
    result = collector.collect()

    assert len(result.resources) == 0


def test_collects_from_multiple_regions():
    mock_ec2_1 = MagicMock()
    mock_ec2_1.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-region1",
                "GroupName": "sg1",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_ec2_2 = MagicMock()
    mock_ec2_2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-region2",
                "GroupName": "sg2",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)

    call_count = 0
    def get_ec2_for_call(region=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return mock_ec2_1
        else:
            return mock_ec2_2

    mock_wrapper.get_ec2.side_effect = get_ec2_for_call

    collector = ResourceAwsSecurityGroupCollector(mock_wrapper, regions=["us-east-1", "eu-west-1"])
    result = collector.collect()

    assert len(result.resources) == 2
    assert "sg-region1" in result.resources
    assert "sg-region2" in result.resources


def test_handles_partial_region_failure():
    mock_ec2_success = MagicMock()
    mock_ec2_success.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-success",
                "GroupName": "success-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_ec2_failure = MagicMock()
    mock_ec2_failure.describe_security_groups.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
        "DescribeSecurityGroups"
    )

    mock_wrapper = MagicMock(spec=Boto3Wrapper)

    call_count = 0
    def get_ec2_for_call(region=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return mock_ec2_success
        else:
            return mock_ec2_failure

    mock_wrapper.get_ec2.side_effect = get_ec2_for_call

    collector = ResourceAwsSecurityGroupCollector(mock_wrapper, regions=["us-east-1", "eu-west-1"])
    result = collector.collect()

    assert len(result.resources) == 1
    assert "sg-success" in result.resources


def test_sg_properties_include_owner_id():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-123",
                "GroupName": "test-sg",
                "OwnerId": "987654321098",
                "IpPermissions": []
            }
        ]
    }

    mock_wrapper = MagicMock(spec=Boto3Wrapper)
    mock_wrapper.get_ec2.return_value = mock_ec2

    collector = ResourceAwsSecurityGroupCollector(mock_wrapper, regions=["us-east-1"])
    result = collector.collect()

    resource = result.resources["sg-123"]
    assert resource.properties["OwnerId"] == "987654321098"
