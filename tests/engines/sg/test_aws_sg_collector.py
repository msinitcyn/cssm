from unittest.mock import MagicMock
import botocore.exceptions
from aws_scanner.engines.sg.aws_sg_collector import AwsSgCollector
from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.engines.sg.sg_data import SgData

def test_collect_without_regions():
    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-1",
                "GroupName": "test-sg-1",
                "OwnerId": "123456789012",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80}],
                "IpPermissionsEgress": []
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.return_value = mock_ec2

    collector = AwsSgCollector(mock_boto3)
    results = collector.collect()

    assert len(results) == 1
    assert isinstance(results[0], SgData)
    assert results[0].group_id == "sg-1"
    assert results[0].region is None
    mock_boto3.get_ec2.assert_called_once_with()
    mock_ec2.describe_security_groups.assert_called_once()

def test_collect_with_regions():
    mock_sg_data1 = {
        "SecurityGroups": [
            {
                "GroupId": "sg-east-1",
                "GroupName": "east-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }
    mock_sg_data2 = {
        "SecurityGroups": [
            {
                "GroupId": "sg-west-2",
                "GroupName": "west-sg",
                "OwnerId": "123456789012",
                "IpPermissions": [{"IpProtocol": "tcp"}]
            }
        ]
    }

    mock_ec2_east = MagicMock()
    mock_ec2_east.describe_security_groups.return_value = mock_sg_data1
    mock_ec2_west = MagicMock()
    mock_ec2_west.describe_security_groups.return_value = mock_sg_data2

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.side_effect = [mock_ec2_east, mock_ec2_west]

    collector = AwsSgCollector(mock_boto3, regions=["us-east-1", "us-west-2"])
    results = collector.collect()

    assert len(results) == 2
    assert results[0].group_id == "sg-east-1"
    assert results[0].region == "us-east-1"
    assert results[1].group_id == "sg-west-2"
    assert results[1].region == "us-west-2"
    assert mock_boto3.get_ec2.call_count == 2

def test_collect_empty_response():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.return_value = mock_ec2

    collector = AwsSgCollector(mock_boto3)
    results = collector.collect()

    assert len(results) == 0

def test_collect_missing_optional_fields():
    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-minimal"
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.return_value = mock_ec2

    collector = AwsSgCollector(mock_boto3)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].group_id == "sg-minimal"
    assert results[0].group_name == ""
    assert results[0].owner_id == ""
    assert results[0].ingress_permissions == []

def test_collect_region_exception():
    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-good",
                "GroupName": "good-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_ec2_good = MagicMock()
    mock_ec2_good.describe_security_groups.return_value = mock_sg_data
    mock_ec2_bad = MagicMock()
    mock_ec2_bad.describe_security_groups.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnauthorizedOperation"}}, "DescribeSecurityGroups")

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.side_effect = [mock_ec2_good, mock_ec2_bad]

    collector = AwsSgCollector(mock_boto3, regions=["us-east-1", "us-west-2"])
    results = collector.collect()

    assert len(results) == 1
    assert results[0].group_id == "sg-good"

def test_collect_no_security_groups_key():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {}

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.return_value = mock_ec2

    collector = AwsSgCollector(mock_boto3)
    results = collector.collect()

    assert len(results) == 0

def test_collect_partial_region_failures():
    mock_sg_data1 = {
        "SecurityGroups": [
            {
                "GroupId": "sg-region1",
                "GroupName": "region1-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }
    mock_sg_data3 = {
        "SecurityGroups": [
            {
                "GroupId": "sg-region3",
                "GroupName": "region3-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_ec2_1 = MagicMock()
    mock_ec2_1.describe_security_groups.return_value = mock_sg_data1
    mock_ec2_2 = MagicMock()
    mock_ec2_2.describe_security_groups.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied"}}, "DescribeSecurityGroups")
    mock_ec2_3 = MagicMock()
    mock_ec2_3.describe_security_groups.return_value = mock_sg_data3

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.side_effect = [mock_ec2_1, mock_ec2_2, mock_ec2_3]

    collector = AwsSgCollector(mock_boto3, regions=["region1", "region2", "region3"])
    results = collector.collect()

    assert len(results) == 2
    assert results[0].group_id == "sg-region1"
    assert results[1].group_id == "sg-region3"

def test_collect_all_regions_fail():
    mock_ec2_1 = MagicMock()
    mock_ec2_1.describe_security_groups.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnauthorizedOperation"}}, "DescribeSecurityGroups")
    mock_ec2_2 = MagicMock()
    mock_ec2_2.describe_security_groups.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDenied"}}, "DescribeSecurityGroups")

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.side_effect = [mock_ec2_1, mock_ec2_2]

    collector = AwsSgCollector(mock_boto3, regions=["us-east-1", "us-west-2"])
    results = collector.collect()

    assert len(results) == 0

def test_collect_empty_regions_list():
    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-default",
                "GroupName": "default-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.return_value = mock_ec2

    collector = AwsSgCollector(mock_boto3, regions=[])
    results = collector.collect()

    assert len(results) == 1
    assert results[0].group_id == "sg-default"
    assert results[0].region is None

def test_collect_none_values_in_response():
    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-with-nones",
                "GroupName": None,
                "OwnerId": None,
                "IpPermissions": None,
                "IpPermissionsEgress": None
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.return_value = mock_ec2

    collector = AwsSgCollector(mock_boto3)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].group_id == "sg-with-nones"
    assert results[0].group_name == ""
    assert results[0].owner_id == ""
    assert results[0].ingress_permissions == []

def test_collect_malformed_security_group():
    mock_sg_data = {
        "SecurityGroups": [
            {
                # Missing required GroupId
            },
            {
                "GroupId": "sg-valid",
                "GroupName": "valid-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.return_value = mock_ec2

    collector = AwsSgCollector(mock_boto3)
    results = collector.collect()
    assert len(results) == 1
    assert results[0].group_id == "sg-valid"

def test_collect_complex_permissions():
    complex_permissions = [
        {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        },
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "UserIdGroupPairs": [{"GroupId": "sg-other"}]
        }
    ]

    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-complex",
                "GroupName": "complex-sg",
                "OwnerId": "123456789012",
                "IpPermissions": complex_permissions,
                "IpPermissionsEgress": complex_permissions
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    mock_boto3 = MagicMock(spec=Boto3Wrapper)
    mock_boto3.get_ec2.return_value = mock_ec2

    collector = AwsSgCollector(mock_boto3)
    results = collector.collect()

    assert len(results) == 1
    assert results[0].ingress_permissions == complex_permissions