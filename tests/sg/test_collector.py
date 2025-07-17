from unittest.mock import MagicMock
from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.scanners.sg.collector import collect_security_groups
from aws_scanner.scanners.sg.security_group_data import SecurityGroupData

def test_collect_security_groups_no_regions():
    original_get_ec2 = Boto3Wrapper.get_ec2
    mock_ec2 = MagicMock()
    Boto3Wrapper.get_ec2 = MagicMock(return_value=mock_ec2)

    mock_response = {
        "SecurityGroups": [
            {
                "GroupId": "sg-123",
                "GroupName": "test-sg",
                "IpPermissions": []
            }
        ]
    }
    mock_ec2.describe_security_groups.return_value = mock_response

    result = collect_security_groups()
    assert len(result) == 1
    assert isinstance(result[0], SecurityGroupData)
    assert result[0].group_id == "sg-123"

    Boto3Wrapper.get_ec2 = original_get_ec2

def test_collect_security_groups_with_regions():
    original_get_ec2 = Boto3Wrapper.get_ec2
    mock_ec2 = MagicMock()
    Boto3Wrapper.get_ec2 = MagicMock(return_value=mock_ec2)

    mock_response = {
        "SecurityGroups": [
            {
                "GroupId": "sg-region",
                "GroupName": "region-sg",
                "IpPermissions": []
            }
        ]
    }
    mock_ec2.describe_security_groups.return_value = mock_response

    result = collect_security_groups(regions=["us-east-1"])
    assert len(result) == 1
    assert result[0].group_id == "sg-region"
    assert result[0].region == "us-east-1"

    Boto3Wrapper.get_ec2 = original_get_ec2

def test_collect_security_groups_region_error():
    original_get_ec2 = Boto3Wrapper.get_ec2
    mock_ec2 = MagicMock()
    Boto3Wrapper.get_ec2 = MagicMock(return_value=mock_ec2)

    mock_ec2.describe_security_groups.side_effect = Exception("Region error")

    result = collect_security_groups(regions=["bad-region"])
    assert len(result) == 0

    Boto3Wrapper.get_ec2 = original_get_ec2

def test_collect_security_groups_with_permissions():
    original_get_ec2 = Boto3Wrapper.get_ec2
    mock_ec2 = MagicMock()
    Boto3Wrapper.get_ec2 = MagicMock(return_value=mock_ec2)

    mock_response = {
        "SecurityGroups": [
            {
                "GroupId": "sg-perm",
                "GroupName": "perm-sg",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ]
            }
        ]
    }
    mock_ec2.describe_security_groups.return_value = mock_response

    result = collect_security_groups()
    assert len(result) == 1
    assert len(result[0].ingress_permissions) == 1
    assert result[0].ingress_permissions[0]["FromPort"] == 22

    Boto3Wrapper.get_ec2 = original_get_ec2