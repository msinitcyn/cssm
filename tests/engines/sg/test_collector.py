from unittest.mock import patch, MagicMock
import pytest

def test_collect_security_groups_without_regions():
    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-1",
                "GroupName": "test-sg-1",
                "OwnerId": "123456789012",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80}]
            },
            {
                "GroupId": "sg-2",
                "GroupName": "test-sg-2",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups()

        assert len(results) == 2
        assert results[0].group_id == "sg-1"
        assert results[0].group_name == "test-sg-1"
        assert results[0].owner_id == "123456789012"
        assert results[0].region is None
        assert results[1].group_id == "sg-2"
        assert results[1].group_name == "test-sg-2"
        assert results[1].region is None

        mock_wrapper.assert_called_once()
        mock_ec2.describe_security_groups.assert_called_once()


def test_collect_security_groups_with_regions():
    mock_sg_data_us_east = {
        "SecurityGroups": [
            {
                "GroupId": "sg-east-1",
                "GroupName": "east-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_sg_data_us_west = {
        "SecurityGroups": [
            {
                "GroupId": "sg-west-1",
                "GroupName": "west-sg",
                "OwnerId": "123456789012",
                "IpPermissions": [{"IpProtocol": "tcp"}]
            }
        ]
    }

    mock_regional_ec2_east = MagicMock()
    mock_regional_ec2_east.describe_security_groups.return_value = mock_sg_data_us_east

    mock_regional_ec2_west = MagicMock()
    mock_regional_ec2_west.describe_security_groups.return_value = mock_sg_data_us_west

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.side_effect = [
            MagicMock(),
            mock_regional_ec2_east,
            mock_regional_ec2_west
        ]

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups(regions=["us-east-1", "us-west-2"])

        assert len(results) == 2
        assert results[0].group_id == "sg-east-1"
        assert results[0].region == "us-east-1"
        assert results[1].group_id == "sg-west-1"
        assert results[1].region == "us-west-2"

        assert mock_wrapper.return_value.get_ec2.call_count == 3
        mock_regional_ec2_east.describe_security_groups.assert_called_once()
        mock_regional_ec2_west.describe_security_groups.assert_called_once()


def test_collect_security_groups_empty_response():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups()

        assert len(results) == 0
        mock_ec2.describe_security_groups.assert_called_once()


def test_collect_security_groups_missing_optional_fields():
    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-minimal"
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups()

        assert len(results) == 1
        assert results[0].group_id == "sg-minimal"
        assert results[0].group_name == ""
        assert results[0].owner_id == ""
        assert results[0].ingress_permissions == []


def test_collect_security_groups_region_exception():
    mock_regional_ec2_good = MagicMock()
    mock_regional_ec2_good.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-good",
                "GroupName": "good-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_regional_ec2_bad = MagicMock()
    mock_regional_ec2_bad.describe_security_groups.side_effect = Exception("Region error")

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.side_effect = [
            MagicMock(),
            mock_regional_ec2_good,
            mock_regional_ec2_bad
        ]

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups(regions=["us-east-1", "us-west-2"])

        assert len(results) == 1
        assert results[0].group_id == "sg-good"
        assert results[0].region == "us-east-1"


def test_collect_security_groups_no_security_groups_key():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {}

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups()

        assert len(results) == 0


def test_collect_security_groups_partial_region_failures():
    mock_sg_data_region1 = {
        "SecurityGroups": [
            {
                "GroupId": "sg-region1-1",
                "GroupName": "region1-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_sg_data_region3 = {
        "SecurityGroups": [
            {
                "GroupId": "sg-region3-1",
                "GroupName": "region3-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    mock_regional_ec2_1 = MagicMock()
    mock_regional_ec2_1.describe_security_groups.return_value = mock_sg_data_region1

    mock_regional_ec2_2 = MagicMock()
    mock_regional_ec2_2.describe_security_groups.side_effect = Exception("Access denied")

    mock_regional_ec2_3 = MagicMock()
    mock_regional_ec2_3.describe_security_groups.return_value = mock_sg_data_region3

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.side_effect = [
            MagicMock(),
            mock_regional_ec2_1,
            mock_regional_ec2_2,  # region2 fails
            mock_regional_ec2_3
        ]

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups(regions=["region1", "region2", "region3"])

        assert len(results) == 2
        assert results[0].group_id == "sg-region1-1"
        assert results[0].region == "region1"
        assert results[1].group_id == "sg-region3-1"
        assert results[1].region == "region3"


def test_collect_security_groups_all_regions_fail():
    mock_regional_ec2_1 = MagicMock()
    mock_regional_ec2_1.describe_security_groups.side_effect = Exception("Region 1 error")

    mock_regional_ec2_2 = MagicMock()
    mock_regional_ec2_2.describe_security_groups.side_effect = Exception("Region 2 error")

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.side_effect = [
            MagicMock(),
            mock_regional_ec2_1,
            mock_regional_ec2_2
        ]

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups(regions=["us-east-1", "us-west-2"])

        assert len(results) == 0


def test_collect_security_groups_empty_regions_list():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-default",
                "GroupName": "default-sg",
                "OwnerId": "123456789012",
                "IpPermissions": []
            }
        ]
    }

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups(regions=[])

        # Empty regions list should behave like regions=None
        assert len(results) == 1
        assert results[0].group_id == "sg-default"
        assert results[0].region is None


def test_collect_security_groups_none_values_in_response():
    mock_sg_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-with-nones",
                "GroupName": None,
                "OwnerId": None,
                "IpPermissions": None
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups()

        assert len(results) == 1
        assert results[0].group_id == "sg-with-nones"
        assert results[0].group_name == ""
        assert results[0].owner_id == ""
        assert results[0].ingress_permissions == []


def test_collect_security_groups_malformed_security_group():
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

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups

        with pytest.raises(KeyError):
            collect_security_groups()


def test_collect_security_groups_boto3_wrapper_initialization_failure():
    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.side_effect = Exception("AWS credentials not found")

        from aws_scanner.engines.sg.collector import collect_security_groups

        with pytest.raises(Exception, match="AWS credentials not found"):
            collect_security_groups()


def test_collect_security_groups_describe_call_failure_without_regions():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.side_effect = Exception("Access denied")

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups

        # Exception not caught when no regions specified
        with pytest.raises(Exception, match="Access denied"):
            collect_security_groups()


def test_collect_security_groups_complex_permissions():
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
                "IpPermissions": complex_permissions
            }
        ]
    }

    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = mock_sg_data

    with patch("aws_scanner.engines.sg.collector.Boto3Wrapper") as mock_wrapper:
        mock_wrapper.return_value.get_ec2.return_value = mock_ec2

        from aws_scanner.engines.sg.collector import collect_security_groups
        results = collect_security_groups()

        assert len(results) == 1
        assert results[0].group_id == "sg-complex"
        assert results[0].ingress_permissions == complex_permissions