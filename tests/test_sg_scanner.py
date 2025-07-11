import pytest
from unittest.mock import MagicMock, patch

from aws_scanner.scanners.sg_scanner import extract_open_ports_from_group, find_open_security_groups

def test_extract_open_ports_with_open_cidr_and_dangerous_port():
    sg = {
        "GroupId": "sg-123",
        "GroupName": "test-sg",
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }
    findings = extract_open_ports_from_group(sg)
    assert findings == [{
        "group_id": "sg-123",
        "group_name": "test-sg",
        "from_port": 22,
        "to_port": 22,
        "cidr": "0.0.0.0/0",
        "protocol": "tcp",
        "is_ipv6": False
    }]

def test_extract_open_ports_with_open_ipv6_and_dangerous_port():
    sg = {
        "GroupId": "sg-124",
        "GroupName": "test-sg-ipv6",
        "IpPermissions": [
            {
                "FromPort": 3389,
                "ToPort": 3389,
                "IpProtocol": "tcp",
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
            }
        ]
    }
    findings = extract_open_ports_from_group(sg)
    assert findings == [{
        "group_id": "sg-124",
        "group_name": "test-sg-ipv6",
        "from_port": 3389,
        "to_port": 3389,
        "cidr": "::/0",
        "protocol": "tcp",
        "is_ipv6": True
    }]

def test_extract_open_ports_all_ports_open():
    sg = {
        "GroupId": "sg-125",
        "GroupName": "all-ports",
        "IpPermissions": [
            {
                "FromPort": 0,
                "ToPort": 65535,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }
    findings = extract_open_ports_from_group(sg)
    assert {
        "group_id": "sg-125",
        "group_name": "all-ports",
        "from_port": 0,
        "to_port": 65535,
        "cidr": "0.0.0.0/0",
        "protocol": "tcp",
        "is_ipv6": False,
        "all_ports": True
    } in findings
    assert {
        "group_id": "sg-125",
        "group_name": "all-ports",
        "from_port": None,
        "to_port": None,
        "cidr": "0.0.0.0/0",
        "protocol": "-1",
        "is_ipv6": False,
        "all_ports": True
    } in findings
    assert len(findings) == 2

def test_extract_open_ports_no_dangerous_ports():
    sg = {
        "GroupId": "sg-456",
        "GroupName": "no-danger",
        "IpPermissions": [
            {
                "FromPort": 1234,
                "ToPort": 1234,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 80,
                "ToPort": 80,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
            }
        ]
    }
    findings = extract_open_ports_from_group(sg)
    assert findings == []

def test_extract_open_ports_multiple_permissions():
    sg = {
        "GroupId": "sg-789",
        "GroupName": "multi-sg",
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 3389,
                "ToPort": 3389,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 8080,
                "ToPort": 8080,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }
    findings = extract_open_ports_from_group(sg)
    assert {
        "group_id": "sg-789",
        "group_name": "multi-sg",
        "from_port": 22,
        "to_port": 22,
        "cidr": "0.0.0.0/0",
        "protocol": "tcp",
        "is_ipv6": False
    } in findings
    assert {
        "group_id": "sg-789",
        "group_name": "multi-sg",
        "from_port": 3389,
        "to_port": 3389,
        "cidr": "0.0.0.0/0",
        "protocol": "tcp",
        "is_ipv6": False
    } in findings
    assert len(findings) == 2

def test_extract_open_ports_missing_ports():
    sg = {
        "GroupId": "sg-000",
        "GroupName": "missing-ports",
        "IpPermissions": [
            {
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }
    findings = extract_open_ports_from_group(sg)
    expected = [
        {
            "group_id": "sg-000",
            "group_name": "missing-ports",
            "from_port": None,
            "to_port": 22,
            "cidr": "0.0.0.0/0",
            "protocol": "tcp",
            "is_ipv6": False,
            "all_ports": True
        },
        {
            "group_id": "sg-000",
            "group_name": "missing-ports",
            "from_port": 22,
            "to_port": None,
            "cidr": "0.0.0.0/0",
            "protocol": "tcp",
            "is_ipv6": False,
            "all_ports": True
        },
        {
            "group_id": "sg-000",
            "group_name": "missing-ports",
            "from_port": None,
            "to_port": None,
            "cidr": "0.0.0.0/0",
            "protocol": "tcp",
            "is_ipv6": False,
            "all_ports": True
        }
    ]
    assert findings == expected

def test_extract_open_ports_empty_ipranges():
    sg = {
        "GroupId": "sg-111",
        "GroupName": "empty-ipranges",
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": []
            },
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp"
                # IpRanges missing
            }
        ]
    }
    findings = extract_open_ports_from_group(sg)
    assert findings == []

def test_extract_open_ports_empty_security_group():
    sg = {}
    findings = extract_open_ports_from_group(sg)
    assert findings == []

    sg2 = {"GroupId": "sg-222"}
    findings2 = extract_open_ports_from_group(sg2)
    assert findings2 == []

def test_find_open_security_groups_success():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-999",
                "GroupName": "mock-sg",
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
    results = find_open_security_groups(ec2=mock_ec2)
    assert results == [{
        "group_id": "sg-999",
        "group_name": "mock-sg",
        "from_port": 22,
        "to_port": 22,
        "cidr": "0.0.0.0/0",
        "protocol": "tcp",
        "is_ipv6": False
    }]

def test_find_open_security_groups_client_error():
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.side_effect = Exception("Some AWS error")
    with patch("aws_scanner.scanners.sg_scanner.botocore.exceptions.ClientError", Exception):
        results = find_open_security_groups(ec2=mock_ec2)
        assert any("error" in r for r in results)
