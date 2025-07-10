import pytest

from aws_scanner.scanners.sg_scanner import extract_open_ports_from_group

def test_extract_open_ports_with_open_cidr_and_dangerous_port():
    sg = {
        "GroupId": "sg-123",
        "GroupName": "test-sg",
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
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
        "cidr": "0.0.0.0/0"
    }]

def test_extract_open_ports_no_dangerous_ports():
    sg = {
        "GroupId": "sg-456",
        "GroupName": "no-danger",
        "IpPermissions": [
            {
                "FromPort": 1234,
                "ToPort": 1234,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 80,
                "ToPort": 80,
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
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 8080,
                "ToPort": 8080,
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
        "cidr": "0.0.0.0/0"
    } in findings
    assert {
        "group_id": "sg-789",
        "group_name": "multi-sg",
        "from_port": 3389,
        "to_port": 3389,
        "cidr": "0.0.0.0/0"
    } in findings
    assert len(findings) == 2

def test_extract_open_ports_missing_ports():
    sg = {
        "GroupId": "sg-000",
        "GroupName": "missing-ports",
        "IpPermissions": [
            {
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }
    findings = extract_open_ports_from_group(sg)
    assert findings == []

def test_extract_open_ports_empty_ipranges():
    sg = {
        "GroupId": "sg-111",
        "GroupName": "empty-ipranges",
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": []
            },
            {
                "FromPort": 22,
                "ToPort": 22
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