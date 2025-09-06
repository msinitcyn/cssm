import json
from unittest.mock import patch, mock_open
import pytest
from aws_scanner.engines.sg.file_sg_collector import FileSgCollector

def test_collect_single_sg():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012",
        "region": "us-east-1",
        "ingress_rules": [
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"]
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        sg = results[0]
        assert sg.group_id == "sg-12345678"
        assert sg.group_name == "test-sg"
        assert sg.owner_id == "123456789012"
        assert sg.region == "us-east-1"
        assert len(sg.ingress_rules) == 1
        assert sg.ingress_rules[0]["IpProtocol"] == "tcp"
        assert sg.ingress_rules[0]["FromPort"] == 22
        assert sg.ingress_rules[0]["ToPort"] == 22
        assert sg.ingress_rules[0]["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]

def test_collect_dict_format():
    test_data = {
        "sg1": {
            "group_id": "sg-11111111",
            "group_name": "sg1",
            "owner_id": "123456789012",
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 80,
                    "to_port": 80,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            ]
        },
        "sg2": {
            "group_id": "sg-22222222",
            "group_name": "sg2",
            "owner_id": "123456789012",
            "ingress_rules": []
        }
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sgs.json")
        results = collector.collect()

        assert len(results) == 2
        assert results[0].group_id == "sg-11111111"
        assert results[1].group_id == "sg-22222222"
        assert len(results[0].ingress_rules) == 1
        assert len(results[1].ingress_rules) == 0

def test_collect_list_format():
    test_data = [
        {
            "group_id": "sg-aaaaaaa",
            "group_name": "first-sg",
            "owner_id": "123456789012",
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 3389,
                    "to_port": 3389,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            ]
        },
        {
            "group_id": "sg-bbbbbbb",
            "group_name": "second-sg",
            "owner_id": "123456789012",
            "ingress_rules": []
        }
    ]

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sgs.json")
        results = collector.collect()

        assert len(results) == 2
        assert results[0].group_id == "sg-aaaaaaa"
        assert results[1].group_id == "sg-bbbbbbb"

def test_normalize_rule_aws_format():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012",
        "ingress_rules": [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                "Description": "HTTPS from VPC"
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        rule = results[0].ingress_rules[0]
        assert rule["IpProtocol"] == "tcp"
        assert rule["FromPort"] == 443
        assert rule["ToPort"] == 443
        assert rule["IpRanges"] == [{"CidrIp": "10.0.0.0/8"}]
        assert rule["Description"] == "HTTPS from VPC"

def test_normalize_rule_ipv6():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012",
        "ingress_rules": [
            {
                "protocol": "tcp",
                "from_port": 80,
                "to_port": 80,
                "ipv6_cidr_blocks": ["::/0"]
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        rule = results[0].ingress_rules[0]
        assert rule["IpProtocol"] == "tcp"
        assert rule["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]

def test_normalize_rule_source_security_group():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012",
        "ingress_rules": [
            {
                "protocol": "tcp",
                "from_port": 3306,
                "to_port": 3306,
                "source_security_group_id": "sg-87654321"
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        rule = results[0].ingress_rules[0]
        assert rule["UserIdGroupPairs"] == [{"GroupId": "sg-87654321"}]

def test_normalize_rule_user_id_group_pairs():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012",
        "ingress_rules": [
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "UserIdGroupPairs": [
                    {"GroupId": "sg-other", "UserId": "987654321098"}
                ]
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        rule = results[0].ingress_rules[0]
        assert rule["UserIdGroupPairs"] == [{"GroupId": "sg-other", "UserId": "987654321098"}]

def test_normalize_rule_protocol_minus_one():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012",
        "ingress_rules": [
            {
                "protocol": "-1",
                "cidr_blocks": ["10.0.0.0/8"]
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        rule = results[0].ingress_rules[0]
        assert rule["IpProtocol"] == "-1"
        assert "FromPort" not in rule
        assert "ToPort" not in rule

def test_fallback_group_id():
    test_data = {
        "name": "test-sg-no-id",
        "owner_id": "123456789012",
        "ingress_rules": []
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].group_id == "test-sg-no-id"

def test_fallback_group_id_unknown():
    test_data = {
        "owner_id": "123456789012",
        "ingress_rules": []
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        assert results[0].group_id == "sg-unknown"

def test_list_format_fallback_ids():
    test_data = [
        {"owner_id": "123456789012", "ingress_rules": []},
        {"name": "second-sg", "owner_id": "123456789012", "ingress_rules": []}
    ]

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sgs.json")
        results = collector.collect()

        assert len(results) == 2
        assert results[0].group_id == "sg-0"
        assert results[1].group_id == "second-sg"

def test_empty_ingress_rules():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012"
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        assert len(results[0].ingress_rules) == 0

def test_legacy_field_ingress_permissions():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012",
        "ingress_permissions": [
            {
                "protocol": "tcp",
                "from_port": 80,
                "to_port": 80,
                "cidr_blocks": ["0.0.0.0/0"]
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/sg.json")
        results = collector.collect()

        assert len(results) == 1
        assert len(results[0].ingress_rules) == 1

def test_invalid_json():
    mock_file = mock_open(read_data="invalid json")

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/invalid.json")

        with pytest.raises(json.JSONDecodeError):
            collector.collect()

def test_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
        collector = FileSgCollector("/nonexistent/path.json")

        with pytest.raises(FileNotFoundError):
            collector.collect()

def test_empty_dict():
    mock_file = mock_open(read_data="{}")

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/empty.json")
        results = collector.collect()

        assert len(results) == 0

def test_empty_list():
    mock_file = mock_open(read_data="[]")

    with patch("builtins.open", mock_file):
        collector = FileSgCollector("/path/to/empty.json")
        results = collector.collect()

        assert len(results) == 0