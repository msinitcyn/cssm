import json
from unittest.mock import mock_open, patch


def test_collect_returns_resource_collection():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "vpc_id": "vpc-12345678",
        "owner_id": "123456789012",
        "ingress_rules": [
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["0.0.0.0/0"]
            }
        ],
        "egress_rules": []
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector
        from aws_scanner.engines.common.resource_definition import ResourceCollection

        collector = ResourceFileSgCollector("/path/to/sg.json")
        result = collector.collect()

        assert isinstance(result, ResourceCollection)


def test_security_group_becomes_resource_definition():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "vpc_id": "vpc-12345678",
        "owner_id": "123456789012",
        "ingress_rules": [
            {
                "protocol": "tcp",
                "from_port": 80,
                "to_port": 80,
                "cidr_blocks": ["0.0.0.0/0"]
            }
        ],
        "egress_rules": [
            {
                "protocol": "-1",
                "from_port": 0,
                "to_port": 0,
                "cidr_blocks": ["0.0.0.0/0"]
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector

        collector = ResourceFileSgCollector("/path/to/sg.json")
        result = collector.collect()

        assert len(result.resources) == 1
        sg = result.get_by_id("sg-12345678")
        assert sg is not None
        assert sg.resource_type == "AWS::EC2::SecurityGroup"


def test_security_group_properties():
    test_data = {
        "group_id": "sg-abcdef12",
        "group_name": "web-servers",
        "vpc_id": "vpc-98765432",
        "owner_id": "123456789012",
        "ingress_rules": [
            {
                "protocol": "tcp",
                "from_port": 443,
                "to_port": 443,
                "cidr_blocks": ["10.0.0.0/8"]
            },
            {
                "protocol": "tcp",
                "from_port": 80,
                "to_port": 80,
                "cidr_blocks": ["0.0.0.0/0"]
            }
        ],
        "egress_rules": [
            {
                "protocol": "-1",
                "from_port": 0,
                "to_port": 0,
                "cidr_blocks": ["0.0.0.0/0"]
            }
        ]
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector

        collector = ResourceFileSgCollector("/path/to/sg.json")
        result = collector.collect()

        sg = result.get_by_id("sg-abcdef12")
        assert sg.properties["GroupId"] == "sg-abcdef12"
        assert sg.properties["GroupName"] == "web-servers"
        assert sg.properties["VpcId"] == "vpc-98765432"
        assert len(sg.properties["SecurityGroupIngress"]) == 2
        assert len(sg.properties["SecurityGroupEgress"]) == 1


def test_retrieve_security_group_by_id():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "vpc_id": "vpc-12345678",
        "owner_id": "123456789012",
        "ingress_rules": [],
        "egress_rules": []
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector

        collector = ResourceFileSgCollector("/path/to/sg.json")
        result = collector.collect()

        sg = result.get_by_id("sg-12345678")
        assert sg is not None
        assert sg.logical_id == "sg-12345678"
        assert sg.resource_type == "AWS::EC2::SecurityGroup"


def test_multiple_security_groups():
    test_data = [
        {
            "group_id": "sg-first",
            "group_name": "first-sg",
            "vpc_id": "vpc-12345678",
            "owner_id": "123456789012",
            "ingress_rules": [],
            "egress_rules": []
        },
        {
            "group_id": "sg-second",
            "group_name": "second-sg",
            "vpc_id": "vpc-87654321",
            "owner_id": "123456789012",
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            ],
            "egress_rules": []
        }
    ]

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector

        collector = ResourceFileSgCollector("/path/to/sg.json")
        result = collector.collect()

        assert len(result.resources) == 2

        sg1 = result.get_by_id("sg-first")
        assert sg1 is not None
        assert sg1.properties["GroupName"] == "first-sg"

        sg2 = result.get_by_id("sg-second")
        assert sg2 is not None
        assert sg2.properties["GroupName"] == "second-sg"
        assert len(sg2.properties["SecurityGroupIngress"]) == 1


def test_security_group_with_missing_vpc():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "test-sg",
        "owner_id": "123456789012",
        "ingress_rules": [],
        "egress_rules": []
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector

        collector = ResourceFileSgCollector("/path/to/sg.json")
        result = collector.collect()

        sg = result.get_by_id("sg-12345678")
        assert sg.properties["GroupId"] == "sg-12345678"
        assert sg.properties.get("VpcId") is None


def test_empty_ingress_and_egress_rules():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "empty-sg",
        "vpc_id": "vpc-12345678",
        "owner_id": "123456789012",
        "ingress_rules": [],
        "egress_rules": []
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector

        collector = ResourceFileSgCollector("/path/to/sg.json")
        result = collector.collect()

        sg = result.get_by_id("sg-12345678")
        assert sg.properties["SecurityGroupIngress"] == []
        assert sg.properties["SecurityGroupEgress"] == []


def test_legacy_ingress_permissions_field():
    test_data = {
        "group_id": "sg-12345678",
        "group_name": "legacy-sg",
        "vpc_id": "vpc-12345678",
        "owner_id": "123456789012",
        "ingress_permissions": [
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["192.168.1.0/24"]
            }
        ],
        "egress_rules": []
    }

    mock_file = mock_open(read_data=json.dumps(test_data))

    with patch("builtins.open", mock_file):
        from aws_scanner.engines.sg.resource_file_sg_collector import ResourceFileSgCollector

        collector = ResourceFileSgCollector("/path/to/sg.json")
        result = collector.collect()

        sg = result.get_by_id("sg-12345678")
        assert len(sg.properties["SecurityGroupIngress"]) == 1
        assert sg.properties["SecurityGroupIngress"][0]["IpProtocol"] == "tcp"