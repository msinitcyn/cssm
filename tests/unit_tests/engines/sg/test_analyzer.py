from unittest.mock import patch, MagicMock
from aws_scanner.engines.sg.sg_data import SgData

def test_is_open_cidr():
    from aws_scanner.engines.sg.analyzer import is_open_cidr

    assert is_open_cidr("0.0.0.0/0") is True
    assert is_open_cidr("::/0") is True
    assert is_open_cidr("10.0.0.0/8") is False
    assert is_open_cidr("192.168.1.0/24") is False
    assert is_open_cidr("") is False
    assert is_open_cidr(None) is False


def test_is_all_ports():
    from aws_scanner.engines.sg.analyzer import is_all_ports

    assert is_all_ports(None, None, "tcp") is True
    assert is_all_ports(0, 65535, "tcp") is True
    assert is_all_ports(80, 80, "-1") is True
    assert is_all_ports(80, 443, "tcp") is False
    assert is_all_ports(22, None, "tcp") is True
    assert is_all_ports(None, 443, "tcp") is True


def test_check_management_ports_ssh():
    from aws_scanner.engines.sg.analyzer import check_management_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_MANAGEMENT_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_management_ports(rule, sg)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with(
            "sg-test",
            raw_data={"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "port_type": "management"}
        )


def test_check_management_ports_rdp():
    from aws_scanner.engines.sg.analyzer import check_management_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 3389,
        "ToPort": 3389,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_MANAGEMENT_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_management_ports(rule, sg)

        assert len(findings) == 1


def test_check_management_ports_ipv6():
    from aws_scanner.engines.sg.analyzer import check_management_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_MANAGEMENT_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_management_ports(rule, sg)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with(
            "sg-test",
            raw_data={"cidr": "::/0", "from_port": 22, "to_port": 22, "port_type": "management"}
        )


def test_check_management_ports_safe():
    from aws_scanner.engines.sg.analyzer import check_management_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
    }

    findings = check_management_ports(rule, sg)
    assert len(findings) == 0


def test_check_database_ports_mysql():
    from aws_scanner.engines.sg.analyzer import check_database_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 3306,
        "ToPort": 3306,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_DATABASE_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_database_ports(rule, sg)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with(
            "sg-test",
            raw_data={"cidr": "0.0.0.0/0", "from_port": 3306, "to_port": 3306, "port_type": "database"}
        )


def test_check_database_ports_postgresql():
    from aws_scanner.engines.sg.analyzer import check_database_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 5432,
        "ToPort": 5432,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_DATABASE_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_database_ports(rule, sg)

        assert len(findings) == 1


def test_check_database_ports_safe():
    from aws_scanner.engines.sg.analyzer import check_database_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 3306,
        "ToPort": 3306,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
    }

    findings = check_database_ports(rule, sg)
    assert len(findings) == 0


def test_check_all_ports_open_public_tcp():
    from aws_scanner.engines.sg.analyzer import check_all_ports_open_public

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 0,
        "ToPort": 65535,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_ALL_PORTS_OPEN_PUBLIC"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_all_ports_open_public(rule, sg)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with(
            "sg-test",
            raw_data={"cidr": "0.0.0.0/0", "from_port": 0, "to_port": 65535, "protocol": "tcp"}
        )


def test_check_all_ports_open_public_all_protocols():
    from aws_scanner.engines.sg.analyzer import check_all_ports_open_public

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_ALL_PORTS_OPEN_PUBLIC"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_all_ports_open_public(rule, sg)

        assert len(findings) == 1


def test_check_all_ports_open_public_safe():
    from aws_scanner.engines.sg.analyzer import check_all_ports_open_public

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 80,
        "ToPort": 80,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    findings = check_all_ports_open_public(rule, sg)
    assert len(findings) == 0


def test_check_cross_account_references_different_account():
    from aws_scanner.engines.sg.analyzer import check_cross_account_references

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "UserIdGroupPairs": [
            {"UserId": "987654321098", "GroupId": "sg-other"}
        ]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "CROSS_ACCOUNT_SG_REFERENCE"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_cross_account_references(rule, sg)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with(
            "sg-test",
            raw_data={"user_id": "987654321098", "group_id": "sg-other"}
        )


def test_check_cross_account_references_same_account():
    from aws_scanner.engines.sg.analyzer import check_cross_account_references

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "UserIdGroupPairs": [
            {"UserId": "123456789012", "GroupId": "sg-same-account"}
        ]
    }

    findings = check_cross_account_references(rule, sg)
    assert len(findings) == 0


def test_check_internal_all_ports_protocol_minus_one():
    from aws_scanner.engines.sg.analyzer import check_internal_all_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "IpProtocol": "-1",
        "UserIdGroupPairs": [{"GroupId": "sg-internal"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_ALL_PORTS_INTERNAL"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_internal_all_ports(rule, sg)

        assert len(findings) == 1


def test_check_internal_all_ports_with_public_cidr():
    from aws_scanner.engines.sg.analyzer import check_internal_all_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_rules=[], region="us-east-1")
    rule = {
        "FromPort": 0,
        "ToPort": 65535,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "UserIdGroupPairs": [{"GroupId": "sg-internal"}]
    }

    findings = check_internal_all_ports(rule, sg)
    assert len(findings) == 0


def test_analyze_sg_multiple_findings():
    from aws_scanner.engines.sg.analyzer import analyze_sg

    sg = SgData(
        group_id="sg-test",
        group_name="test",
        owner_id="123456789012",
        ingress_rules=[
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 3306,
                "ToPort": 3306,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 0,
                "ToPort": 65535,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ],
        region="us-east-1"
    )

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "vulnerability"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = analyze_sg(sg)

        assert len(findings) == 3


def test_analyze_sg_no_findings():
    from aws_scanner.engines.sg.analyzer import analyze_sg

    sg = SgData(
        group_id="sg-test",
        group_name="test",
        owner_id="123456789012",
        ingress_rules=[
            {
                "FromPort": 80,
                "ToPort": 80,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
            }
        ],
        region="us-east-1"
    )

    findings = analyze_sg(sg)
    assert len(findings) == 0