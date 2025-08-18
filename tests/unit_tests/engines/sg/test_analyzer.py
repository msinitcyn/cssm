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


def test_check_open_ipv4_dangerous_port():
    from aws_scanner.engines.sg.analyzer import check_open_ipv4

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_open_ipv4(rule, sg)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with(
            "sg-test",
            raw_data={"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22}
        )


def test_check_open_ipv4_all_ports():
    from aws_scanner.engines.sg.analyzer import check_open_ipv4

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 0,
        "ToPort": 65535,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_open_ipv4(rule, sg)

        assert len(findings) == 1


def test_check_open_ipv4_safe_port():
    from aws_scanner.engines.sg.analyzer import check_open_ipv4

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 8080,
        "ToPort": 8080,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    findings = check_open_ipv4(rule, sg)
    assert len(findings) == 0


def test_check_open_ipv4_private_cidr():
    from aws_scanner.engines.sg.analyzer import check_open_ipv4

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
    }

    findings = check_open_ipv4(rule, sg)
    assert len(findings) == 0


def test_check_open_ipv4_multiple_ranges():
    from aws_scanner.engines.sg.analyzer import check_open_ipv4

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [
            {"CidrIp": "0.0.0.0/0"},
            {"CidrIp": "10.0.0.0/8"},
            {"CidrIp": "0.0.0.0/0"}
        ]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_open_ipv4(rule, sg)

        assert len(findings) == 2  # Two open CIDR blocks


def test_check_open_ipv4_missing_ip_ranges():
    from aws_scanner.engines.sg.analyzer import check_open_ipv4

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp"
    }

    findings = check_open_ipv4(rule, sg)
    assert len(findings) == 0


def test_check_open_ipv6_dangerous_port():
    from aws_scanner.engines.sg.analyzer import check_open_ipv6

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 443,
        "ToPort": 443,
        "IpProtocol": "tcp",
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_OPEN_PORT"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_open_ipv6(rule, sg)

        assert len(findings) == 1
        mock_vuln.instantiate.assert_called_once_with(
            "sg-test",
            raw_data={"cidr": "::/0", "from_port": 443, "to_port": 443}
        )


def test_check_open_ipv6_safe_ipv6_range():
    from aws_scanner.engines.sg.analyzer import check_open_ipv6

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}]
    }

    findings = check_open_ipv6(rule, sg)
    assert len(findings) == 0


def test_check_cross_account_references_different_account():
    from aws_scanner.engines.sg.analyzer import check_cross_account_references

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
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

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "UserIdGroupPairs": [
            {"UserId": "123456789012", "GroupId": "sg-same-account"}
        ]
    }

    findings = check_cross_account_references(rule, sg)
    assert len(findings) == 0


def test_check_cross_account_references_no_user_id():
    from aws_scanner.engines.sg.analyzer import check_cross_account_references

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "UserIdGroupPairs": [
            {"GroupId": "sg-no-user-id"}
        ]
    }

    findings = check_cross_account_references(rule, sg)
    assert len(findings) == 0


def test_check_cross_account_references_multiple_pairs():
    from aws_scanner.engines.sg.analyzer import check_cross_account_references

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "UserIdGroupPairs": [
            {"UserId": "987654321098", "GroupId": "sg-other1"},
            {"UserId": "123456789012", "GroupId": "sg-same"},
            {"UserId": "111111111111", "GroupId": "sg-other2"}
        ]
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "CROSS_ACCOUNT_SG_REFERENCE"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_cross_account_references(rule, sg)

        assert len(findings) == 2


def test_check_internal_all_ports_protocol_minus_one():
    from aws_scanner.engines.sg.analyzer import check_internal_all_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
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

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 0,
        "ToPort": 65535,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "UserIdGroupPairs": [{"GroupId": "sg-internal"}]
    }

    findings = check_internal_all_ports(rule, sg)
    assert len(findings) == 0  # Has public CIDR, so not internal-only


def test_check_internal_all_ports_with_public_ipv6():
    from aws_scanner.engines.sg.analyzer import check_internal_all_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 0,
        "ToPort": 65535,
        "IpProtocol": "tcp",
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
    }

    findings = check_internal_all_ports(rule, sg)
    assert len(findings) == 0


def test_check_internal_all_ports_specific_ports():
    from aws_scanner.engines.sg.analyzer import check_internal_all_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": 80,
        "ToPort": 443,
        "IpProtocol": "tcp",
        "UserIdGroupPairs": [{"GroupId": "sg-internal"}]
    }

    findings = check_internal_all_ports(rule, sg)
    assert len(findings) == 0  # Not all ports


def test_check_internal_all_ports_missing_ranges():
    from aws_scanner.engines.sg.analyzer import check_internal_all_ports

    sg = SgData(group_id="sg-test", group_name="test", owner_id="123456789012", ingress_permissions=[], region="us-east-1")
    rule = {
        "FromPort": None,
        "ToPort": None,
        "IpProtocol": "tcp"
    }

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "SG_ALL_PORTS_INTERNAL"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = check_internal_all_ports(rule, sg)

        assert len(findings) == 1


def test_analyze_sg_multiple_findings():
    from aws_scanner.engines.sg.analyzer import analyze_sg

    sg = SgData(
        group_id="sg-test",
        group_name="test",
        owner_id="123456789012",
        ingress_permissions=[
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 443,
                "ToPort": 443,
                "IpProtocol": "tcp",
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
            },
            {
                "UserIdGroupPairs": [{"UserId": "987654321098", "GroupId": "sg-other"}]
            },
            {
                "IpProtocol": "-1",
                "UserIdGroupPairs": [{"GroupId": "sg-internal"}]
            }
        ],
        region="us-east-1"
    )

    with patch("aws_scanner.engines.sg.analyzer.VULNERABILITIES") as mock_vulns:
        mock_vuln = MagicMock()
        mock_vuln.instantiate.return_value = {"type": "vulnerability"}
        mock_vulns.__getitem__.return_value = mock_vuln

        findings = analyze_sg(sg)

        # Should find: open IPv4, open IPv6, cross-account reference, internal all ports (rule 3), internal all ports (rule 4)
        assert len(findings) == 5

def test_analyze_sg_no_findings():
    from aws_scanner.engines.sg.analyzer import analyze_sg

    sg = SgData(
        group_id="sg-test",
        group_name="test",
        owner_id="123456789012",
        ingress_permissions=[
            {
                "FromPort": 8080,
                "ToPort": 8080,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
            }
        ],
        region="us-east-1"
    )

    findings = analyze_sg(sg)
    assert len(findings) == 0


def test_analyze_sg_empty_permissions():
    from aws_scanner.engines.sg.analyzer import analyze_sg

    sg = SgData(
        group_id="sg-test",
        group_name="test",
        owner_id="123456789012",
        ingress_permissions=[],
        region="us-east-1"
    )

    findings = analyze_sg(sg)
    assert len(findings) == 0