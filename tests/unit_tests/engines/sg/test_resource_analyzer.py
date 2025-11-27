import pytest
from aws_scanner.engines.common.resource_definition import ResourceDefinition


def test_analyze_sg_from_resource_accepts_resource_definition():
    resource_def = ResourceDefinition(
        logical_id="WebServerSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-12345678",
            "GroupName": "web-server-sg",
            "SecurityGroupIngress": []
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    assert isinstance(findings, list)


def test_analyze_sg_from_resource_open_ssh():
    resource_def = ResourceDefinition(
        logical_id="OpenSSHSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-openssh",
            "GroupName": "open-ssh-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_OPEN_MANAGEMENT_PORT" in vulnerability_ids


def test_analyze_sg_from_resource_open_rdp():
    resource_def = ResourceDefinition(
        logical_id="OpenRDPSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-openrdp",
            "GroupName": "open-rdp-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_OPEN_MANAGEMENT_PORT" in vulnerability_ids


def test_analyze_sg_from_resource_open_database_port():
    resource_def = ResourceDefinition(
        logical_id="OpenDatabaseSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-openmysql",
            "GroupName": "open-mysql-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_OPEN_DATABASE_PORT" in vulnerability_ids


def test_analyze_sg_from_resource_all_ports_open():
    resource_def = ResourceDefinition(
        logical_id="AllPortsOpenSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-allopen",
            "GroupName": "all-ports-open-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 0,
                    "ToPort": 65535,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_ALL_PORTS_OPEN_PUBLIC" in vulnerability_ids


def test_analyze_sg_from_resource_all_protocols_open():
    resource_def = ResourceDefinition(
        logical_id="AllProtocolsOpenSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-allprotocols",
            "GroupName": "all-protocols-open-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "-1",
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_ALL_PORTS_OPEN_PUBLIC" in vulnerability_ids


def test_analyze_sg_from_resource_ipv6_open():
    resource_def = ResourceDefinition(
        logical_id="IPv6OpenSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-ipv6open",
            "GroupName": "ipv6-open-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIpv6": "::/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_OPEN_MANAGEMENT_PORT" in vulnerability_ids


def test_analyze_sg_from_resource_restricted_ssh():
    resource_def = ResourceDefinition(
        logical_id="RestrictedSSHSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-restrictedssh",
            "GroupName": "restricted-ssh-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "10.0.0.0/8"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_sg_from_resource_no_ingress_rules():
    resource_def = ResourceDefinition(
        logical_id="NoIngressSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-noingress",
            "GroupName": "no-ingress-sg",
            "SecurityGroupIngress": []
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    assert len(findings) == 0


def test_analyze_sg_from_resource_multiple_vulnerabilities():
    resource_def = ResourceDefinition(
        logical_id="MultiVulnSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-multivuln",
            "GroupName": "multi-vuln-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "0.0.0.0/0"
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_OPEN_MANAGEMENT_PORT" in vulnerability_ids
    assert "SG_OPEN_DATABASE_PORT" in vulnerability_ids
    assert len(findings) == 2


def test_analyze_sg_from_resource_cross_account_reference():
    resource_def = ResourceDefinition(
        logical_id="CrossAccountSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-crossaccount",
            "GroupName": "cross-account-sg",
            "OwnerId": "123456789012",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "SourceSecurityGroupId": "sg-other",
                    "SourceSecurityGroupOwnerId": "999999999999"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "CROSS_ACCOUNT_SG_REFERENCE" in vulnerability_ids


def test_analyze_sg_from_resource_all_ports_internal():
    resource_def = ResourceDefinition(
        logical_id="AllPortsInternalSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-allinternal",
            "GroupName": "all-ports-internal-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "-1",
                    "CidrIp": "10.0.0.0/8"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_ALL_PORTS_INTERNAL" in vulnerability_ids


def test_analyze_sg_from_resource_open_http_port():
    resource_def = ResourceDefinition(
        logical_id="OpenHTTPSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-openhttp",
            "GroupName": "open-http-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_OPEN_PORT" in vulnerability_ids


def test_analyze_sg_from_resource_mixed_ipv4_ipv6():
    resource_def = ResourceDefinition(
        logical_id="MixedIPSG",
        resource_type="AWS::EC2::SecurityGroup",
        properties={
            "GroupId": "sg-mixedip",
            "GroupName": "mixed-ip-sg",
            "SecurityGroupIngress": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "CidrIp": "10.0.0.0/8"
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "CidrIp": "0.0.0.0/0"
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "CidrIpv6": "::/0"
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "CidrIpv6": "2001:db8::/32"
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    )

    from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource

    findings = analyze_sg_from_resource(resource_def)

    vulnerability_ids = [f["id"] for f in findings]
    assert "SG_OPEN_MANAGEMENT_PORT" in vulnerability_ids
    assert "SG_OPEN_DATABASE_PORT" in vulnerability_ids

    management_findings = [f for f in findings if f["id"] == "SG_OPEN_MANAGEMENT_PORT"]
    assert len(management_findings) == 2
