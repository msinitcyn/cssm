import pytest
from aws_scanner.scanners.sg.analyzer import analyze_sg
from aws_scanner.scanners.sg.security_group_data import SecurityGroupData

class DummyVuln:
    def __init__(self, id):
        self.id = id
    def instantiate(self, group_id, raw_data=None):
        return {"vuln": self.id, "group_id": group_id, **(raw_data or {})}

# Patch VULNERABILITIES for test isolation
import aws_scanner.scanners.sg.analyzer as analyzer_mod
analyzer_mod.VULNERABILITIES = {
    "SG_OPEN_PORT": DummyVuln("SG_OPEN_PORT"),
    "CROSS_ACCOUNT_SG_REFERENCE": DummyVuln("CROSS_ACCOUNT_SG_REFERENCE"),
    "SG_ALL_PORTS_INTERNAL": DummyVuln("SG_ALL_PORTS_INTERNAL")
}

def make_sg(group_id, owner_id, ingress_permissions, group_name="test"):
    return SecurityGroupData(group_id=group_id, group_name=group_name, owner_id=owner_id, ingress_permissions=ingress_permissions)

def test_analyze_sg_open_ipv4():
    # Non-default group
    sg = make_sg("sg-1", "1111", [
        {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])
    findings = analyze_sg(sg)
    for f in findings:
        if f["vuln"] == "SG_OPEN_PORT" and f["cidr"] == "0.0.0.0/0":
            assert "is_default" not in f
    # Default group
    sg_default = make_sg("sg-1d", "1111", [
        {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ], group_name="default")
    findings_default = analyze_sg(sg_default)
    assert any(f["vuln"] == "SG_OPEN_PORT" and f["cidr"] == "0.0.0.0/0" and f.get("is_default") for f in findings_default)

def test_analyze_sg_open_ipv6():
    # Non-default group
    sg = make_sg("sg-2", "1111", [
        {"FromPort": 3389, "ToPort": 3389, "IpProtocol": "tcp", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    ])
    findings = analyze_sg(sg)
    for f in findings:
        if f["vuln"] == "SG_OPEN_PORT" and f["cidr"] == "::/0":
            assert "is_default" not in f
    # Default group
    sg_default = make_sg("sg-2d", "1111", [
        {"FromPort": 3389, "ToPort": 3389, "IpProtocol": "tcp", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    ], group_name="default")
    findings_default = analyze_sg(sg_default)
    assert any(f["vuln"] == "SG_OPEN_PORT" and f["cidr"] == "::/0" and f.get("is_default") for f in findings_default)

def test_analyze_sg_cross_account():
    # Non-default group
    sg = make_sg("sg-3", "1111", [
        {"UserIdGroupPairs": [{"UserId": "2222", "GroupId": "sg-ext"}]}
    ])
    findings = analyze_sg(sg)
    for f in findings:
        if f["vuln"] == "CROSS_ACCOUNT_SG_REFERENCE" and f["user_id"] == "2222":
            assert "is_default" not in f
    # Default group
    sg_default = make_sg("sg-3d", "1111", [
        {"UserIdGroupPairs": [{"UserId": "2222", "GroupId": "sg-ext"}]}
    ], group_name="default")
    findings_default = analyze_sg(sg_default)
    assert any(f["vuln"] == "CROSS_ACCOUNT_SG_REFERENCE" and f["user_id"] == "2222" and f.get("is_default") for f in findings_default)

def test_analyze_sg_no_findings():
    sg = make_sg("sg-4", "1111", [
        {"FromPort": 1234, "ToPort": 1234, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
    ])
    findings = analyze_sg(sg)
    assert findings == []

def test_analyze_sg_cross_account_same_owner():
    sg = make_sg("sg-5", "1111", [
        {"UserIdGroupPairs": [{"UserId": "1111", "GroupId": "sg-self"}]}
    ])
    findings = analyze_sg(sg)
    assert not any(f["vuln"] == "CROSS_ACCOUNT_SG_REFERENCE" for f in findings)

def test_analyze_sg_all_ports_internal():
    # Non-default group
    sg = make_sg("sg-6", "1111", [
        {"FromPort": 0, "ToPort": 65535, "IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
    ])
    findings = analyze_sg(sg)
    for f in findings:
        if f["vuln"] == "SG_ALL_PORTS_INTERNAL":
            assert "is_default" not in f
    # Default group
    sg_default = make_sg("sg-6d", "1111", [
        {"FromPort": 0, "ToPort": 65535, "IpProtocol": "-1", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
    ], group_name="default")
    findings_default = analyze_sg(sg_default)
    assert any(f["vuln"] == "SG_ALL_PORTS_INTERNAL" and f.get("is_default") for f in findings_default)

def test_analyze_sg_all_ports_public():
    sg = make_sg("sg-7", "1111", [
        {"FromPort": 0, "ToPort": 65535, "IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])
    findings = analyze_sg(sg)
    assert not any(f["vuln"] == "SG_ALL_PORTS_INTERNAL" for f in findings)

def test_analyze_sg_not_all_ports():
    sg = make_sg("sg-8", "1111", [
        {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
    ])
    findings = analyze_sg(sg)
    assert not any(f["vuln"] == "SG_ALL_PORTS_INTERNAL" for f in findings)
