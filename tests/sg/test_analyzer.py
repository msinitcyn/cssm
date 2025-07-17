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
    "CROSS_ACCOUNT_SG_REFERENCE": DummyVuln("CROSS_ACCOUNT_SG_REFERENCE")
}

def make_sg(group_id, owner_id, ingress_permissions):
    return SecurityGroupData(group_id=group_id, group_name="test", owner_id=owner_id, ingress_permissions=ingress_permissions)

def test_analyze_sg_open_ipv4():
    sg = make_sg("sg-1", "1111", [
        {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    ])
    findings = analyze_sg(sg)
    assert any(f["vuln"] == "SG_OPEN_PORT" and f["cidr"] == "0.0.0.0/0" for f in findings)

def test_analyze_sg_open_ipv6():
    sg = make_sg("sg-2", "1111", [
        {"FromPort": 3389, "ToPort": 3389, "IpProtocol": "tcp", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
    ])
    findings = analyze_sg(sg)
    assert any(f["vuln"] == "SG_OPEN_PORT" and f["cidr"] == "::/0" for f in findings)

def test_analyze_sg_cross_account():
    sg = make_sg("sg-3", "1111", [
        {"UserIdGroupPairs": [{"UserId": "2222", "GroupId": "sg-ext"}]}
    ])
    findings = analyze_sg(sg)
    assert any(f["vuln"] == "CROSS_ACCOUNT_SG_REFERENCE" and f["user_id"] == "2222" for f in findings)

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
