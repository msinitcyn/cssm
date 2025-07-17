# aws_scanner/scanners/sg/sg_analyzer.py

from typing import List, Dict
from aws_scanner.scanners.sg.security_group_data import SecurityGroupData
from aws_scanner.core.vulnerabilities import VULNERABILITIES

DANGEROUS_PORTS = {22, 3389, 3306, 5432, 80, 443}

def is_open_cidr(cidr: str) -> bool:
    return cidr in {"0.0.0.0/0", "::/0"}

def is_all_ports(from_port, to_port, protocol) -> bool:
    return (
        from_port is None or
        to_port is None or
        (from_port == 0 and to_port == 65535) or
        protocol == "-1"
    )

def check_open_ipv4(rule, sg, findings):
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    protocol = rule.get("IpProtocol")
    for ip_range in rule.get("IpRanges", []):
        cidr = ip_range.get("CidrIp")
        if is_open_cidr(cidr) and (from_port in DANGEROUS_PORTS or is_all_ports(from_port, to_port, protocol)):
            findings.append(VULNERABILITIES["SG_OPEN_PORT"].instantiate(
                sg.group_id, raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port}
            ))

def check_open_ipv6(rule, sg, findings):
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    protocol = rule.get("IpProtocol")
    for ip_range in rule.get("Ipv6Ranges", []):
        cidr = ip_range.get("CidrIpv6")
        if is_open_cidr(cidr) and (from_port in DANGEROUS_PORTS or is_all_ports(from_port, to_port, protocol)):
            findings.append(VULNERABILITIES["SG_OPEN_PORT"].instantiate(
                sg.group_id, raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port}
            ))

def check_cross_account_references(rule, sg, findings):
    for pair in rule.get("UserIdGroupPairs", []):
        user_id = pair.get("UserId")
        group_id = pair.get("GroupId")
        if user_id and user_id != sg.owner_id:
            findings.append(VULNERABILITIES["CROSS_ACCOUNT_SG_REFERENCE"].instantiate(
                sg.group_id, raw_data={"user_id": user_id, "group_id": group_id}
            ))

def analyze_sg(sg: SecurityGroupData) -> List[Dict]:
    findings = []
    for rule in sg.ingress_permissions:
        check_open_ipv4(rule, sg, findings)
        check_open_ipv6(rule, sg, findings)
        check_cross_account_references(rule, sg, findings)
    return findings
