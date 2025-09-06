from typing import Dict, Any, List
from aws_scanner.engines.sg.sg_data import SgData
from aws_scanner.core.vulnerabilities import VULNERABILITIES

MANAGEMENT_PORTS = {22, 3389}
DATABASE_PORTS = {3306, 5432, 1433, 5984, 6379, 27017}
DANGEROUS_PORTS = MANAGEMENT_PORTS | DATABASE_PORTS | {80, 443}

def is_open_cidr(cidr: str) -> bool:
    return cidr in {"0.0.0.0/0", "::/0"}

def is_all_ports(from_port, to_port, protocol) -> bool:
    return (
        from_port is None or
        to_port is None or
        (from_port == 0 and to_port == 65535) or
        protocol == "-1"
    )

def check_management_ports(rule: Dict[str, Any], sg: SgData) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if from_port in MANAGEMENT_PORTS or to_port in MANAGEMENT_PORTS:
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if is_open_cidr(cidr):
                findings.append(
                    VULNERABILITIES["SG_OPEN_MANAGEMENT_PORT"].instantiate(
                        sg.group_id,
                        raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port, "port_type": "management"}
                    )
                )

        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6")
            if is_open_cidr(cidr):
                findings.append(
                    VULNERABILITIES["SG_OPEN_MANAGEMENT_PORT"].instantiate(
                        sg.group_id,
                        raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port, "port_type": "management"}
                    )
                )

    return findings

def check_database_ports(rule: Dict[str, Any], sg: SgData) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if from_port in DATABASE_PORTS or to_port in DATABASE_PORTS:
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if is_open_cidr(cidr):
                findings.append(
                    VULNERABILITIES["SG_OPEN_DATABASE_PORT"].instantiate(
                        sg.group_id,
                        raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port, "port_type": "database"}
                    )
                )

        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6")
            if is_open_cidr(cidr):
                findings.append(
                    VULNERABILITIES["SG_OPEN_DATABASE_PORT"].instantiate(
                        sg.group_id,
                        raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port, "port_type": "database"}
                    )
                )

    return findings

def check_all_ports_open_public(rule: Dict[str, Any], sg: SgData) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    protocol = rule.get("IpProtocol")

    if is_all_ports(from_port, to_port, protocol):
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if is_open_cidr(cidr):
                findings.append(
                    VULNERABILITIES["SG_ALL_PORTS_OPEN_PUBLIC"].instantiate(
                        sg.group_id,
                        raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port, "protocol": protocol}
                    )
                )

        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6")
            if is_open_cidr(cidr):
                findings.append(
                    VULNERABILITIES["SG_ALL_PORTS_OPEN_PUBLIC"].instantiate(
                        sg.group_id,
                        raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port, "protocol": protocol}
                    )
                )

    return findings

def check_open_dangerous_ports_general(rule: Dict[str, Any], sg: SgData) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    protocol = rule.get("IpProtocol")

    if (from_port in DANGEROUS_PORTS or to_port in DANGEROUS_PORTS) and \
       not (from_port in MANAGEMENT_PORTS or to_port in MANAGEMENT_PORTS) and \
       not (from_port in DATABASE_PORTS or to_port in DATABASE_PORTS) and \
       not is_all_ports(from_port, to_port, protocol):

        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if is_open_cidr(cidr):
                findings.append(
                    VULNERABILITIES["SG_OPEN_PORT"].instantiate(
                        sg.group_id,
                        raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port}
                    )
                )

        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6")
            if is_open_cidr(cidr):
                findings.append(
                    VULNERABILITIES["SG_OPEN_PORT"].instantiate(
                        sg.group_id,
                        raw_data={"cidr": cidr, "from_port": from_port, "to_port": to_port}
                    )
                )

    return findings

def check_cross_account_references(rule: Dict[str, Any], sg: SgData) -> List[Dict[str, Any]]:
    findings = []
    for pair in rule.get("UserIdGroupPairs", []):
        user_id = pair.get("UserId")
        group_id = pair.get("GroupId")
        if user_id and user_id != sg.owner_id:
            findings.append(
                VULNERABILITIES["CROSS_ACCOUNT_SG_REFERENCE"].instantiate(
                    sg.group_id,
                    raw_data={"user_id": user_id, "group_id": group_id}
                )
            )
    return findings

def check_internal_all_ports(rule: Dict[str, Any], sg: SgData) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    protocol = rule.get("IpProtocol")

    if is_all_ports(from_port, to_port, protocol):
        has_public_cidr = False

        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if is_open_cidr(cidr):
                has_public_cidr = True

        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6")
            if is_open_cidr(cidr):
                has_public_cidr = True

        if not has_public_cidr:
            findings.append(
                VULNERABILITIES["SG_ALL_PORTS_INTERNAL"].instantiate(
                    sg.group_id,
                    raw_data={"from_port": from_port, "to_port": to_port, "protocol": protocol}
                )
            )
    return findings

def analyze_sg(sg: SgData) -> List[Dict[str, Any]]:
    findings = []
    for rule in sg.ingress_rules:
        findings.extend(check_all_ports_open_public(rule, sg))
        findings.extend(check_database_ports(rule, sg))
        findings.extend(check_management_ports(rule, sg))
        findings.extend(check_open_dangerous_ports_general(rule, sg))
        findings.extend(check_cross_account_references(rule, sg))
        findings.extend(check_internal_all_ports(rule, sg))
    return findings