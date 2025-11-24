from typing import Dict, Any, List
from aws_scanner.engines.common.resource_definition import ResourceDefinition
from aws_scanner.core.vulnerabilities import VULNERABILITIES


MANAGEMENT_PORTS = {22, 3389}
DATABASE_PORTS = {3306, 5432, 1433, 5984, 6379, 27017}
DANGEROUS_PORTS = MANAGEMENT_PORTS | DATABASE_PORTS | {80, 443}


def _is_open_cidr(cidr: str) -> bool:
    return cidr in {"0.0.0.0/0", "::/0"}


def _is_all_ports(from_port, to_port, protocol) -> bool:
    return (
        from_port is None or
        to_port is None or
        (from_port == 0 and to_port == 65535) or
        protocol == "-1"
    )


def analyze_sg_from_resource(resource_def: ResourceDefinition) -> List[Dict[str, Any]]:
    findings = []
    props = resource_def.properties

    ingress_rules = props.get("SecurityGroupIngress", [])
    owner_id = props.get("OwnerId")

    for rule in ingress_rules:
        findings.extend(_check_all_ports_open_public(rule, resource_def.logical_id))
        findings.extend(_check_database_ports(rule, resource_def.logical_id))
        findings.extend(_check_management_ports(rule, resource_def.logical_id))
        findings.extend(_check_open_dangerous_ports_general(rule, resource_def.logical_id))
        findings.extend(_check_cross_account_references(rule, resource_def.logical_id, owner_id))
        findings.extend(_check_internal_all_ports(rule, resource_def.logical_id))

    return findings


def _check_management_ports(rule: Dict[str, Any], logical_id: str) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if from_port in MANAGEMENT_PORTS or to_port in MANAGEMENT_PORTS:
        cidr_ip = rule.get("CidrIp")
        if cidr_ip and _is_open_cidr(cidr_ip):
            findings.append(
                VULNERABILITIES["SG_OPEN_MANAGEMENT_PORT"].instantiate(
                    logical_id,
                    raw_data={"cidr": cidr_ip, "from_port": from_port, "to_port": to_port, "port_type": "management"}
                )
            )

        cidr_ipv6 = rule.get("CidrIpv6")
        if cidr_ipv6 and _is_open_cidr(cidr_ipv6):
            findings.append(
                VULNERABILITIES["SG_OPEN_MANAGEMENT_PORT"].instantiate(
                    logical_id,
                    raw_data={"cidr": cidr_ipv6, "from_port": from_port, "to_port": to_port, "port_type": "management"}
                )
            )

    return findings


def _check_database_ports(rule: Dict[str, Any], logical_id: str) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if from_port in DATABASE_PORTS or to_port in DATABASE_PORTS:
        cidr_ip = rule.get("CidrIp")
        if cidr_ip and _is_open_cidr(cidr_ip):
            findings.append(
                VULNERABILITIES["SG_OPEN_DATABASE_PORT"].instantiate(
                    logical_id,
                    raw_data={"cidr": cidr_ip, "from_port": from_port, "to_port": to_port, "port_type": "database"}
                )
            )

        cidr_ipv6 = rule.get("CidrIpv6")
        if cidr_ipv6 and _is_open_cidr(cidr_ipv6):
            findings.append(
                VULNERABILITIES["SG_OPEN_DATABASE_PORT"].instantiate(
                    logical_id,
                    raw_data={"cidr": cidr_ipv6, "from_port": from_port, "to_port": to_port, "port_type": "database"}
                )
            )

    return findings


def _check_all_ports_open_public(rule: Dict[str, Any], logical_id: str) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    protocol = rule.get("IpProtocol")

    if _is_all_ports(from_port, to_port, protocol):
        cidr_ip = rule.get("CidrIp")
        if cidr_ip and _is_open_cidr(cidr_ip):
            findings.append(
                VULNERABILITIES["SG_ALL_PORTS_OPEN_PUBLIC"].instantiate(
                    logical_id,
                    raw_data={"cidr": cidr_ip, "from_port": from_port, "to_port": to_port, "protocol": protocol}
                )
            )

        cidr_ipv6 = rule.get("CidrIpv6")
        if cidr_ipv6 and _is_open_cidr(cidr_ipv6):
            findings.append(
                VULNERABILITIES["SG_ALL_PORTS_OPEN_PUBLIC"].instantiate(
                    logical_id,
                    raw_data={"cidr": cidr_ipv6, "from_port": from_port, "to_port": to_port, "protocol": protocol}
                )
            )

    return findings


def _check_open_dangerous_ports_general(rule: Dict[str, Any], logical_id: str) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    protocol = rule.get("IpProtocol")

    if (from_port in DANGEROUS_PORTS or to_port in DANGEROUS_PORTS) and \
       not (from_port in MANAGEMENT_PORTS or to_port in MANAGEMENT_PORTS) and \
       not (from_port in DATABASE_PORTS or to_port in DATABASE_PORTS) and \
       not _is_all_ports(from_port, to_port, protocol):

        cidr_ip = rule.get("CidrIp")
        if cidr_ip and _is_open_cidr(cidr_ip):
            findings.append(
                VULNERABILITIES["SG_OPEN_PORT"].instantiate(
                    logical_id,
                    raw_data={"cidr": cidr_ip, "from_port": from_port, "to_port": to_port}
                )
            )

        cidr_ipv6 = rule.get("CidrIpv6")
        if cidr_ipv6 and _is_open_cidr(cidr_ipv6):
            findings.append(
                VULNERABILITIES["SG_OPEN_PORT"].instantiate(
                    logical_id,
                    raw_data={"cidr": cidr_ipv6, "from_port": from_port, "to_port": to_port}
                )
            )

    return findings


def _check_cross_account_references(rule: Dict[str, Any], logical_id: str, owner_id: str) -> List[Dict[str, Any]]:
    findings = []

    source_sg_owner = rule.get("SourceSecurityGroupOwnerId")
    source_sg_id = rule.get("SourceSecurityGroupId")

    if source_sg_owner and owner_id and source_sg_owner != owner_id:
        findings.append(
            VULNERABILITIES["CROSS_ACCOUNT_SG_REFERENCE"].instantiate(
                logical_id,
                raw_data={"user_id": source_sg_owner, "group_id": source_sg_id}
            )
        )

    return findings


def _check_internal_all_ports(rule: Dict[str, Any], logical_id: str) -> List[Dict[str, Any]]:
    findings = []
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    protocol = rule.get("IpProtocol")

    if _is_all_ports(from_port, to_port, protocol):
        has_public_cidr = False

        cidr_ip = rule.get("CidrIp")
        if cidr_ip and _is_open_cidr(cidr_ip):
            has_public_cidr = True

        cidr_ipv6 = rule.get("CidrIpv6")
        if cidr_ipv6 and _is_open_cidr(cidr_ipv6):
            has_public_cidr = True

        if not has_public_cidr and (cidr_ip or cidr_ipv6):
            findings.append(
                VULNERABILITIES["SG_ALL_PORTS_INTERNAL"].instantiate(
                    logical_id,
                    raw_data={"from_port": from_port, "to_port": to_port, "protocol": protocol}
                )
            )

    return findings
