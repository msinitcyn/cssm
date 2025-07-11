# aws_scanner/scanners/sg_scanner.py

import boto3
import botocore.exceptions

DANGEROUS_PORTS = {22, 3389, 3306, 5432, 80, 443}  # SSH, RDP, MySQL, Postgres, HTTP/S

def is_cidr_open(cidr):
    return cidr == "0.0.0.0/0"

def is_cidr_ipv6_open(cidr):
    return cidr == "::/0"

def is_all_ports(from_port, to_port, protocol):
    return (
        from_port is None or
        to_port is None or
        (from_port == 0 and to_port == 65535) or
        protocol == "-1"
    )

def extract_open_ports_from_group(sg):
    findings = []
    group_id = sg.get("GroupId")
    group_name = sg.get("GroupName", "")

    for permission in sg.get("IpPermissions", []):
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        protocol = permission.get("IpProtocol")
        ip_ranges = permission.get("IpRanges", [])
        ipv6_ranges = permission.get("Ipv6Ranges", [])

        # Check IPv4 ranges
        for ip_range in ip_ranges:
            cidr = ip_range.get("CidrIp")
            if is_cidr_open(cidr):
                finding = {
                    "group_id": group_id,
                    "group_name": group_name,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                    "protocol": protocol,
                    "is_ipv6": False
                }
                if from_port in DANGEROUS_PORTS or is_all_ports(from_port, to_port, protocol):
                    if is_all_ports(from_port, to_port, protocol):
                        finding["all_ports"] = True
                    findings.append(finding)

        # Check IPv6 ranges
        for ip_range in ipv6_ranges:
            cidr = ip_range.get("CidrIpv6")
            if is_cidr_ipv6_open(cidr):
                finding = {
                    "group_id": group_id,
                    "group_name": group_name,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr,
                    "protocol": protocol,
                    "is_ipv6": True
                }
                if from_port in DANGEROUS_PORTS or is_all_ports(from_port, to_port, protocol):
                    if is_all_ports(from_port, to_port, protocol):
                        finding["all_ports"] = True
                    findings.append(finding)

    return findings

def find_open_security_groups(ec2=None):
    if ec2 is None:
        ec2 = boto3.client("ec2")

    results = []
    try:
        response = ec2.describe_security_groups()
        for sg in response.get("SecurityGroups", []):
            results += extract_open_ports_from_group(sg)
    except botocore.exceptions.ClientError as e:
        results.append({"error": str(e)})

    return results
