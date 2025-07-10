# aws_scanner/scanners/sg_scanner.py

import boto3
import botocore.exceptions

DANGEROUS_PORTS = {22, 3389, 3306, 5432, 80, 443}  # SSH, RDP, MySQL, Postgres, HTTP/S

def is_cidr_open(cidr):
    return cidr == "0.0.0.0/0"

def extract_open_ports_from_group(sg):
    findings = []
    group_id = sg.get("GroupId")
    group_name = sg.get("GroupName", "")

    for permission in sg.get("IpPermissions", []):
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        ip_ranges = permission.get("IpRanges", [])

        # Some rules may allow all ports (e.g., -1). Skip if ports are not specified.
        if from_port is None or to_port is None:
            continue

        for ip_range in ip_ranges:
            cidr = ip_range.get("CidrIp")
            if is_cidr_open(cidr) and from_port in DANGEROUS_PORTS:
                findings.append({
                    "group_id": group_id,
                    "group_name": group_name,
                    "from_port": from_port,
                    "to_port": to_port,
                    "cidr": cidr
                })
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
