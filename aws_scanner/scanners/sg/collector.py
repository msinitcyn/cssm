# aws_scanner/sg/collector.py

import boto3
from aws_scanner.scanners.sg.security_group_data import SecurityGroupData

def collect_security_groups(ec2=None):
    if ec2 is None:
        ec2 = boto3.client("ec2")

    response = ec2.describe_security_groups()
    groups = []
    for sg in response["SecurityGroups"]:
        groups.append(SecurityGroupData.from_aws(sg))
    return groups
