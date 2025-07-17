from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.scanners.sg.security_group_data import SecurityGroupData

boto3Wrapper = Boto3Wrapper()

def collect_security_groups(regions=None):
    groups = []

    if regions is None:
        ec2 = boto3Wrapper.get_ec2()
        response = ec2.describe_security_groups()

        for sg in response["SecurityGroups"]:
            groups.append(SecurityGroupData.from_aws(sg))
    else:
        for region in regions:
            try:
                ec2 = boto3Wrapper.get_ec2(region=region)
                response = ec2.describe_security_groups()

                for sg in response["SecurityGroups"]:
                    sg_data = SecurityGroupData.from_aws(sg)
                    sg_data.region = region
                    groups.append(sg_data)

            except Exception as e:
                print(f"Error scanning region {region}: {e}")
                continue

    return groups