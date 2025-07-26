from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.engines.sg.sg_data import SgData

def collect_security_groups(regions: list[str] = None) -> list[SgData]:
    ec2 = Boto3Wrapper().get_ec2()
    results = []

    if regions:
        for region in regions:
            try:
                regional_ec2 = Boto3Wrapper().get_ec2(region=region)
                groups = regional_ec2.describe_security_groups().get("SecurityGroups", [])
                
                for group in groups:
                    results.append(SgData(
                        group_id=group["GroupId"],
                        group_name=group.get("GroupName", ""),
                        owner_id=group.get("OwnerId", ""),
                        ingress_permissions=group.get("IpPermissions", []),
                        region=region
                    ))
            except Exception:
                continue
    else:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
        for group in groups:
            results.append(SgData(
                group_id=group["GroupId"],
                group_name=group.get("GroupName", ""),
                owner_id=group.get("OwnerId", ""),
                ingress_permissions=group.get("IpPermissions", []),
                region=None
            ))

    return results