# aws_scanner/scanners/sg/security_group_data.py

from typing import List, Dict

class SecurityGroupData:
    def __init__(self, group_id: str, group_name: str, owner_id: str, ingress_permissions: List[Dict]):
        self.group_id = group_id
        self.group_name = group_name
        self.owner_id = owner_id
        self.ingress_permissions = ingress_permissions

    @staticmethod
    def from_aws(data: Dict):
        return SecurityGroupData(
            group_id=data["GroupId"],
            group_name=data.get("GroupName", ""),
            owner_id=data.get("OwnerId", ""),
            ingress_permissions=data.get("IpPermissions", [])
        )
