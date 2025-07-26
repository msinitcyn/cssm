from typing import List, Dict

class SgData:
    def __init__(self, group_id: str, group_name: str, owner_id: str, 
                 ingress_permissions: List[Dict], region: str = None):
        self.group_id = group_id
        self.group_name = group_name or ""
        self.owner_id = owner_id or ""
        self.ingress_permissions = ingress_permissions or []
        self.region = region