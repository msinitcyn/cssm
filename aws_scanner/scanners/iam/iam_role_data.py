# aws_scanner/scanners/iam/iam_role_data.py

class IamRoleData:
    def __init__(self, name: str, inline_policies: dict = None, attached_policies: dict = None):
        self.name = name
        self.inline_policies = inline_policies or {}
        self.attached_policies = attached_policies or {}
