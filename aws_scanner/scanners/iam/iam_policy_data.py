# aws_scanner/scanners/iam/iam_policy_data.py

class IamPolicyData:
    def __init__(self, name, policy_type, document, arn=None, is_inline=True):
        self.name = name
        self.policy_type = policy_type
        self.document = document or {}
        self.arn = arn
        self.is_inline = is_inline