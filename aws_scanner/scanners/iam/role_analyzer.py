from .iam_role_data import IamRoleData
from .policy_analyzer import analyze_policy

def analyze_iam_role(role_data: IamRoleData):
    policies = []

    for policy_name, policy_doc in role_data.inline_policies.items():
        issues = analyze_policy(policy_doc)
        policies.append({
            "name": policy_name,
            "type": "inline",
            "issues": issues if issues else []
        })

    for policy_name, policy_doc in role_data.attached_policies.items():
        issues = analyze_policy(policy_doc)
        policies.append({
            "name": policy_name,
            "type": "attached",
            "issues": issues if issues else []
        })

    return {
        "role": role_data.name,
        "policies": policies
    }
