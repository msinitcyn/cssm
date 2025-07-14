from .iam_role_data import IamRoleData
from .policy_analyzer import analyze_policy

def analyze_iam_role(role_data: IamRoleData):
    findings = []

    for policy_name, policy_doc in role_data.inline_policies.items():
        issues = analyze_policy(policy_doc)
        for issue in issues:
            findings.append({
                "role": role_data.name,
                "policy_type": "inline",
                "policy_name": policy_name,
                "issue": issue
            })

    for policy_name, policy_doc in role_data.attached_policies.items():
        issues = analyze_policy(policy_doc)
        for issue in issues:
            findings.append({
                "role": role_data.name,
                "policy_type": "attached",
                "policy_name": policy_name,
                "issue": issue
            })

    return findings
