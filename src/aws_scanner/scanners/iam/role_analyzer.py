from typing import Optional, Dict, Any
from .iam_role_data import IamRoleData
from .policy_analyzer import analyze_policy, is_restrictive
from aws_scanner.core.vulnerabilities import VULNERABILITIES

def analyze_assume_role_policy(trust_policy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    statements = trust_policy.get("Statement")
    if not statements:
        return None
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action")
        if isinstance(actions, str):
            actions = [actions]

        if "sts:AssumeRole" not in actions:
            continue

        principal = stmt.get("Principal")
        if principal in ("*", {"AWS": "*"}):
            condition = stmt.get("Condition")
            if not condition or not is_restrictive(condition):
                return VULNERABILITIES["IAM_ROLE_BROAD_ASSUME_ROLE"].instantiate(
                    entity_name="role",
                    raw_data=stmt
                )
    return None

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

    trust_policy_issue = analyze_assume_role_policy(role_data.trust_policy_document or {})
    trust_policy_issues = [trust_policy_issue] if trust_policy_issue else []

    return {
        "role": role_data.name,
        "policies": policies,
        "trust_policy_issues": trust_policy_issues
    }
