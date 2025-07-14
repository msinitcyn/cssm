from typing import List, Dict, Any
from .iam_policy_data import IamPolicyData

def analyze_policy(policy: IamPolicyData) -> List[Dict[str, Any]]:
    findings = []

    doc = policy.document
    statements = doc.get("Statement")
    if not statements:
        return findings

    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        finding = analyze_statement(stmt)
        if finding:
            findings.append({
                "issue": finding,
                "statement": stmt
            })

    return findings


def analyze_statement(stmt: Dict[str, Any]) -> str | None:
    def to_list(val):
        if isinstance(val, str):
            return [val]
        if isinstance(val, list):
            return val
        return []

    action = to_list(stmt.get("Action", []))
    not_action = to_list(stmt.get("NotAction", []))
    resource = to_list(stmt.get("Resource", []))
    not_resource = to_list(stmt.get("NotResource", []))
    condition = stmt.get("Condition")

    if "*" in action and "*" in resource:
        return 'Too permissive: Action="*", Resource="*"'

    if not_action and "*" in resource:
        return 'NotAction + wildcard Resource can lead to broad access'

    if not_resource and "*" in action:
        return 'NotResource + wildcard Action can lead to broad access'

    if "*" in action and condition:
        return 'Wildcard Action + Condition — risky if Condition is weak'

    if not_action and condition:
        return 'NotAction + Condition — risky if exclusions are narrow'

    return None
