# aws_scanner/scanners/iam/policy_analyzer.py

from typing import List, Dict, Any

RESTRICTIVE_KEYS = {
    "aws:SourceIp",
    "aws:VpcSourceIp",
    "aws:SourceVpc",
    "aws:PrincipalOrgId",
}

def analyze_policy(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
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

    if ("*" in action or "*" in resource) and not is_restrictive(condition):
        return 'Wildcard access without restrictive Condition — access may be too broad'

    return None


def is_restrictive(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False

    for cond_operator, cond_block in condition.items():
        if not isinstance(cond_block, dict):
            continue
        for key in cond_block:
            if key in RESTRICTIVE_KEYS:
                return True
    return False
