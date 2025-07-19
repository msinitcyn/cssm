from typing import List, Dict, Any
from aws_scanner.core.vulnerabilities import VULNERABILITIES

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


def analyze_statement(stmt: Dict[str, Any]):
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

    has_wildcard_action = any(a == "*" for a in action)
    has_wildcard_resource = any(r == "*" for r in resource)

    if has_wildcard_action and has_wildcard_resource:
        return VULNERABILITIES["IAM_POLICY_WILDCARD_ALL"].instantiate("policy", raw_data=stmt)

    if not_action and has_wildcard_resource:
        return VULNERABILITIES["IAM_POLICY_NOTACTION_WILDCARD_RESOURCE"].instantiate("policy", raw_data=stmt)

    if not_resource and has_wildcard_action:
        return VULNERABILITIES["IAM_POLICY_NOTRESOURCE_WILDCARD_ACTION"].instantiate("policy", raw_data=stmt)

    if has_wildcard_action and condition:
        return VULNERABILITIES["IAM_POLICY_WILDCARD_ACTION_CONDITION"].instantiate("policy", raw_data=stmt)

    if not_action and condition:
        return VULNERABILITIES["IAM_POLICY_NOTACTION_CONDITION"].instantiate("policy", raw_data=stmt)

    if has_wildcard_action and not is_restrictive(condition):
        return VULNERABILITIES["IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION"].instantiate("policy", raw_data=stmt)

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
