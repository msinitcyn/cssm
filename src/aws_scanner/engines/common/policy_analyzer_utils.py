from typing import Dict, Any, List
from aws_scanner.core.vulnerabilities import VULNERABILITIES
from .iam_policy_data import IamPolicyData

RESTRICTIVE_KEYS = {
    "aws:SourceIp",
    "aws:VpcSourceIp",
    "aws:SourceVpc",
    "aws:PrincipalOrgId",
}

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

PRIVILEGE_ESCALATION_PATTERNS = [
    ["iam:CreateRole", "iam:AttachRolePolicy"],
    ["iam:CreateRole", "iam:PutRolePolicy"], 
    ["iam:CreateUser", "iam:AttachUserPolicy"],
    ["iam:CreateUser", "iam:PutUserPolicy"],
    ["lambda:CreateFunction", "iam:PassRole"],
]

def has_privilege_escalation(actions, resources):
    has_wildcard_resource = any(r == "*" for r in resources)
    if not has_wildcard_resource:
        return False
        
    set(actions)
    
    for pattern in PRIVILEGE_ESCALATION_PATTERNS:
        if all(
            any(
                pattern_action in action or 
                action == "*" or
                pattern_action == action
                for action in actions
            )
            for pattern_action in pattern
        ):
            return True
    return False

def analyze_statement(stmt: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    
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
        findings.append(VULNERABILITIES["IAM_POLICY_WILDCARD_ALL"].instantiate("policy", raw_data=stmt))

    if not_action and has_wildcard_resource:
        findings.append(VULNERABILITIES["IAM_POLICY_NOTACTION_WILDCARD_RESOURCE"].instantiate("policy", raw_data=stmt))

    if not_resource and has_wildcard_action:
        findings.append(VULNERABILITIES["IAM_POLICY_NOTRESOURCE_WILDCARD_ACTION"].instantiate("policy", raw_data=stmt))

    if has_wildcard_action and condition:
        findings.append(VULNERABILITIES["IAM_POLICY_WILDCARD_ACTION_CONDITION"].instantiate("policy", raw_data=stmt))

    if not_action and condition:
        findings.append(VULNERABILITIES["IAM_POLICY_NOTACTION_CONDITION"].instantiate("policy", raw_data=stmt))

    if has_wildcard_action and not is_restrictive(condition):
        findings.append(VULNERABILITIES["IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION"].instantiate("policy", raw_data=stmt))

    if has_privilege_escalation(action, resource):
        findings.append(VULNERABILITIES["IAM_POLICY_PRIVILEGE_ESCALATION"].instantiate("policy", raw_data=stmt))

    return findings

def analyze_policy(policy: IamPolicyData) -> List[Dict[str, Any]]:
    findings = []
    doc = policy.document
    statements = doc.get("Statement", [])
    
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        
        findings.extend(analyze_statement(stmt))

    return findings