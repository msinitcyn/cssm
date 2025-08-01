from typing import Dict, Any, List
from .iam_role_data import IamRoleData
from aws_scanner.engines.common.policy_analyzer_utils import analyze_policy, is_restrictive
from aws_scanner.core.vulnerabilities import VULNERABILITIES

def analyze_assume_role_policy(trust_policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    statements = trust_policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        if "sts:AssumeRole" not in actions:
            continue

        principal = stmt.get("Principal")
        if principal in ("*", {"AWS": "*"}):
            condition = stmt.get("Condition")
            if not condition or not is_restrictive(condition):
                findings.append(
                    VULNERABILITIES["IAM_ROLE_BROAD_ASSUME_ROLE"].instantiate(
                        raw_data=stmt
                    )
                )
    return findings

def analyze_iam_role(role_data: IamRoleData) -> List[Dict[str, Any]]:
    findings = []

    findings.extend(analyze_assume_role_policy(role_data.trust_policy_document or {}))

    for policy in role_data.inline_policies:
        policy_findings = analyze_policy(policy)
        for finding in policy_findings:
            finding["policy_name"] = getattr(policy, "name", "inline")
            finding["policy_type"] = "inline"
        findings.extend(policy_findings)

    for policy in role_data.attached_policies:
        policy_findings = analyze_policy(policy)
        for finding in policy_findings:
            finding["policy_name"] = getattr(policy, "name", "attached")
            finding["policy_type"] = "attached"
        findings.extend(policy_findings)

    return findings
