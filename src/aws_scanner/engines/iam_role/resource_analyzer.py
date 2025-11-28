from typing import Dict, Any, List
from aws_scanner.engines.common.resource_definition import ResourceDefinition
from aws_scanner.core.vulnerabilities import VULNERABILITIES


RESTRICTIVE_KEYS = {
    "aws:SourceIp",
    "aws:VpcSourceIp",
    "aws:SourceVpc",
    "aws:PrincipalOrgId",
}


def _is_restrictive(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False

    for cond_operator, cond_block in condition.items():
        if not isinstance(cond_block, dict):
            continue
        for key in cond_block:
            if key in RESTRICTIVE_KEYS:
                return True
    return False


def analyze_iam_role_from_resource(resource_def: ResourceDefinition) -> List[Dict[str, Any]]:
    findings = []

    trust_policy = resource_def.properties.get("AssumeRolePolicyDocument")
    if not trust_policy:
        trust_policy = resource_def.properties.get("trust_policy_document")

    if not trust_policy:
        return findings

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
            if not condition or not _is_restrictive(condition):
                findings.append(
                    VULNERABILITIES["IAM_ROLE_BROAD_ASSUME_ROLE"].instantiate(
                        entity_name=resource_def.logical_id,
                        raw_data=stmt
                    )
                )

    return findings
