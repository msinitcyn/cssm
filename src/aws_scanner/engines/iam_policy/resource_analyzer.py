import fnmatch
from typing import List, Dict, Any
from aws_scanner.engines.common.resource_definition import ResourceDefinition
from aws_scanner.core.vulnerabilities import VULNERABILITIES


RESTRICTIVE_KEYS = {
    "aws:SourceIp",
    "aws:VpcSourceIp",
    "aws:SourceVpc",
    "aws:PrincipalOrgId",
}

SENSITIVE_ACTIONS = {
    "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
    "s3:GetObjectVersion", "s3:PutObjectAcl", "s3:DeleteObjectVersion",
    "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
    "s3:PutBucketAcl", "s3:PutBucketVersioning",
    "iam:CreateUser", "iam:DeleteUser", "iam:CreateRole", "iam:DeleteRole",
    "iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy",
    "iam:CreateAccessKey", "iam:DeleteAccessKey",
    "ec2:TerminateInstances", "ec2:StopInstances", "ec2:CreateSecurityGroup",
    "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
    "rds:DeleteDBInstance", "rds:DeleteDBCluster", "rds:ModifyDBInstance",
    "secretsmanager:GetSecretValue", "secretsmanager:UpdateSecret", "secretsmanager:DeleteSecret",
    "ssm:GetParameter", "ssm:GetParameters", "ssm:PutParameter", "ssm:DeleteParameter",
    "lambda:UpdateFunctionCode", "lambda:DeleteFunction", "lambda:InvokeFunction",
    "cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:DeleteStack",
}

PRIVILEGE_ESCALATION_PATTERNS = [
    ["iam:CreateRole", "iam:AttachRolePolicy"],
    ["iam:CreateRole", "iam:PutRolePolicy"],
    ["iam:CreateUser", "iam:AttachUserPolicy"],
    ["iam:CreateUser", "iam:PutUserPolicy"],
    ["lambda:CreateFunction", "iam:PassRole"],
]


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


def _has_sensitive_actions_without_conditions(actions: List[str], condition: Any) -> bool:
    if condition and _is_restrictive(condition):
        return False

    action_set = set(actions)

    for action in action_set:
        if action in SENSITIVE_ACTIONS:
            return True

        for sensitive_action in SENSITIVE_ACTIONS:
            if fnmatch.fnmatch(sensitive_action, action):
                return True

    return False


def _has_privilege_escalation(actions: List[str], resources: List[str]) -> bool:
    has_wildcard_resource = any(r == "*" for r in resources)
    if not has_wildcard_resource:
        return False

    action_set = set(actions)
    if '*' in action_set:
        return True

    for pattern in PRIVILEGE_ESCALATION_PATTERNS:
        pattern_matched = True
        for pattern_action in pattern:
            found = False
            for action in action_set:
                if fnmatch.fnmatch(pattern_action, action) or fnmatch.fnmatch(action, pattern_action):
                    found = True
                    break
            if not found:
                pattern_matched = False
                break

        if pattern_matched:
            return True

    return False


def _has_assume_role_wildcard(actions: List[str], resources: List[str], not_resources: List[str], condition: Any) -> bool:
    has_wildcard_resource = any(r == "*" for r in resources)
    has_not_resource = len(not_resources) > 0

    if not has_wildcard_resource and not has_not_resource:
        return False

    action_set = set(actions)
    has_assume_role = any(
        action == "sts:AssumeRole" or
        action == "*" or
        fnmatch.fnmatch("sts:AssumeRole", action) or
        fnmatch.fnmatch(action, "sts:AssumeRole")
        for action in action_set
    )

    if has_assume_role and not _is_restrictive(condition):
        return True

    return False


def _analyze_statement(stmt: Dict[str, Any]) -> List[Dict[str, Any]]:
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

    if has_wildcard_action and not _is_restrictive(condition):
        findings.append(VULNERABILITIES["IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION"].instantiate("policy", raw_data=stmt))

    if _has_privilege_escalation(action, resource):
        findings.append(VULNERABILITIES["IAM_POLICY_PRIVILEGE_ESCALATION"].instantiate("policy", raw_data=stmt))

    if _has_assume_role_wildcard(action, resource, not_resource, condition):
        findings.append(VULNERABILITIES["IAM_POLICY_ASSUME_ROLE_WILDCARD"].instantiate("policy", raw_data=stmt))

    if _has_sensitive_actions_without_conditions(action, condition):
        findings.append(VULNERABILITIES["IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS"].instantiate("policy", raw_data=stmt))

    return findings


def analyze_iam_policy_from_resource(resource_def: ResourceDefinition) -> List[Dict[str, Any]]:
    findings = []

    policy_document = resource_def.properties.get("PolicyDocument", {})
    statements = policy_document.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        findings.extend(_analyze_statement(stmt))

    return findings