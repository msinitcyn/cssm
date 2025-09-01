from typing import Dict, Any, List, Tuple
from aws_scanner.core.vulnerabilities import VULNERABILITIES

ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'

def classify_bucket_group(pab: Dict[str, bool]) -> str:
    ignore_acls = pab.get("IgnorePublicAcls", False)
    block_policy = pab.get("BlockPublicPolicy", False)
    restrict_policy = pab.get("RestrictPublicBuckets", False)

    can_use_acl = not ignore_acls
    can_use_policy = not (block_policy and restrict_policy)

    if can_use_acl and can_use_policy:
        return "ACL+Policy"
    elif can_use_acl:
        return "ACL-only"
    elif can_use_policy:
        return "Policy-only"
    else:
        return "Blocked"

def analyze_acl(bucket_data) -> bool:
    pab = bucket_data.pab_config
    if pab.get("IgnorePublicAcls", False):
        return False
    acl = bucket_data.acl_grants or []
    return any(
        grant.get("Grantee", {}).get("URI") == ALL_USERS_URI
        for grant in acl
    )

def analyze_policy(bucket_data) -> Tuple[bool, bool]:
    pab = bucket_data.pab_config
    block_policy = pab.get("BlockPublicPolicy", False)
    restrict_policy = pab.get("RestrictPublicBuckets", False)
    if block_policy and restrict_policy:
        return False, False

    policy_doc = bucket_data.policy.document if bucket_data.policy else {}
    is_public_policy = False
    condition_present = False

    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal not in ("*", {"AWS": "*"}):
            continue
        action = stmt.get("Action")
        if isinstance(action, str):
            action = [action]
        if not any(a in action for a in ("s3:GetObject", "s3:*")):
            continue
        if stmt.get("Condition"):
            condition_present = True
        else:
            is_public_policy = True

    return is_public_policy, condition_present

def is_cors_rule_overpermissive(rule: Dict[str, Any]) -> bool:
    return any(
        "*" in rule.get(key, [])
        for key in ["AllowedOrigins", "AllowedHeaders", "AllowedMethods"]
    )

def check_acl_vulnerability(bucket_data) -> List[Dict[str, Any]]:
    if analyze_acl(bucket_data):
        return [VULNERABILITIES["S3_PUBLIC_ACL"].instantiate(bucket_data.name)]
    return []

def check_policy_vulnerabilities(bucket_data) -> List[Dict[str, Any]]:
    is_policy, has_condition = analyze_policy(bucket_data)
    findings = []

    if is_policy:
        findings.append(VULNERABILITIES["S3_PUBLIC_POLICY"].instantiate(bucket_data.name))

    if not is_policy and has_condition:
        findings.append(VULNERABILITIES["S3_POTENTIALLY_PUBLIC_POLICY_CONDITION"].instantiate(bucket_data.name))

    return findings

def check_cors_vulnerabilities(bucket_data) -> List[Dict[str, Any]]:
    findings = []
    cors = bucket_data.cors_config or {}
    for rule in cors.get("CORSRules", []):
        if is_cors_rule_overpermissive(rule):
            findings.append(VULNERABILITIES["S3_PUBLIC_CORS"].instantiate(bucket_data.name, raw_data=rule))
    return findings

def check_website_vulnerability(bucket_data) -> List[Dict[str, Any]]:
    if bucket_data.website_config:
        return [VULNERABILITIES["S3_PUBLIC_WEBSITE"].instantiate(bucket_data.name)]
    return []

def check_logging_vulnerability(bucket_data) -> List[Dict[str, Any]]:
    findings = []
    logging_config = bucket_data.server_access_logging or {}

    if not logging_config or not logging_config.get("enabled", True):
        findings.append({
            "id": "S3_NO_ACCESS_LOGGING",
            "description": "S3 bucket does not have server access logging enabled",
            "severity": "low",
            "entity_type": "s3_bucket",
            "entity_name": bucket_data.name,
            "remediation": "Enable server access logging to track bucket access",
            "raw_data": logging_config
        })

    return findings

def check_versioning_vulnerability(bucket_data) -> List[Dict[str, Any]]:
    findings = []
    versioning_config = bucket_data.versioning or {}

    if versioning_config.get("status") == "Suspended":
        findings.append({
            "id": "S3_VERSIONING_SUSPENDED",
            "description": "S3 bucket versioning is suspended",
            "severity": "medium",
            "entity_type": "s3_bucket",
            "entity_name": bucket_data.name,
            "remediation": "Enable versioning to protect against accidental deletion or modification",
            "raw_data": versioning_config
        })

    return findings

def check_encryption_vulnerability(bucket_data) -> List[Dict[str, Any]]:
    findings = []
    encryption_config = bucket_data.encryption or {}

    if not encryption_config or encryption_config.get("server_side_encryption") == "none":
        findings.append({
            "id": "S3_NO_ENCRYPTION",
            "description": "S3 bucket does not have server-side encryption enabled",
            "severity": "high",
            "entity_type": "s3_bucket",
            "entity_name": bucket_data.name,
            "remediation": "Enable server-side encryption with AWS KMS or AES-256",
            "raw_data": encryption_config
        })

    return findings

def check_mfa_delete_vulnerability(bucket_data) -> List[Dict[str, Any]]:
    findings = []

    if bucket_data.mfa_delete is False:
        findings.append({
            "id": "S3_MFA_DELETE_DISABLED",
            "description": "S3 bucket does not have MFA Delete enabled",
            "severity": "medium",
            "entity_type": "s3_bucket",
            "entity_name": bucket_data.name,
            "remediation": "Enable MFA Delete to require multi-factor authentication for object deletion",
            "raw_data": {"mfa_delete": bucket_data.mfa_delete}
        })

    return findings

def analyze_s3_bucket(bucket_data) -> List[Dict[str, Any]]:
    findings = []
    findings.extend(check_acl_vulnerability(bucket_data))
    findings.extend(check_policy_vulnerabilities(bucket_data))
    findings.extend(check_cors_vulnerabilities(bucket_data))
    findings.extend(check_website_vulnerability(bucket_data))
    findings.extend(check_logging_vulnerability(bucket_data))
    findings.extend(check_versioning_vulnerability(bucket_data))
    findings.extend(check_encryption_vulnerability(bucket_data))
    findings.extend(check_mfa_delete_vulnerability(bucket_data))
    return findings