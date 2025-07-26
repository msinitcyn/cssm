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

    policy = bucket_data.policy_doc or {}
    is_public_policy = False
    condition_present = False

    for stmt in policy.get("Statement", []):
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

def analyze_s3_bucket(bucket_data) -> List[Dict[str, Any]]:
    findings = []
    findings.extend(check_acl_vulnerability(bucket_data))
    findings.extend(check_policy_vulnerabilities(bucket_data))
    findings.extend(check_cors_vulnerabilities(bucket_data))
    findings.extend(check_website_vulnerability(bucket_data))
    return findings