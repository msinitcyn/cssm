from typing import Dict, Any, List
from aws_scanner.engines.common.resource_definition import ResourceDefinition
from aws_scanner.core.vulnerabilities import VULNERABILITIES


ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'


def _is_cors_rule_overpermissive(rule: Dict[str, Any]) -> bool:
    return any(
        "*" in rule.get(key, [])
        for key in ["AllowedOrigins", "AllowedHeaders", "AllowedMethods"]
    )


def analyze_s3_bucket_from_resource(resource_def: ResourceDefinition) -> List[Dict[str, Any]]:
    findings = []
    props = resource_def.properties

    pab = props.get("PublicAccessBlockConfiguration", {}) or {}

    if _check_public_acl(props, pab):
        findings.append(
            VULNERABILITIES["S3_PUBLIC_ACL"].instantiate(
                entity_name=resource_def.logical_id
            )
        )

    if _check_public_policy(props, pab):
        findings.append(
            VULNERABILITIES["S3_PUBLIC_POLICY"].instantiate(
                entity_name=resource_def.logical_id
            )
        )

    findings.extend(_check_cors_vulnerabilities(props, resource_def.logical_id))

    if _check_website_hosting(props):
        findings.append(
            VULNERABILITIES["S3_PUBLIC_WEBSITE"].instantiate(
                entity_name=resource_def.logical_id
            )
        )

    if _check_no_encryption(props):
        findings.append({
            "id": "S3_NO_ENCRYPTION",
            "description": "S3 bucket does not have server-side encryption enabled",
            "severity": "high",
            "entity_type": "s3_bucket",
            "entity_name": resource_def.logical_id,
            "remediation": "Enable server-side encryption with AWS KMS or AES-256",
            "raw_data": props.get("BucketEncryption", {})
        })

    if _check_no_logging(props):
        findings.append({
            "id": "S3_NO_ACCESS_LOGGING",
            "description": "S3 bucket does not have server access logging enabled",
            "severity": "low",
            "entity_type": "s3_bucket",
            "entity_name": resource_def.logical_id,
            "remediation": "Enable server access logging to track bucket access",
            "raw_data": props.get("LoggingConfiguration", {})
        })

    if _check_versioning_suspended(props):
        findings.append({
            "id": "S3_VERSIONING_SUSPENDED",
            "description": "S3 bucket versioning is suspended",
            "severity": "medium",
            "entity_type": "s3_bucket",
            "entity_name": resource_def.logical_id,
            "remediation": "Enable versioning to protect against accidental deletion or modification",
            "raw_data": props.get("VersioningConfiguration", {})
        })

    if _check_mfa_delete_disabled(props):
        findings.append({
            "id": "S3_MFA_DELETE_DISABLED",
            "description": "S3 bucket does not have MFA Delete enabled",
            "severity": "medium",
            "entity_type": "s3_bucket",
            "entity_name": resource_def.logical_id,
            "remediation": "Enable MFA Delete to require multi-factor authentication for object deletion",
            "raw_data": {"mfa_delete": props.get("MfaDelete", False)}
        })

    return findings


def _check_public_acl(props: Dict[str, Any], pab: Dict[str, Any]) -> bool:
    if pab.get("IgnorePublicAcls", False):
        return False

    acl_grants = props.get("AclGrants", [])
    return any(
        grant.get("Grantee", {}).get("URI") == ALL_USERS_URI
        for grant in acl_grants
    )


def _check_public_policy(props: Dict[str, Any], pab: Dict[str, Any]) -> bool:
    block_policy = pab.get("BlockPublicPolicy", False)
    restrict_policy = pab.get("RestrictPublicBuckets", False)
    if block_policy and restrict_policy:
        return False

    policy_doc = props.get("Policy", {})
    if not policy_doc:
        return False

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
        if not stmt.get("Condition"):
            return True

    return False


def _check_cors_vulnerabilities(props: Dict[str, Any], logical_id: str) -> List[Dict[str, Any]]:
    findings = []
    cors_config = props.get("CorsConfiguration", {}) or {}

    for rule in cors_config.get("CorsRules", []):
        if _is_cors_rule_overpermissive(rule):
            findings.append(
                VULNERABILITIES["S3_PUBLIC_CORS"].instantiate(
                    entity_name=logical_id,
                    raw_data=rule
                )
            )

    return findings


def _check_website_hosting(props: Dict[str, Any]) -> bool:
    return bool(props.get("WebsiteConfiguration"))


def _check_no_encryption(props: Dict[str, Any]) -> bool:
    encryption_config = props.get("BucketEncryption", {})
    if not encryption_config:
        return True

    sse_config = encryption_config.get("ServerSideEncryptionConfiguration", [])
    return len(sse_config) == 0


def _check_no_logging(props: Dict[str, Any]) -> bool:
    logging_config = props.get("LoggingConfiguration", {})
    return not logging_config or not logging_config.get("DestinationBucketName")


def _check_versioning_suspended(props: Dict[str, Any]) -> bool:
    versioning_config = props.get("VersioningConfiguration", {})
    return versioning_config.get("Status") == "Suspended"


def _check_mfa_delete_disabled(props: Dict[str, Any]) -> bool:
    return props.get("MfaDelete") is False
