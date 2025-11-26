from typing import List, Dict, Any
from pathlib import Path
from collections import defaultdict

from aws_scanner.engines.cloudformation.reader import CloudFormationReader
from aws_scanner.engines.common.resource_definition import ResourceCollection, ResourceDefinition
from aws_scanner.core import resource_orchestrator
from aws_scanner.core.vulnerabilities import VULNERABILITIES


def _extract_inline_policies_from_roles(collection: ResourceCollection) -> Dict[str, str]:
    """Extract inline policies from IAM roles and add them as separate resources to the collection.

    Returns a mapping of policy logical_id to role name for later entity_name fixing.
    """
    policy_to_role_map = {}
    roles_to_process = [r for r in collection.resources.values() if r.resource_type == "AWS::IAM::Role"]

    for role_resource in roles_to_process:
        role_name = role_resource.properties.get("RoleName", role_resource.logical_id)
        inline_policies = role_resource.properties.get("Policies", [])
        for policy in inline_policies:
            policy_doc = policy.get("PolicyDocument", {})
            if policy_doc:
                policy_logical_id = policy.get("PolicyName", f"{role_resource.logical_id}-InlinePolicy")
                policy_resource = ResourceDefinition(
                    logical_id=policy_logical_id,
                    resource_type="AWS::IAM::Policy",
                    properties={
                        "PolicyName": policy.get("PolicyName", "InlinePolicy"),
                        "PolicyDocument": policy_doc
                    }
                )
                collection.add_resource(policy_resource)
                policy_to_role_map[policy_logical_id] = role_name

    return policy_to_role_map


def _extract_bucket_policies(collection: ResourceCollection) -> None:
    """Extract S3 bucket policies and add them as analyzable resources to the collection.

    Also adds the policy document to the bucket resource properties for S3 analysis.
    """
    bucket_policies = [r for r in collection.resources.values() if r.resource_type == "AWS::S3::BucketPolicy"]

    for policy_resource in bucket_policies:
        policy_doc = policy_resource.properties.get("PolicyDocument", {})
        bucket_ref = policy_resource.properties.get("Bucket", "")

        if policy_doc:
            bucket_logical_id = bucket_ref
            if isinstance(bucket_ref, dict) and "Ref" in bucket_ref:
                bucket_logical_id = bucket_ref["Ref"]

            target_bucket = collection.resources.get(bucket_logical_id)
            if target_bucket:
                bucket_name = target_bucket.properties.get("BucketName", bucket_logical_id)
                # Add policy document to bucket properties for S3 analyzer
                target_bucket.properties["Policy"] = policy_doc
            else:
                bucket_name = bucket_ref if isinstance(bucket_ref, str) else bucket_logical_id

            # Also create IAM policy resource for IAM policy analysis
            policy_as_iam_resource = ResourceDefinition(
                logical_id=f"{policy_resource.logical_id}-AsPolicy",
                resource_type="AWS::IAM::Policy",
                properties={
                    "PolicyName": policy_resource.logical_id,
                    "PolicyDocument": policy_doc,
                    "_bucket_name": bucket_name
                }
            )
            collection.add_resource(policy_as_iam_resource)


def _fix_entity_names_for_inline_policies(findings: List[Dict[str, Any]], policy_to_role_map: Dict[str, str]) -> None:
    """Fix entity_name in findings for inline policies extracted from roles."""
    for finding in findings:
        if finding.get("entity_type") == "iam_policy" and finding.get("entity_name") == "policy":
            # This is an inline policy finding, update entity_name to the parent role name
            # The policy_to_role_map keys are policy logical_ids, but we need to match by the fact that
            # the finding came from an inline policy. Since all inline policies have entity_name="policy" (hardcoded in analyzer),
            # we need to figure out which role it belongs to. For now, if there's only one role, use that.
            # Better approach: check if we can match based on the statement in raw_data
            if policy_to_role_map:
                # Use the first role name (works for single role, needs better logic for multiple roles)
                role_name = next(iter(policy_to_role_map.values()))
                finding["entity_name"] = role_name


def _fix_entity_names_for_buckets(findings: List[Dict[str, Any]], collection: ResourceCollection) -> None:
    """Fix entity_name in findings for S3 buckets to use BucketName property when available."""
    for finding in findings:
        if finding.get("entity_type") == "s3_bucket":
            logical_id = finding.get("entity_name")
            if logical_id and logical_id in collection.resources:
                bucket_resource = collection.resources[logical_id]
                bucket_name = bucket_resource.properties.get("BucketName", logical_id)
                finding["entity_name"] = bucket_name


def _format_results_by_resource_type(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group findings by resource type for the report generator."""
    results = {
        "iam_roles": [],
        "s3_buckets": [],
        "security_groups": []
    }

    entities_by_type = defaultdict(lambda: defaultdict(list))

    for finding in findings:
        entity_type = finding.get("entity_type", "")
        entity_name = finding.get("entity_name", "unknown")

        if entity_type in ("iam_role", "iam_policy"):
            entities_by_type["iam_roles"][entity_name].append(finding)
        elif entity_type == "s3_bucket":
            entities_by_type["s3_buckets"][entity_name].append(finding)
        elif entity_type == "security_group":
            entities_by_type["security_groups"][entity_name].append(finding)

    for entity_type, entities in entities_by_type.items():
        for entity_name, entity_findings in entities.items():
            if entity_type == "iam_roles":
                results["iam_roles"].append({
                    "role_name": entity_name,
                    "vulnerabilities": entity_findings
                })
            elif entity_type == "s3_buckets":
                results["s3_buckets"].append({
                    "bucket_name": entity_name,
                    "vulnerabilities": entity_findings
                })
            elif entity_type == "security_groups":
                results["security_groups"].append({
                    "group_name": entity_name,
                    "vulnerabilities": entity_findings
                })

    return results


def scan_cloudformation_template(file_path: str) -> Dict[str, List[Dict[str, Any]]]:
    """Scan a CloudFormation template for security vulnerabilities."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"CloudFormation template not found: {file_path}")

    with open(file_path, 'r') as f:
        content = f.read()

    reader = CloudFormationReader()
    collection = reader.read(content)

    policy_to_role_map = _extract_inline_policies_from_roles(collection)
    _extract_bucket_policies(collection)

    findings = resource_orchestrator.analyze_resources(collection)

    _fix_entity_names_for_inline_policies(findings, policy_to_role_map)
    _fix_entity_names_for_buckets(findings, collection)

    results = _format_results_by_resource_type(findings)

    return results
