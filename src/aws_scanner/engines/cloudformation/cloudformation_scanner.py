from typing import List, Dict, Any
from pathlib import Path
from collections import defaultdict

from aws_scanner.engines.cloudformation.reader import CloudFormationReader
from aws_scanner.engines.common.resource_definition import ResourceCollection
from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource
from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource
from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource
from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource
from aws_scanner.core.vulnerabilities import VULNERABILITIES


def analyze_s3_bucket_policy(policy_doc: Dict[str, Any], bucket_name: str) -> List[Dict[str, Any]]:
    findings = []
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
            findings.append(VULNERABILITIES["S3_PUBLIC_POLICY"].instantiate(bucket_name))
            break
    return findings


def scan_cloudformation_template(file_path: str) -> Dict[str, List[Dict[str, Any]]]:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"CloudFormation template not found: {file_path}")

    content = path.read_text()

    reader = CloudFormationReader()
    collection = reader.read(content)

    results = {
        "iam_roles": [],
        "s3_buckets": [],
        "security_groups": []
    }

    for resource in collection.resources.values():
        resource_type = resource.resource_type

        if resource_type == "AWS::IAM::Role":
            role_name = resource.properties.get("RoleName", resource.logical_id)
            findings = analyze_iam_role_from_resource(resource)

            inline_policies = resource.properties.get("Policies", [])
            for policy in inline_policies:
                policy_doc = policy.get("PolicyDocument", {})
                if policy_doc:
                    from aws_scanner.engines.common.resource_definition import ResourceDefinition
                    policy_resource = ResourceDefinition(
                        logical_id=policy.get("PolicyName", f"{resource.logical_id}-Policy"),
                        resource_type="AWS::IAM::Policy",
                        properties={
                            "PolicyName": policy.get("PolicyName", "InlinePolicy"),
                            "PolicyDocument": policy_doc
                        }
                    )
                    policy_findings = analyze_iam_policy_from_resource(policy_resource)
                    findings.extend(policy_findings)

            if findings:
                results["iam_roles"].append({
                    "role_name": role_name,
                    "vulnerabilities": findings
                })

        elif resource_type in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            findings = analyze_iam_policy_from_resource(resource)
            if findings:
                policy_name = resource.properties.get("PolicyName", resource.logical_id)
                results["iam_roles"].append({
                    "role_name": policy_name,
                    "vulnerabilities": findings
                })

        elif resource_type == "AWS::S3::Bucket":
            bucket_name = resource.properties.get("BucketName", resource.logical_id)
            findings = analyze_s3_bucket_from_resource(resource)

            bucket_entry = None
            if findings:
                bucket_entry = {
                    "bucket_name": bucket_name,
                    "vulnerabilities": findings
                }
                results["s3_buckets"].append(bucket_entry)
            else:
                bucket_entry = {
                    "bucket_name": bucket_name,
                    "vulnerabilities": []
                }
                results["s3_buckets"].append(bucket_entry)

        elif resource_type == "AWS::S3::BucketPolicy":
            policy_doc = resource.properties.get("PolicyDocument", {})
            bucket_ref = resource.properties.get("Bucket", "")

            if policy_doc:
                bucket_logical_id = bucket_ref
                if isinstance(bucket_ref, dict) and "Ref" in bucket_ref:
                    bucket_logical_id = bucket_ref["Ref"]

                target_bucket = collection.resources.get(bucket_logical_id)
                if target_bucket:
                    bucket_name = target_bucket.properties.get("BucketName", bucket_logical_id)
                else:
                    bucket_name = bucket_ref if isinstance(bucket_ref, str) else bucket_logical_id

                findings = analyze_s3_bucket_policy(policy_doc, bucket_name)

                if findings:
                    for bucket in results["s3_buckets"]:
                        if bucket["bucket_name"] == bucket_name:
                            bucket["vulnerabilities"].extend(findings)
                            break
                    else:
                        results["s3_buckets"].append({
                            "bucket_name": bucket_name,
                            "vulnerabilities": findings
                        })

        elif resource_type == "AWS::EC2::SecurityGroup":
            findings = analyze_sg_from_resource(resource)
            if findings:
                group_name = resource.properties.get("GroupName", resource.logical_id)
                results["security_groups"].append({
                    "group_name": group_name,
                    "vulnerabilities": findings
                })

    return results
