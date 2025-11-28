import logging
from typing import List, Dict, Any

from aws_scanner.engines.common.resource_definition import ResourceCollection
from aws_scanner.engines.iam_role.resource_analyzer import analyze_iam_role_from_resource
from aws_scanner.engines.iam_policy.resource_analyzer import analyze_iam_policy_from_resource
from aws_scanner.engines.s3.resource_analyzer import analyze_s3_bucket_from_resource
from aws_scanner.engines.sg.resource_analyzer import analyze_sg_from_resource


logger = logging.getLogger(__name__)


def analyze_resources(collection: ResourceCollection) -> List[Dict[str, Any]]:
    all_findings = []

    for resource in collection.resources.values():
        resource_type = resource.resource_type

        if resource_type == "AWS::IAM::Role":
            findings = analyze_iam_role_from_resource(resource)
            all_findings.extend(findings)

        elif resource_type in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            findings = analyze_iam_policy_from_resource(resource)
            all_findings.extend(findings)

        elif resource_type == "AWS::S3::Bucket":
            findings = analyze_s3_bucket_from_resource(resource)
            all_findings.extend(findings)

        elif resource_type == "AWS::EC2::SecurityGroup":
            findings = analyze_sg_from_resource(resource)
            all_findings.extend(findings)

        else:
            logger.warning(f"Unknown resource type: {resource_type} (resource: {resource.logical_id})")

    return all_findings
