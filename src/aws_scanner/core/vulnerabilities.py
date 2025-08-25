from dataclasses import dataclass
from typing import Optional, Dict

@dataclass
class VulnerabilityTemplate:
    id: str
    description: str
    severity: str
    entity_type: str
    remediation: Optional[str] = None

    def instantiate(self, entity_name: str, raw_data: Optional[dict] = None):
        return {
            "id": self.id,
            "description": self.description,
            "severity": self.severity,
            "entity_type": self.entity_type,
            "entity_name": entity_name,
            "remediation": self.remediation,
            "raw_data": raw_data,
        }

VULNERABILITIES: Dict[str, VulnerabilityTemplate] = {
    "IAM_POLICY_WILDCARD_ALL": VulnerabilityTemplate(
        id="IAM_POLICY_WILDCARD_ALL",
        description='Too permissive: Action="*", Resource="*"',
        severity="high",
        entity_type="iam_policy",
        remediation="Avoid using wildcard '*' in both Action and Resource."
    ),
    "IAM_POLICY_NOTACTION_WILDCARD_RESOURCE": VulnerabilityTemplate(
        id="IAM_POLICY_NOTACTION_WILDCARD_RESOURCE",
        description="NotAction + wildcard Resource can lead to broad access",
        severity="medium",
        entity_type="iam_policy",
    ),
    "IAM_POLICY_NOTRESOURCE_WILDCARD_ACTION": VulnerabilityTemplate(
        id="IAM_POLICY_NOTRESOURCE_WILDCARD_ACTION",
        description="NotResource + wildcard Action can lead to broad access",
        severity="medium",
        entity_type="iam_policy",
        remediation="Avoid using NotResource with wildcard Action. Specify resources explicitly."
    ),
    "IAM_POLICY_WILDCARD_ACTION_CONDITION": VulnerabilityTemplate(
        id="IAM_POLICY_WILDCARD_ACTION_CONDITION",
        description="Wildcard Action + Condition — risky if Condition is weak",
        severity="medium",
        entity_type="iam_policy",
        remediation="Restrict wildcard actions or strengthen the Condition."
    ),
    "IAM_POLICY_NOTACTION_CONDITION": VulnerabilityTemplate(
        id="IAM_POLICY_NOTACTION_CONDITION",
        description="NotAction + Condition — risky if exclusions are narrow",
        severity="medium",
        entity_type="iam_policy",
        remediation="Broaden exclusions or avoid NotAction with weak Condition."
    ),
    "IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION": VulnerabilityTemplate(
        id="IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION",
        description="Wildcard access without restrictive Condition — access may be too broad",
        severity="high",
        entity_type="iam_policy",
        remediation="Add restrictive Condition such as SourceIp or avoid wildcards."
    ),
    "IAM_POLICY_PRIVILEGE_ESCALATION": VulnerabilityTemplate(
        id="IAM_POLICY_PRIVILEGE_ESCALATION",
        description="Policy contains privilege escalation permissions",
        severity="critical",
        entity_type="iam_policy",
        remediation="Restrict IAM permissions or add conditions to prevent privilege escalation."
    ),
    "IAM_POLICY_ASSUME_ROLE_WILDCARD": VulnerabilityTemplate(
        id="IAM_POLICY_ASSUME_ROLE_WILDCARD",
        description="Policy allows sts:AssumeRole on wildcard resources — can assume any role in any account",
        severity="critical",
        entity_type="iam_policy",
        remediation="Restrict Resource to specific role ARNs or add restrictive conditions like aws:RequestedRegion."
    ),
    "IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS": VulnerabilityTemplate(
        id="IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS",
        description="Policy allows sensitive actions without restrictive conditions — access should be limited by IP, MFA, time, or other constraints",
        severity="medium",
        entity_type="iam_policy",
        remediation="Add restrictive conditions such as aws:SourceIp, aws:MultiFactorAuthPresent, or aws:RequestedRegion to limit access."
    ),
    "IAM_ROLE_BROAD_ASSUME_ROLE": VulnerabilityTemplate(
        id="IAM_ROLE_BROAD_ASSUME_ROLE",
        description="IAM Role trust policy allows sts:AssumeRole to Principal='*' or without restrictive conditions — critical lateral movement risk",
        severity="critical",
        entity_type="iam_role",
        remediation="Restrict Principal in trust policy and add Condition to limit AssumeRole access."
    ),
    "S3_PUBLIC_ACL": VulnerabilityTemplate(
        id="S3_PUBLIC_ACL",
        description="S3 bucket is publicly accessible via ACL.",
        severity="high",
        entity_type="s3_bucket",
        remediation="Remove public grants from the bucket ACL."
    ),
    "S3_PUBLIC_POLICY": VulnerabilityTemplate(
        id="S3_PUBLIC_POLICY",
        description="S3 bucket is publicly accessible via bucket policy.",
        severity="high",
        entity_type="s3_bucket",
        remediation="Restrict bucket policy to avoid public access."
    ),
    "S3_POTENTIALLY_PUBLIC_POLICY_CONDITION": VulnerabilityTemplate(
        id="S3_POTENTIALLY_PUBLIC_POLICY_CONDITION",
        description="S3 bucket policy allows access with weak or non-restrictive Condition.",
        severity="medium",
        entity_type="s3_bucket",
        remediation="Strengthen the Condition or restrict access further."
    ),
    "S3_PUBLIC_CORS": VulnerabilityTemplate(
        id="S3_PUBLIC_CORS",
        description="S3 bucket CORS configuration allows any origin (wildcard).",
        severity="medium",
        entity_type="s3_bucket",
        remediation="Restrict AllowedOrigins in CORS configuration."
    ),
    "S3_PUBLIC_WEBSITE": VulnerabilityTemplate(
        id="S3_PUBLIC_WEBSITE",
        description="S3 bucket is publicly accessible via website configuration.",
        severity="medium",
        entity_type="s3_bucket",
        remediation="Restrict website configuration or disable if not needed."
    ),
    "SG_OPEN_PORT": VulnerabilityTemplate(
        id="SG_OPEN_PORT",
        description="Security Group allows access to dangerous or all ports from open CIDR",
        severity="high",
        entity_type="security_group",
        remediation="Restrict access by CIDR and port range"
    ),
    "CROSS_ACCOUNT_SG_REFERENCE": VulnerabilityTemplate(
        id="CROSS_ACCOUNT_SG_REFERENCE",
        description="Ingress rule references a group from another AWS account",
        severity="medium",
        entity_type="security_group",
        remediation="Review trust boundary and intended access"
    ),
    "SG_ALL_PORTS_INTERNAL": VulnerabilityTemplate(
        id="SG_ALL_PORTS_INTERNAL",
        description="Security Group allows port range 0–65535 internally or to non-public CIDRs",
        severity="medium",
        entity_type="security_group",
        remediation="Restrict port ranges or split rules by protocol/port for better boundary control"
    ),
}