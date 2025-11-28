from dataclasses import dataclass
from pathlib import Path
from typing import Optional

@dataclass
class IamPolicyConfig:
    attached_only: bool
    file: Optional[str] = None

@dataclass
class IamRoleConfig:
    file: Optional[str] = None

@dataclass
class S3Config:
    file: Optional[str] = None

@dataclass
class SgConfig:
    regions: list[str] | None
    file: Optional[str] = None

@dataclass
class CloudFormationConfig:
    file: str

@dataclass
class ReportConfig:
    path: Path = Path("output/report.json")
    html: bool = False

@dataclass
class RunConfig:
    s3: S3Config | None
    iam_role: IamRoleConfig | None
    iam_policy: IamPolicyConfig | None
    sg: SgConfig | None
    cloudformation: CloudFormationConfig | None
    report: ReportConfig