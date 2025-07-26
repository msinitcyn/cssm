from dataclasses import dataclass
from pathlib import Path

@dataclass
class IamPolicyConfig:
    attached_only: bool = False

@dataclass
class IamRoleConfig:
    pass

@dataclass
class S3Config:
    pass

@dataclass
class SgConfig:
    regions: list[str] | None

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
    report: ReportConfig