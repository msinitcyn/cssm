from typing import Optional
from aws_scanner.core.configs import RunConfig, S3Config, IamConfig, SgConfig, ReportConfig

def create_run_config(args) -> RunConfig:
    return RunConfig(
        s3 = build_s3_config(args),
        iam = build_iam_config(args),
        sg = build_sg_config(args),
        report = build_report_config(args)
    )

def build_s3_config(args) -> Optional[S3Config]:
    return S3Config() if args.command in (None, "s3") else None

def build_iam_config(args) -> Optional[IamConfig]:
    return IamConfig() if args.command in (None, "iam") else None

def build_sg_config(args) -> Optional[SgConfig]:
    if args.command not in (None, "sg"):
        return None
    regions = getattr(args, 'regions', None)
    regions = regions.split(",") if regions else None
    return SgConfig(regions=regions)

def build_report_config(args) -> ReportConfig:
    return ReportConfig(
        path = args.output.resolve(),
        html = args.html
    )