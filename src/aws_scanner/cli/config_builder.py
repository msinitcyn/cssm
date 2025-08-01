from typing import Optional
from aws_scanner.core.configs import RunConfig, S3Config, IamRoleConfig, IamPolicyConfig, SgConfig, ReportConfig

def create_run_config(args) -> RunConfig:
    return RunConfig(
        s3=build_s3_config(args),
        iam_role=build_iam_role_config(args),
        iam_policy=build_iam_policy_config(args),
        sg=build_sg_config(args),
        report=build_report_config(args)
    )

def build_s3_config(args) -> Optional[S3Config]:
    if args.command not in (None, "s3"):
        return None
    return S3Config(file=getattr(args, "file", None))

def build_iam_role_config(args) -> Optional[IamRoleConfig]:
    if args.command not in (None, "iam") or hasattr(args, "policies_only") and args.policies_only:
        return None

    attached_only = getattr(args, 'attached_only', False)
    if attached_only:
        raise ValueError("--attached-only can only be used with --policies-only")

    return IamRoleConfig(file=getattr(args, "file", None))

def build_iam_policy_config(args) -> Optional[IamPolicyConfig]:
    if args.command not in (None, "iam") or not hasattr(args, "policies_only") or not args.policies_only:
        return None

    attached_only = getattr(args, 'attached_only', False)

    return IamPolicyConfig(
        attached_only=attached_only,
        file=getattr(args, "file", None)
    )

def build_sg_config(args) -> Optional[SgConfig]:
    if args.command not in (None, "sg"):
        return None

    regions = getattr(args, 'regions', None)
    regions = regions.split(",") if regions else None

    return SgConfig(
        regions=regions,
        file=getattr(args, "file", None)
    )

def build_report_config(args) -> ReportConfig:
    return ReportConfig(
        path=args.output.resolve(),
        html=args.html
    )
