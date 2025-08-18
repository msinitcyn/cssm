# Project Roadmap

## Milestone 1: MVP+
[x] CLI with argparse flags (--s3-only, --iam-only, --sg-only, --all)<br>
[x] Logging and critical error handling<br>
[x] --output path support<br>
[x] SG: IPv6 and port range awareness<br>
[x] S3: advanced policy checks (ACL, policy, PAB)<br>

## Milestone 2: DevOps basics
[x] .env support, AWS_PROFILE loading<br>
[x] Dockerfile for containerized runs<br>
[x] GitHub Actions CI (pytest, Docker build)<br>

## Milestone 3: Risk model improvements
[x] Risk level scoring<br>
[x] Multiple access vectors<br>
[x] HTML summary report<br>

## Milestone 4: IAM logic depth
[x] Support for NotAction / NotResource<br>
[x] Detect Condition blocks<br>
[x] Flag broad AssumeRole permissions<br>

## Milestone 5: SG and networking logic
[x] Detect cross-account SG rules<br>
[x] Warn on port range 0–65535<br>
[x] Multi-region SG scan (optional)<br>

## Milestone 6: S3 context awareness
[x] Detect CORS config with wildcard origins<br>
[x] Detect website hosting config<br>
[x] Standalone CLI for local IAM policy analysis<br>
[ ] Rule-based risk evaluation for S3<br>

## Milestone 7: Validation & Test Coverage
[ ] Create comprehensive test case suite:<br>
    - IAM: wildcard policies, broad assume role permissions, missing conditions<br>
    - S3: public buckets, dangerous CORS configs, website hosting enabled<br>
[ ] Test against known security incidents (Capital One breach, etc.)<br>
[ ] False positive detection - verify good configs are NOT flagged<br>
[ ] Document test results and detection accuracy metrics<br>
[ ] Create test runner with pass/fail reporting<br>
[ ] Generate HTML reports for each example in CI build for demo purposes<br>

## Milestone 8: IDE and GitHub integration
[ ] VSCode extension with inline highlights for risky configurations<br>
[ ] GitHub Bot for PR comments on risky policies<br>
[ ] Integration with popular file types (Terraform .tf files, CloudFormation .yaml)<br>

---

# Feature Descriptions

## Completed Features

### CLI with argparse flags
Allow selecting which services to scan via flags: `--s3-only`, `--iam-only`, `--sg-only`, `--all`. Enables scripting and automation.

### Logging and critical error handling
Log warnings, errors, and AWS exceptions clearly. Exit with failure on missing credentials, unreachable regions, etc.

### --output path support
Allow user to specify JSON report output path via `--output /path/to/file.json`.

### SG: IPv6 and port range awareness
Detect rules like `::/0` and port ranges (`FromPort=0, ToPort=65535`). These are commonly overlooked misconfigurations.

### S3: advanced policy checks
Analyze both ACL and bucket policy, including cases with conditions or partial wildcard access. Respect PublicAccessBlock configuration.

### .env support, AWS_PROFILE loading
Load AWS credentials and region config from `.env` or environment vars. Allow devs to avoid setting credentials globally.

### Dockerfile for containerized runs
Provide a lightweight image for reproducible usage and CI/CD. Include necessary Python deps and entrypoint.

### GitHub Actions CI
Run tests, and build Docker image in GitHub Actions pipeline on push / PR.

### Risk level scoring
Assign severity levels (e.g., `high`, `medium`, `low`) to findings based on exposure and impact. Example: public S3 + wildcard CORS = high.

### Multiple access vectors
Report when both ACL and policy allow access. Instead of `access_vector: "ACL"`, use `["ACL", "Policy"]`.

### HTML summary report
Generate optional human-readable `.html` report alongside `.json`, highlighting key risks for sharing or internal reviews.

### Support for NotAction / NotResource
Properly analyze IAM policies that use exclusions like `"NotAction": "iam:DeleteRole"`. These can lead to overbroad access.

### Detect Condition blocks
Detect if a policy lacks restrictive `Condition`, e.g., IP or VPC source restriction. Warn if overbroad.

### Flag broad AssumeRole permissions
Warn on IAM roles that allow `sts:AssumeRole` to `Principal: *`, or with no condition. These are critical lateral movement risks.

### Detect cross-account SG rules
Identify SG ingress rules referencing groups in another AWS account via `UserIdGroupPairs`. Potential hidden trust boundaries.

### Warn on port range 0–65535
SG rule like `FromPort=0` to `ToPort=65535` should raise a warning, even if not to 0.0.0.0/0. Signals poor boundary control.

### Multi-region SG scan (optional)
Allow scanning of SGs in all enabled regions. Currently skipped, but may help teams with global infra.

### Detect CORS config with wildcard origins
If S3 bucket has CORS config allowing `*` origin or all headers/methods, flag it. Especially dangerous when combined with public policy.

### Detect website hosting config
Flag if `WebsiteConfiguration` is enabled on an S3 bucket. Increases attack surface.

### Standalone CLI for local IAM policy analysis
A script that accepts local JSON IAM policy and runs analysis without needing AWS credentials.

## Upcoming Features

### Rule-based risk evaluation for S3
Combine ACL + policy + CORS + website flags to assign a single risk label. Example: "public read via ACL and wildcard CORS".

### Validation & Test Coverage Features
Create comprehensive test suites to validate detection accuracy and reduce false positives. Include real-world incident test cases.

### VSCode extension
Highlight dangerous IAM actions, wildcard resources, or insecure SG blocks inline in code editor during development.

### GitHub Bot for PR comments
Automatically post inline comments on PRs that introduce insecure IAM policies or SG rules. Based on scanning changed files.