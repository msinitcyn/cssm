# Cloud Security Scanner for Misconfigurations (CSSM)

CSSM is a tool for identifying common security misconfigurations in AWS cloud environments.

It focuses on scanning three major areas of risk:

- Publicly exposed S3 buckets
- IAM roles with overly permissive policies
- Security Groups with dangerously open ports

The goal is to quickly detect high-risk settings that frequently lead to data leaks and unauthorized access, especially in manually configured or poorly audited environments.

## Scanners

### S3 Scanner (`s3_scanner.py`)
- Detects S3 buckets that are publicly accessible.
- Evaluates:
  - Bucket ACLs (grants to `AllUsers`)
  - Bucket policies (explicit "Allow" with wildcard principals)
  - Public Access Block settings

### IAM Scanner (`iam_scanner.py`)
- Identifies IAM roles that have dangerously permissive policies.
- Flags:
  - Inline or attached policies that allow `"Action": "*"` and `"Resource": "*"`
- Handles and reports inaccessible roles gracefully.

### Security Group Scanner (`sg_scanner.py`)
- Scans for security groups exposing sensitive ports to the entire internet (`0.0.0.0/0`).
- Focuses on common attack vectors:
  - SSH (`22`), RDP (`3389`), MySQL (`3306`), PostgreSQL (`5432`), HTTP/HTTPS (`80`, `443`)
- Planned improvements:
  - IPv6 support (`::/0`)
  - Port range analysis
  - Cross-account access checks

## Usage

Run the scanner from the project root using Python:

```bash
python -m aws_scanner.main [OPTION]
```
**Options**

| Flag         | Description                                                           |
|--------------|-----------------------------------------------------------------------|
| `--s3-only`  | Scan only S3 buckets                                                  |
| `--iam-only` | Scan only IAM roles                                                   |
| `--sg-only`  | Scan only security groups                                             |
| `--all`      | Run all scanners (default if no flag is provided)                     |
| `--output`   | Path to save the JSON report (default: `output/report.json`)          |

### Examples

Run all scanners (default behavior):

```bash
python -m aws_scanner.main
```

Run only the S3 scanner:
```bash
python -m aws_scanner.main --s3-only
```

Scan IAM roles and write results to a custom file:
```bash
python -m aws_scanner.main --iam-only --output results/iam_report.json
```

Scan security groups only:
```bash
python -m aws_scanner.main --sg-only
```