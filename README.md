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
python -m aws_scanner.cli.main [COMMAND] [OPTIONS]
```

### Commands

| Flag    | Description                                       | Options                                   |
|---------|---------------------------------------------------|-------------------------------------------|
| `s3`    | Scan only S3 buckets                              |                                           |
| `iam`   | Scan only IAM roles                               |                                           |
| `sg`    | Scan only security groups                         | `--regions` - Comma-separated AWS regions |
| (none)  | Run all scanners (default if no flag is provided) |                                           |

### Global Options

| Flag       | Description                                                  |
|------------|--------------------------------------------------------------|
| `--output` | Path to save the JSON report (default: `output/report.json`) |
| `--html`   | Generate HTML summary report in addition to JSON             |

### Examples

Run all scanners (default behavior):

```bash
python -m aws_scanner.cli.main
```

Run only the S3 scanner:
```bash
python -m aws_scanner.cli.main s3
```

Scan IAM roles and write results to a custom file:
```bash
python -m aws_scanner.cli.main --output results/iam_report.json iam
```

Scan security groups in specific regions:
```bash
python -m aws_scanner.cli.main sg --regions us-east-1,eu-west-1
```

Generate HTML report along with JSON:
```bash
python -m aws_scanner.cli.main --html
```

Scan security groups and generate HTML report:
```bash
python -m aws_scanner.cli.main --html sg
```

## Output

The scanner generates:
1. JSON report with detailed findings
2. Optional HTML summary (when using `--html` flag)

## Local Development Setup

### Prerequisites
- Python 3.8+
- pip
- AWS credentials configured (~/.aws/credentials or environment variables)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-repo/aws-scanner.git
cd aws-scanner
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/MacOS
# OR
venv\Scripts\activate    # Windows
```

3. Install dependencies using `pyproject.toml`:
```bash
pip install -e .
```

4. Configure AWS credentials:
* Create `.env` file in project root:
```bash
touch .env
```

* Add your AWS credentials to `.env`:
```ini
AWS_REGION=your_region (e.g. us-east-1)
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
```

* Load environment variables before running:
```bash
source .env
```

* (Optional) Add `.env` to `.gitignore`:
```bash
echo ".env" >> .gitignore
```

### Running in Development Mode
After installation, the package will be available in editable mode. You can run:
```bash
aws-scanner [COMMAND] [OPTIONS]
```
Or via module:
```bash
python -m aws_scanner.cli.main [COMMAND] [OPTIONS]
```

### Testing
Run tests with:
```bash
pytest tests/
```