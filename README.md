# AWS Cloud Security Scanner for Misconfigurations (CSSM)

CSSM is a comprehensive tool for identifying common security misconfigurations in AWS cloud environments. It provides both command-line scanning capabilities and file-based analysis for security auditing and compliance validation.

## What It Detects

CSSM focuses on scanning four major areas of AWS security risk:

### S3 Security Issues
- **Public buckets** (ACL and policy-based exposure)
- **Missing encryption** at rest
- **Disabled versioning** and MFA delete protection
- **Missing access logging** for audit trails
- **Dangerous CORS configurations** with wildcard origins
- **Public website hosting** misconfigurations

### IAM Policy & Role Vulnerabilities  
- **Wildcard permissions** (`"Action": "*"`, `"Resource": "*"`)
- **Privilege escalation** paths (CreateRole + AttachPolicy combinations)
- **Cross-account AssumeRole** with wildcard resources
- **Missing restrictive conditions** on sensitive actions
- **Overpermissive trust policies** allowing broad principal access
- **NotAction/NotResource** misuse leading to unintended access

### IAM User Account Issues
- **High-privilege users without MFA** protection
- **Inactive or unused access keys** (stale credentials)
- **Old access keys** requiring rotation
- **Dormant user accounts** with active credentials

### Security Group Misconfigurations
- **Management ports** (SSH 22, RDP 3389) open to internet
- **Database ports** (MySQL 3306, PostgreSQL 5432) exposed publicly  
- **All ports open** (0-65535 or protocol -1) configurations
- **Cross-account security group** references
- **IPv6 exposure** (`::/0`) equivalent to IPv4 `0.0.0.0/0`

## Sample Output

```json
{
  "iam_policies": [
    {
      "policy_arn": "arn:aws:iam::123456789012:policy/BadPolicy",
      "policy_name": "BadPolicy", 
      "vulnerabilities": [
        {
          "id": "IAM_POLICY_WILDCARD_ALL",
          "description": "Too permissive: Action=\"*\", Resource=\"*\"",
          "severity": "high",
          "remediation": "Avoid using wildcard '*' in both Action and Resource."
        }
      ]
    }
  ],
  "s3_buckets": [
    {
      "bucket_name": "my-public-bucket",
      "vulnerabilities": [
        {
          "id": "S3_PUBLIC_POLICY", 
          "description": "S3 bucket is publicly accessible via bucket policy",
          "severity": "high"
        }
      ]
    }
  ]
}
```

## Installation & Setup

### Prerequisites
- Python 3.8+
- AWS credentials configured (for live scanning)

### Quick Install
```bash
# Clone repository
git clone https://github.com/your-repo/aws-scanner.git
cd aws-scanner

# Create virtual environment  
python -m venv venv
source venv/bin/activate  # Linux/MacOS
# OR
venv\Scripts\activate     # Windows

# Install package
pip install -e .
```

### AWS Credentials Setup
```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1

# Option 2: Create .env file
cat > .env << EOF
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
EOF

# Option 3: Use AWS CLI profiles
aws configure --profile scanner
export AWS_PROFILE=scanner
```

## Usage Examples

### Live AWS Scanning

```bash
# Scan all services (default)
aws-scanner

# Scan specific services
aws-scanner s3                    # S3 buckets only  
aws-scanner iam                   # IAM roles only
aws-scanner iam --policies        # IAM policies only
aws-scanner sg                    # Security groups only

# Multi-region security group scanning
aws-scanner sg --regions us-east-1,us-west-2,eu-west-1

# Custom output location
aws-scanner --output /path/to/custom-report.json

# Generate HTML summary report
aws-scanner --html
```

### Offline File Analysis

```bash
# Analyze local IAM policy files
aws-scanner iam --policies --file examples/iam/policies/wildcard_admin.json

# Analyze S3 configurations  
aws-scanner s3 --file examples/s3/public_s3_bucket.json

# Analyze security group configurations
aws-scanner sg --file examples/sg/open_security_group.json
```

### Docker Usage

```bash
# Build image
docker build -t cssm-scanner .

# Run with AWS credentials
docker run --rm \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_REGION=$AWS_REGION \
  -v $(pwd)/output:/app/output \
  cssm-scanner --output /app/output/docker-report.json
```

## Project Structure

```
aws-scanner/
├── src/aws_scanner/
│   ├── cli/                    # Command-line interface
│   ├── core/                   # Core configurations and utilities
│   ├── engines/                # Analysis engines by service
│   │   ├── iam_policy/         # IAM policy analysis
│   │   ├── iam_role/           # IAM role analysis  
│   │   ├── s3/                 # S3 bucket analysis
│   │   └── sg/                 # Security group analysis
│   ├── reports/                # Report generation
│   └── scanners/               # Service orchestration
├── examples/                   # Test cases and examples
├── tests/                      # Unit and integration tests
└── templates/                  # HTML report templates
```

## Testing & Validation

### Run Test Suite
```bash
# Unit tests
pytest tests/unit_tests/

# Integration tests with examples
pytest tests/integration_tests/

# Test coverage
pytest --cov=aws_scanner tests/
```

### Example Test Cases
The project includes comprehensive test cases in `examples/` covering:
- **Real-world breach scenarios** (Capital One-style misconfigurations)
- **Privilege escalation** attack paths
- **Public exposure** patterns
- **Compliance violations** 

## Detection Coverage

### Critical Severity Issues
- Root user access keys and missing MFA
- All ports open to internet (`0.0.0.0/0`)
- Database ports exposed publicly
- Wildcard IAM permissions (`*:*`)
- Cross-account AssumeRole without conditions

### High Severity Issues  
- S3 buckets publicly accessible
- Management ports (SSH/RDP) open to internet
- Admin users without MFA
- Missing S3 encryption
- Stale user accounts with active credentials

### Medium Severity Issues
- S3 versioning disabled
- Unused access keys
- CORS misconfigurations
- Cross-account security group references
- Policies with weak conditions

## Enterprise Features

- **Compliance Reporting**: Built-in mapping to SOC 2, PCI DSS, HIPAA controls
- **Risk Scoring**: Automated severity assessment and prioritization
- **Batch Processing**: Support for multiple accounts and regions
- **Custom Rules**: Extensible vulnerability detection framework
- **Audit Trails**: Detailed finding context and remediation guidance

### Development Setup
```bash
# Install development dependencies
pip install -e .[dev,test]

# Run linting
ruff check .
```

## Roadmap

See [roadmap.md](roadmap.md) for detailed feature plans including:
- **Advanced detection** for complex attack patterns
- **Infrastructure as Code** support (Terraform, CloudFormation)
- **Web interface** and API endpoints
- **Multi-cloud** expansion (Azure, GCP)
- **AI-powered** risk analysis and remediation suggestions