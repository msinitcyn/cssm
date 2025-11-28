# Supported Features Specification

**Document Version**: 1.0  
**Last Updated**: 2025-01-20  
**Status**: Active Reference Document

---

## Purpose

This document serves as the authoritative reference for all features currently supported by the AWS Cloud Security Scanner (CSSM). When developing new features or modifications, reference this document to understand backward compatibility requirements.

**Backward Compatibility Policy**: Unless explicitly documented in a feature spec, all new features MUST maintain 100% backward compatibility with the formats and behaviors documented here.

---

## 1. CLI Commands

### 1.1 Global Options

Available for all commands:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output` | Path | `output/report.json` | Path to save JSON report |
| `--html` | Flag | False | Generate HTML summary report alongside JSON |

### 1.2 Service Commands

#### S3 Bucket Scanning
```bash
aws-scanner s3 [--file PATH]
```

**Options:**
- `--file`: Path to local S3 configuration JSON file (offline analysis)

**Behavior:**
- Without `--file`: Scans all S3 buckets in the configured AWS account
- With `--file`: Analyzes the specified local configuration file

#### IAM Scanning
```bash
aws-scanner iam [--policies] [--attached-only] [--file PATH]
```

**Options:**
- `--policies`: Scan only IAM policies (skip role trust policy analysis)
- `--attached-only`: Limit to policies attached to roles (requires `--policies`)
- `--file`: Path to local IAM configuration JSON file

**Behavior:**
- Without flags: Scans IAM roles including trust policies and attached/inline policies
- With `--policies`: Scans IAM policies independently
- With `--attached-only`: Only scans policies that are attached to roles
- With `--file`: Analyzes local configuration file

**Validation:**
- `--attached-only` cannot be used without `--policies` (exit with error)

#### Security Group Scanning
```bash
aws-scanner sg [--regions REGIONS] [--file PATH]
```

**Options:**
- `--regions`: Comma-separated list of AWS regions (e.g., `us-east-1,us-west-2,eu-west-1`)
- `--file`: Path to local Security Group configuration JSON file

**Behavior:**
- Without `--regions`: Scans security groups in the default AWS region
- With `--regions`: Scans across specified regions
- With `--file`: Analyzes local configuration file

---

## 2. Input Sources

### 2.1 AWS Live Scanning

**Requirements:**
- Valid AWS credentials via environment variables, `.env` file, or AWS CLI profile
- Required environment variables:
  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - `AWS_REGION` (optional, defaults to `us-east-1`)
- Alternative: `AWS_PROFILE` pointing to AWS CLI profile

**Supported Resources:**
- S3 buckets (all buckets in account)
- IAM roles (all roles in account)
- IAM policies (all policies in account)
- Security groups (in specified regions)

### 2.2 Local File Analysis

**File Type:** JSON only
**Location:** Any valid file path
**Use Case:** Offline analysis without AWS credentials

---

## 3. Input File Formats

### 3.1 IAM Policy File Format

**Location Pattern**: `examples/iam/policies/*.json`

**Format:**
```json
{
    "name": "PolicyName",
    "resource_type": "iam_policy",
    "policy_type": "attached" | "inline",
    "arn": "arn:aws:iam::123456789012:policy/PolicyName",
    "is_inline": false,
    "document": {
        "Version": "2012-10-17",
        "Statement": [...]
    }
}
```

**Required Fields:**
- `name`: String
- `document`: IAM Policy Document object

**Optional Fields:**
- `resource_type`: String (informational)
- `policy_type`: String ("attached" or "inline")
- `arn`: String (ARN format)
- `is_inline`: Boolean

### 3.2 IAM Role File Format

**Location Pattern**: `examples/iam/roles/*.json`

**Format:**
```json
{
    "role-name": {
        "assume_role_policy_document": {
            "Version": "2012-10-17",
            "Statement": [...]
        },
        "inline_policies": [
            {
                "name": "policy-name",
                "document": {...}
            }
        ],
        "attached_policies": [
            {
                "name": "policy-name"
            }
        ]
    }
}
```

**Structure:**
- Top-level keys: Role names (string)
- Each role contains:

**Required Fields:**
- `assume_role_policy_document`: IAM Policy Document object (trust policy)

**Optional Fields:**
- `inline_policies`: Array of objects
  - Each object has:
    - `name` (required): String
    - `document` (required): IAM Policy Document object
- `attached_policies`: Array of objects
  - Each object has:
    - `name` (required): String
    - `document` (optional): IAM Policy Document object

**Compatibility Notes:**
- Field `trust_policy_document` is supported as alias for `assume_role_policy_document`
- Missing `inline_policies` or `attached_policies` treated as empty arrays

### 3.3 S3 Bucket File Format

**Location Pattern**: `examples/s3/*.json`

**Format:**
```json
{
    "bucket-name": {
        "acl": "public-read" | "public-read-write" | "private" | [...],
        "policy": {
            "Version": "2012-10-17",
            "Statement": [...]
        },
        "public_access_block": {
            "BlockPublicAcls": true,
            "IgnorePublicAcls": true,
            "BlockPublicPolicy": true,
            "RestrictPublicBuckets": true
        },
        "cors_config": {...},
        "website_config": {...},
        "server_access_logging": {...},
        "versioning": {...},
        "encryption": {...},
        "mfa_delete": true
    }
}
```

**Structure:**
- Top-level keys: Bucket names (string)
- Each bucket contains:

**Optional Fields (all):**
- `acl`: String or Array
  - String values: `"public-read"`, `"public-read-write"`, `"private"`
  - Strings are converted to ACL grant objects
  - Array: Direct ACL grants (bypasses conversion)
- `policy`: IAM Policy Document object (bucket policy)
- `public_access_block`: Object with boolean fields
- `pab_config`: Alias for `public_access_block`
- `block_public_access`: Alias for `public_access_block`
- `cors_config`: Object
- `website_config`: Object
- `server_access_logging`: Object
- `versioning`: Object
- `encryption`: Object
- `mfa_delete`: Boolean or String ("Enabled"/"Disabled")

**ACL String Conversion Rules:**
- `"public-read"` → Single READ grant to AllUsers
- `"public-read-write"` → READ and WRITE grants to AllUsers
- `"private"` → Empty grants array
- Unknown values → Empty grants array

**Field Aliases:**
- `public_access_block`, `block_public_access`, `pab_config` are interchangeable

### 3.4 Security Group File Format

**Location Pattern**: `examples/sg/*.json`

**Format:**
```json
{
    "group_id": "sg-12345678",
    "group_name": "security-group-name",
    "vpc_id": "vpc-12345678",
    "owner_id": "123456789012",
    "region": "us-east-1",
    "ingress_rules": [
        {
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": ["::/0"],
            "source_security_group_id": "sg-87654321",
            "description": "Rule description"
        }
    ],
    "egress_rules": [...]
}
```

**Required Fields:**
- `group_id`: String

**Optional Fields:**
- `group_name`: String
- `vpc_id`: String
- `owner_id`: String
- `region`: String
- `ingress_rules`: Array of rule objects
- `ingress_permissions`: Alias for `ingress_rules`
- `egress_rules`: Array of rule objects

**Rule Object Fields (all optional):**
- `protocol`: String (e.g., "tcp", "udp", "-1")
- `from_port`: Integer
- `to_port`: Integer
- `cidr_blocks`: Array of CIDR strings (IPv4)
- `ipv6_cidr_blocks`: Array of CIDR strings (IPv6)
- `source_security_group_id`: String
- `description`: String

**Compatibility Notes:**
- `ingress_permissions` is an alias for `ingress_rules` (legacy support)

---

## 4. Detected Vulnerabilities

### 4.1 IAM Policy Vulnerabilities

| ID | Severity | Description |
|----|----------|-------------|
| `IAM_POLICY_WILDCARD_ALL` | High | Action="*" and Resource="*" |
| `IAM_POLICY_NOTACTION_WILDCARD_RESOURCE` | Medium | NotAction with wildcard Resource |
| `IAM_POLICY_NOTRESOURCE_WILDCARD_ACTION` | Medium | NotResource with wildcard Action |
| `IAM_POLICY_WILDCARD_ACTION_CONDITION` | Medium | Wildcard Action with Condition |
| `IAM_POLICY_NOTACTION_CONDITION` | Medium | NotAction with Condition |
| `IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION` | High | Wildcard without restrictive Condition |
| `IAM_POLICY_PRIVILEGE_ESCALATION` | Critical | Contains privilege escalation permissions |
| `IAM_POLICY_ASSUME_ROLE_WILDCARD` | Critical | sts:AssumeRole on wildcard resources |
| `IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS` | Medium | Sensitive actions without IP/MFA/time conditions |

### 4.2 IAM Role Vulnerabilities

| ID | Severity | Description |
|----|----------|-------------|
| `IAM_ROLE_BROAD_ASSUME_ROLE` | Critical | Trust policy allows Principal='*' or lacks conditions |

### 4.3 IAM User Vulnerabilities

| ID | Severity | Description |
|----|----------|-------------|
| `IAM_USER_NO_MFA_HIGH_PRIVILEGE` | Critical | High-privilege user without MFA |
| `IAM_USER_CONSOLE_ACCESS_NO_MFA` | High | Console access without MFA |
| `IAM_USER_INACTIVE_ACCESS_KEY` | Medium | Access key unused for 90+ days |
| `IAM_USER_UNUSED_ACCESS_KEY` | Medium | Access key never used |
| `IAM_USER_OLD_ACCESS_KEY` | High | Access key older than 365 days |
| `IAM_USER_STALE_ACCOUNT` | High | Account inactive for 365+ days with active credentials |

### 4.4 Root User Vulnerabilities

| ID | Severity | Description |
|----|----------|-------------|
| `IAM_ROOT_USER_ACCESS_KEYS` | Critical | Root user has active access keys |
| `IAM_ROOT_USER_NO_MFA` | Critical | Root user without MFA |

### 4.5 S3 Bucket Vulnerabilities

| ID | Severity | Description |
|----|----------|-------------|
| `S3_PUBLIC_ACL` | High | Bucket publicly accessible via ACL |
| `S3_PUBLIC_POLICY` | High | Bucket publicly accessible via policy |
| `S3_POTENTIALLY_PUBLIC_POLICY_CONDITION` | Medium | Bucket policy with weak Condition |
| `S3_PUBLIC_CORS` | Medium | CORS allows wildcard origin |
| `S3_PUBLIC_WEBSITE` | Medium | Website configuration enabled |
| `S3_NO_ACCESS_LOGGING` | Low | Access logging not enabled |
| `S3_VERSIONING_SUSPENDED` | Medium | Versioning suspended or disabled |
| `S3_NO_ENCRYPTION` | High | Server-side encryption not enabled |
| `S3_MFA_DELETE_DISABLED` | Medium | MFA Delete not enabled |

### 4.6 Security Group Vulnerabilities

| ID | Severity | Description |
|----|----------|-------------|
| `SG_OPEN_PORT` | High | Dangerous ports open to public CIDR |
| `SG_OPEN_MANAGEMENT_PORT` | High | SSH/RDP (22/3389) open to internet |
| `SG_OPEN_DATABASE_PORT` | Critical | Database ports open to internet |
| `SG_ALL_PORTS_OPEN_PUBLIC` | Critical | All ports (0-65535) or all protocols open |
| `CROSS_ACCOUNT_SG_REFERENCE` | Medium | Ingress rule references cross-account group |
| `SG_ALL_PORTS_INTERNAL` | Medium | Port range 0-65535 open internally |

---

## 5. Output Formats

### 5.1 JSON Report Format

**Default Output**: `output/report.json`

**Structure:**
```json
{
    "scan_metadata": {
        "timestamp": "2025-01-20T10:30:00Z",
        "scanner_version": "1.0.0",
        "scan_type": "file" | "aws",
        "regions": ["us-east-1"]
    },
    "iam_roles": [
        {
            "name": "role-name",
            "findings": [
                {
                    "id": "IAM_POLICY_WILDCARD_ALL",
                    "description": "Too permissive: Action=\"*\", Resource=\"*\"",
                    "severity": "high",
                    "entity_type": "iam_policy",
                    "entity_name": "policy-name",
                    "remediation": "Avoid using wildcard '*' in both Action and Resource.",
                    "raw_data": {...}
                }
            ]
        }
    ],
    "iam_policies": [...],
    "s3_buckets": [
        {
            "name": "bucket-name",
            "findings": [...]
        }
    ],
    "security_groups": [
        {
            "group_id": "sg-12345678",
            "group_name": "sg-name",
            "region": "us-east-1",
            "findings": [...]
        }
    ],
    "summary": {
        "total_findings": 42,
        "critical": 5,
        "high": 15,
        "medium": 18,
        "low": 4
    }
}
```

**Finding Object Structure:**
- `id`: String (vulnerability ID)
- `description`: String (human-readable description)
- `severity`: String (`"critical"`, `"high"`, `"medium"`, `"low"`)
- `entity_type`: String (resource type)
- `entity_name`: String (resource identifier)
- `remediation`: String (recommended fix)
- `raw_data`: Object (relevant configuration data)

### 5.2 HTML Report Format

**Enabled with**: `--html` flag
**Output**: Same directory as JSON, with `.html` extension

**Features:**
- Summary dashboard with severity breakdown
- Color-coded severity indicators
- Grouped findings by resource
- Expandable detail sections
- Remediation guidance
- Responsive design

---

## 6. Data Transformations

### 6.1 S3 ACL String to Grants

When processing S3 configurations, ACL strings are converted to grant objects:

**Input:**
```json
{"acl": "public-read"}
```

**Output (internal):**
```json
{
    "AclGrants": [
        {
            "Grantee": {
                "Type": "Group",
                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
            },
            "Permission": "READ"
        }
    ]
}
```

**Conversion Table:**

| Input String | Grants Generated |
|-------------|------------------|
| `"public-read"` | READ to AllUsers |
| `"public-read-write"` | READ and WRITE to AllUsers |
| `"private"` | Empty array |
| Unknown | Empty array |

### 6.2 Field Normalization

Certain fields support multiple names for backward compatibility:

**S3 Buckets:**
- `public_access_block` = `block_public_access` = `pab_config`

**Security Groups:**
- `ingress_rules` = `ingress_permissions`

**IAM Roles:**
- `assume_role_policy_document` = `trust_policy_document`

---

## 7. Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (findings may exist) |
| 1 | CLI usage error or invalid arguments |
| 2 | File not found |
| 3 | AWS credentials error |
| 4 | AWS API error |

**Note:** Finding vulnerabilities is NOT considered an error condition. Exit code 0 is returned even when vulnerabilities are found.

---

## 8. Limitations and Known Behaviors

### 8.1 CloudFormation Support
**Status**: Not yet implemented  
**Expected in**: Milestone 9

### 8.2 Multi-format Input Files
**Status**: JSON only  
**Planned**: YAML support for CloudFormation templates

### 8.3 Region Handling
- S3: Scans all buckets regardless of region (S3 is global)
- IAM: Scans all resources (IAM is global)
- Security Groups: Default region or specified regions only

### 8.4 Resource Limits
- No built-in pagination limits
- Large accounts may experience slower scan times
- File-based analysis has no resource limits

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-20 | Initial specification document |

---

## Usage in Feature Development

When creating new feature specifications:

1. **Check Compatibility**: Review this document to understand current behavior
2. **Document Changes**: If breaking compatibility, explicitly state what changes
3. **Reference This Spec**: Link to specific sections when discussing compatibility
4. **Update This Spec**: When feature is complete, update this document

**Example Reference in Feature Spec:**
```markdown
**Backward Compatibility**: This feature maintains 100% compatibility 
with S3 input file format as specified in supported-features.md §3.3.
```

Or for breaking changes:
```markdown
**Breaking Change**: This feature deprecates the `trust_policy_document` 
field alias (supported-features.md §3.2) in favor of standard 
`assume_role_policy_document` only. Migration guide provided in §5.
```