# Scanner & Extension Reliability Fixes

## Issues to Fix

### Scanner

1. **CloudFormation AWS::S3::BucketPolicy Support**
   - Error: "Unknown resource type: AWS::S3::BucketPolicy"
   - File `examples/cloudformation/vulnerable_stack.yaml` fails

2. **Error Messages for Malformed Files**
   - Cryptic errors on malformed JSON/YAML
   - Need clear messages with file path and problem description

### Extension

1. **CloudFormation Support Missing**
   - No command to scan CloudFormation .yaml/.yml files

2. **Platform-Specific Binary**
   - Hardcoded `aws-scanner-linux` (line 28 in extension.ts)

3. **CloudFormation Result Display**
   - Extension expects specific keys (iam_policies, s3_buckets, etc.)
   - CloudFormation returns mixed resource types

---

## Implementation Stages

### Stage 1 (Tests): CloudFormation BucketPolicy Support
- CloudFormation files with AWS::S3::BucketPolicy scan successfully
- Bucket policies extracted and analyzed
- Vulnerabilities in bucket policies detected

### Stage 2 (Implementation): Add BucketPolicy Scanner
- Add AWS::S3::BucketPolicy to CloudFormation resource mapping
- Extract bucket policy from resource properties
- Analyze policy for vulnerabilities

### Stage 3 (Tests): Error Handling
- Malformed JSON produces clear error message
- Malformed YAML produces clear error message
- Error messages include file path

### Stage 4 (Implementation): Improve Error Messages
- Validate file format before parsing
- Catch parse errors with clear messages
- Include file path in error context

### Stage 5 (Tests): Extension CloudFormation Support
- Command registered: `aws-scanner.scanCloudFormation`
- Calls scanner with correct `--cloudformation` flag
- Displays mixed resource types correctly

### Stage 6 (Implementation): Add Extension CloudFormation Command
- Register CloudFormation scan command
- Use `--cloudformation` flag
- Parse and display mixed results (IAM/S3/SG from single template)

---

## Expected Behavior

### Scanner CLI

BucketPolicy in CloudFormation templates:
```bash
aws-scanner --cloudformation examples/cloudformation/vulnerable_stack.yaml
# Scans successfully, detects bucket policy vulnerabilities
```

Clear error messages:
```bash
aws-scanner iam --file malformed.json
# Error: Invalid JSON in file 'malformed.json' at line 3, position 42
```

### Extension

New command available:
- **Scan CloudFormation Template**

CloudFormation results show all resource types found in template with their findings.
