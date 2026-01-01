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

2. **CloudFormation Result Display**
   - Extension expects specific keys (iam_policies, s3_buckets, etc.)
   - CloudFormation returns mixed resource types

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
