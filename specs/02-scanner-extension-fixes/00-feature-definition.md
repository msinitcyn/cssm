# Scanner & Extension Reliability Fixes

## Issues to Fix

### Scanner

1. **CloudFormation AWS::S3::BucketPolicy Support**
   - Error: "Unknown resource type: AWS::S3::BucketPolicy"
   - File `examples/cloudformation/vulnerable_stack.yaml` fails

2. **Scanner Crashes on Errors**
   - Uncaught exceptions crash scanner with Python stack traces
   - Exit code non-zero on data errors
   - No graceful error handling

3. **IAM Policies Missing from Scanner Output**
   - Scanner puts both IAM roles and policies in `iam_roles` key
   - No `iam_policies` key exists in output
   - Extension expects policies in `iam_policies` and finds nothing
   - Integration tests validate incorrect behavior (look in `iam_roles` for policies)

### Integration Tests

1. **CloudFormation Test Doesn't Use Common Framework**
   - `test_cloudformation_scanning.py` has hardcoded test logic
   - Duplicates verification code from `test_examples.py`
   - Doesn't use `examples_to_test.json` like other services
   - Makes tests harder to maintain

2. **IAM Policy Tests Validate Incorrect Behavior**
   - Tests look for policies in `iam_roles` key (wrong)
   - Should look in `iam_policies` key (correct)
   - Tests pass while extension fails

### Extension

1. **CloudFormation Support Missing**
   - No command to scan CloudFormation .yaml/.yml files

2. **CloudFormation Result Display**
   - Extension expects specific keys (iam_policies, s3_buckets, etc.)
   - CloudFormation returns mixed resource types

3. **Extension Only Shows One Result Section**
   - Extension uses `getResultKey()` to pick single section based on scan type
   - When scanning IAM policies, only looks in `iam_policies` (which doesn't exist)
   - Should display ALL sections with findings
   - User can't see results even when scanner finds them

## Expected Behavior

### Scanner CLI

Never crashes:
```bash
aws-scanner s3 --file malformed.json
# Exit code: 0
# Returns valid JSON with error details (no Python stack trace)
```

BucketPolicy in CloudFormation templates:
```bash
aws-scanner --cloudformation examples/cloudformation/vulnerable_stack.yaml
# Scans successfully, detects bucket policy vulnerabilities
```

Separate output keys for roles and policies:
```bash
aws-scanner iam --policies --file examples/iam/policies/wildcard_admin.json
# Returns:
# {
#   "iam_roles": [],
#   "iam_policies": [{
#     "policy_name": "BadPolicy",
#     "vulnerabilities": [...]
#   }],
#   "s3_buckets": [],
#   "security_groups": []
# }
```

### Extension

New command available:
- Scan CloudFormation Template

Display all sections with findings:
- Extension shows IAM roles, IAM policies, S3 buckets, and security groups
- Any section with findings is displayed
- User sees all results regardless of which scanner command was used
- Same display logic for all scan commands

Example output when scanning IAM policy:
```
IAM Policies: 1 item(s)
==================================================

1. BadPolicy
   Found 5 security issue(s):
   1. [HIGH] Too permissive: Action="*", Resource="*"
      Fix: Avoid using wildcard '*' in both Action and Resource.
```
