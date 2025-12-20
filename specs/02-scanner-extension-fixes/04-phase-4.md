# Phase 4: Example Validation

**Status**: Not started

---

## Checklist

[ ] Create test matrix for all examples
  - List all files in examples/
  - Map each file to correct command
  - Document expected results

[ ] Test each example file with extension
  - IAM policies: Use "Scan IAM Policy" command
  - IAM roles: Use "Scan IAM Role" command
  - S3 buckets: Use "Scan S3" command
  - Security groups: Use "Scan Security Group" command
  - CloudFormation: Use "Scan CloudFormation" command

[ ] Document test results
  - Record which files work
  - Record any errors or issues
  - Capture screenshots of results

[ ] Fix any discovered issues
  - Update collectors if format issues found
  - Update extension if display issues found
  - Add tests for edge cases

[ ] Create extension usage guide
  - Document which command for which file type
  - Add example workflows
  - Include troubleshooting tips

---

## Test Matrix Template

| File | Command | Expected Findings | Status | Notes |
|------|---------|-------------------|--------|-------|
| examples/iam/policies/assume_role_wildcard.json | Scan IAM Policy | IAM_POLICY_ASSUME_ROLE_WILDCARD | ⏳ | |
| examples/iam/roles/broad_trust_policy.json | Scan IAM Role | IAM_ROLE_BROAD_ASSUME_ROLE | ⏳ | |
| examples/s3/public_bucket.json | Scan S3 | S3_PUBLIC_POLICY | ⏳ | |
| examples/sg/open_ssh.json | Scan Security Group | SG_OPEN_MANAGEMENT_PORT | ⏳ | |
| examples/cloudformation/vulnerable_stack.yaml | Scan CloudFormation | Multiple findings | ⏳ | |

---

## Validation Script

Create automated test script:
```bash
#!/bin/bash
# Test all examples with scanner CLI

for file in examples/iam/policies/*.json; do
  echo "Testing: $file"
  python -m aws_scanner.cli.main iam --policies --file "$file"
done

for file in examples/iam/roles/*.json; do
  echo "Testing: $file"
  python -m aws_scanner.cli.main iam --file "$file"
done

# ... etc for other types
```

---

## Files to Create

- `docs/extension-usage-guide.md`
- `scripts/test-all-examples.sh`
- `specs/02-scanner-extension-fixes/test-results.md`

---

## Acceptance Criteria

- All example files scan successfully
- No crashes or stack traces
- Results match expected vulnerabilities
- Extension UI shows findings clearly
- Documentation complete
