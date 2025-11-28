### Phase 1: Integration Tests

[x] Create example CloudFormation template with vulnerabilities
  - Template with IAM role (wildcard permissions)
  - Template with S3 bucket (public policy)
  - Template with Security Group (open ports)
  - Place in `examples/cloudformation/vulnerable_stack.yaml`

[x] Create integration test for CloudFormation scanning
  - Test file: `tests/integration_tests/test_cloudformation_scanning.py`
  - Scan example template with `--cloudformation` flag
  - Verify IAM vulnerability detected
  - Verify S3 vulnerability detected
  - Verify Security Group vulnerability detected
  - Test will fail - that's expected (TDD)

