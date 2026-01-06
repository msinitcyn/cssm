### Stage 9 (Tests): IAM Policies Separate Output

**Goal**: Write tests that verify IAM policies appear in `iam_policies` key, not `iam_roles`.

#### Checklist

[x] Update integration test expectations
  - File: `tests/integration_tests/test_examples.py`
  - Tests should look for policies in `iam_policies` key
  - Tests should look for roles in `iam_roles` key
  - Update assertions to check correct keys

[x] Add test for policy output structure
  - Verify policy output has `policy_name` field
  - Verify policy output has `policy_arn` field
  - Verify policy output has `vulnerabilities` array

[x] Tests should fail initially
  - Scanner currently returns policies in `iam_roles`
  - Tests verify correct behavior (will fail until implementation)
