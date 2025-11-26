### Phase 7: Deprecation and Cleanup

**Goal**: Remove old data classes and analyzer code that is no longer needed.

[ ] Evaluate files for deletion
  - Checked: All old data classes still used by AWS API collectors
  - Checked: All old analyzers still used by AWS API scanners
  - Checked: All old scanner files still used by CLI for AWS scanning
  - Checked: policy_analyzer_utils.py still used by old analyzers
  - **Decision**: KEEP all old code - AWS API scanning still requires it

[ ] Files KEPT (still needed for AWS API scanning):
  - `src/aws_scanner/engines/iam_role/iam_role_data.py` (IamRoleData)
  - `src/aws_scanner/engines/common/iam_policy_data.py` (IamPolicyData)
  - `src/aws_scanner/engines/s3/s3_bucket_data.py` (S3BucketData)
  - `src/aws_scanner/engines/sg/sg_data.py` (SgData)
  - `src/aws_scanner/engines/iam_role/analyzer.py` (used by iam_role_scanner)
  - `src/aws_scanner/engines/iam_policy/analyzer.py` (used by iam_policy_scanner)
  - `src/aws_scanner/engines/s3/analyzer.py` (used by s3_scanner)
  - `src/aws_scanner/engines/sg/analyzer.py` (used by sg_scanner)
  - `src/aws_scanner/engines/iam_policy/policy_analyzer_utils.py` (used by analyzers)
  - `src/aws_scanner/scanners/iam_role_scanner.py`
  - `src/aws_scanner/scanners/iam_policy_scanner.py`
  - `src/aws_scanner/scanners/s3_scanner.py`
  - `src/aws_scanner/scanners/sg_scanner.py`

[ ] Verify all tests pass
  - Run full test suite: `pytest` ✓
  - 365 unit tests passing
  - 1 integration test passing
  - No regressions
  - All tests green

**Architecture**: CloudFormation scanning uses new resource-based path (ResourceDefinition + resource analyzers), while AWS API scanning continues using existing data class path. Both coexist without conflicts.

---

