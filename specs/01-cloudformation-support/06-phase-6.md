### Phase 6: Wire Resource Orchestrator into All Scanners

**Goal**: Use `resource_orchestrator.analyze_resources()` universally for all file-based and CloudFormation scanning.

**Architecture**:
```
CLI → pick_collector(config) → ResourceCollection → resource_orchestrator.analyze_resources() → format_results() → generate_report()
```

**Current State**:
- `resource_orchestrator.analyze_resources()` exists but is UNUSED
- `cloudformation_scanner.py` manually loops instead of using orchestrator
- Individual scanners (`iam_policy_scanner.py`, etc.) use old path: `Old collectors → List[DataClass] → old analyzers`

**Target State**:
- All file-based scanning uses: `Resource collectors → ResourceCollection → resource_orchestrator`
- CloudFormation scanning uses orchestrator properly
- AWS API scanning degraded temporarily (will restore with AWS Resource collectors in future phase)

**Note**: AWS API scanning will be temporarily broken. Will restore with AWS Resource collectors in future.

---

#### 6.1 Wire Orchestrator into CloudFormation Scanner

[x] Write unit tests for cloudformation_scanner using orchestrator
  - Test file: `tests/unit_tests/engines/cloudformation/test_cloudformation_scanner.py`
  - Test `scan_cloudformation_template()` uses CloudFormationReader
  - Test calls `resource_orchestrator.analyze_resources(collection)`
  - Test extracts inline IAM policies from roles and adds to collection
  - Test handles S3 bucket policies
  - Test formats results by resource type (iam_roles, s3_buckets, security_groups)
  - Test backward compatibility: same vulnerabilities detected
  - All tests should FAIL initially (TDD)

[x] Refactor cloudformation_scanner to use orchestrator
  - File: `src/aws_scanner/engines/cloudformation/cloudformation_scanner.py`
  - Step 1: Use CloudFormationReader → ResourceCollection
  - Step 2: Extract inline policies from IAM roles, add to collection
  - Step 3: Handle S3 bucket policies, add to collection
  - Step 4: Call `resource_orchestrator.analyze_resources(collection)` → flat findings list
  - Step 5: Group findings by resource type for reporter
  - Remove manual looping through resources
  - Make all tests pass

---

#### 6.2 Create Result Formatter

[x] Write unit tests for result formatter
  - Test file: `tests/unit_tests/core/test_result_formatter.py`
  - Test `format_results(findings: List[Dict]) → Dict[str, List]`
  - Test groups findings by entity_type (iam_role, s3_bucket, security_group)
  - Test creates structure: `{"iam_roles": [...], "s3_buckets": [...], "security_groups": [...]}`
  - Test groups findings per entity (by entity_name)
  - Test handles empty findings list
  - Test handles unknown entity types
  - All tests should FAIL initially (TDD)

[x] Implement result formatter
  - New file: `src/aws_scanner/core/result_formatter.py`
  - Create `format_results(findings: List[Dict[str, Any]]) → Dict[str, List]`
  - Read `entity_type` from each finding
  - Read `entity_name` from each finding
  - Group by entity_type: iam_role → iam_roles, s3_bucket → s3_buckets, security_group → security_groups
  - Within each type, group findings by entity_name
  - Return formatted results dict
  - Make all tests pass

---

#### 6.3 Update scan_orchestrator to Use New Pattern

[x] Write unit tests for updated scan_orchestrator
  - Test file: `tests/unit_tests/scanners/test_scan_orchestrator_unified.py`
  - Test CloudFormation path: CloudFormationReader → resource_orchestrator → format_results
  - Test IAM policy file path: ResourceFileIamPolicyCollector → resource_orchestrator → format_results
  - Test IAM role file path: ResourceFileIamRoleCollector → resource_orchestrator → format_results
  - Test S3 file path: ResourceFileS3Collector → resource_orchestrator → format_results
  - Test SG file path: ResourceFileSgCollector → resource_orchestrator → format_results
  - Test AWS API paths raise NotImplementedError (temporarily degraded)
  - All tests should FAIL initially (TDD)

[x] Implement unified scan_orchestrator
  - File: `src/aws_scanner/scanners/scan_orchestrator.py`
  - Add helper `get_collector(config)`:
    - If cloudformation: return CloudFormationReader(config.cloudformation.file)
    - If iam_policy + file: return ResourceFileIamPolicyCollector(config.iam_policy.file)
    - If iam_role + file: return ResourceFileIamRoleCollector(config.iam_role.file)
    - If s3 + file: return ResourceFileS3Collector(config.s3.file)
    - If sg + file: return ResourceFileSgCollector(config.sg.file)
    - If AWS API (no file): raise NotImplementedError("AWS API scanning not yet migrated to resource path")
  - Update `run_scan()`:
    - Call `collector = get_collector(config)`
    - Call `collection = collector.collect()` or `collector.read()`
    - Call `findings = resource_orchestrator.analyze_resources(collection)`
    - Call `results = result_formatter.format_results(findings)`
    - Call `generate_report(config.report, results)`
  - Make all tests pass

---

#### 6.4 Verify All File-Based Scanning Works

[x] Run full test suite
  - Run: `pytest tests/unit_tests/`
  - Run: `pytest tests/integration_tests/test_cloudformation_scanning.py`
  - All tests should pass

[ ] Test file-based scanning manually
  - Test: `cssm --cloudformation examples/cloudformation/vulnerable_stack.yaml`
  - Test: `cssm iam --policies --file examples/iam/policies/wildcard_admin.json`
  - Test: `cssm iam --roles --file examples/iam/roles/overprivileged_role.json`
  - Test: `cssm s3 --file examples/s3/public_s3_bucket.json`
  - Verify same vulnerabilities detected as before

[ ] Verify AWS API scanning shows proper error
  - Test: `cssm iam --policies` (no --file flag)
  - Should show: "AWS API scanning not yet migrated to resource path" error
  - This is acceptable temporary degradation
