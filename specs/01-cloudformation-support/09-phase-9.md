### Phase 9: Unify CloudFormation into General Collector Pattern

**Goal**: Eliminate special-case CloudFormation handling in scan_orchestrator by creating a CloudFormation file collector.

**Current State**:
```python
def run_scan(run_config: RunConfig):
    if run_config.cloudformation:
        results = scan_cloudformation_template(...)  # Special path
    else:
        collector = _get_collector(...)              # General path
```

**Target State**:
```python
def run_scan(run_config: RunConfig):
    collector = _get_collector(run_config, boto3_wrapper)  # Unified path
    collection = collector.collect()
    findings = resource_orchestrator.analyze_resources(collection)
    results = format_results(findings)
```

---

#### 9.1 Create ResourceFileCloudFormationCollector

[x] Write unit tests for ResourceFileCloudFormationCollector
  - Test file: `tests/unit_tests/engines/cloudformation/test_resource_file_cloudformation_collector.py`
  - Test `collect()` returns ResourceCollection ✓
  - Test YAML template parsing ✓
  - Test JSON template parsing ✓
  - Test Resources section extraction ✓
  - Test inline IAM policies are extracted as separate ResourceDefinitions ✓
  - Test S3 bucket policies are extracted as separate ResourceDefinitions ✓
  - Test handles file not found error ✓
  - Test handles invalid YAML/JSON ✓
  - Test handles templates with no Resources section ✓
  - Test handles CloudFormation intrinsic functions ✓
  - Test backward compatibility with existing CloudFormation examples ✓
  - All tests FAILED initially (TDD) ✓

[x] Implement ResourceFileCloudFormationCollector
  - New file: `src/aws_scanner/engines/cloudformation/resource_file_cloudformation_collector.py` ✓
  - Create `ResourceFileCloudFormationCollector(file_path)` ✓
  - Implement `collect() -> ResourceCollection` ✓
  - Use existing cloudformation_reader logic internally ✓
  - Extract all resources from template as ResourceDefinitions ✓
  - Handle inline policies (from IAM roles) as separate ResourceDefinitions ✓
  - Handle S3 bucket policies as separate ResourceDefinitions ✓
  - All tests pass ✓

---

#### 9.2 Wire ResourceFileCloudFormationCollector into scan_orchestrator

[x] Write unit tests for scan_orchestrator with CloudFormation collector
  - Test file: `tests/unit_tests/scanners/test_scan_orchestrator_unified.py` ✓
  - Test CloudFormation path uses ResourceFileCloudFormationCollector ✓
  - Test CloudFormation path flows through resource_orchestrator ✓
  - Test CloudFormation results are formatted correctly ✓
  - Test CloudFormation path detects vulnerabilities ✓
  - All tests FAILED initially (TDD) ✓

[x] Update scan_orchestrator to use CloudFormation collector
  - File: `src/aws_scanner/scanners/scan_orchestrator.py` ✓
  - Update `_get_collector(config, boto3_wrapper)`: ✓
    - If cloudformation: return ResourceFileCloudFormationCollector(config.cloudformation.file) ✓
  - Remove the if/else branching in `run_scan()` ✓
  - Use single unified path for all scanning ✓
  - All tests pass ✓

---

#### 9.3 Remove scan_cloudformation_template function

[x] Verify scan_cloudformation_template is no longer used
  - Search codebase for imports of scan_cloudformation_template ✓
  - Search codebase for calls to scan_cloudformation_template ✓
  - Ensure only scan_orchestrator previously used it ✓
  - Verify it's now unused after 9.2 ✓

[x] Remove scan_cloudformation_template function
  - File: `src/aws_scanner/engines/cloudformation/cloudformation_scanner.py` ✓
  - Delete `scan_cloudformation_template()` function ✓
  - cloudformation_reader module retained (used by collector internally) ✓
  - Updated module-level imports ✓

[x] Remove cloudformation_scanner.py entirely
  - Checked file only contained scan_cloudformation_template() and helper functions ✓
  - Deleted the entire file ✓
  - Updated imports that referenced it ✓

---

#### 9.4 Verify All Scanning Works with Unified Path

[x] Run full test suite
  - Run: `pytest tests/unit_tests/` ✓
  - All 179 tests pass ✓
  - No regressions ✓

[x] Test CloudFormation scanning manually
  - Tested collector with `examples/cloudformation/vulnerable_stack.yaml` ✓
  - Successfully collected 6 resources ✓
  - Resource types: IAM::Role, IAM::Policy, S3::Bucket, S3::BucketPolicy, EC2::SecurityGroup ✓

[x] Verified unified path architecture
  - CloudFormation uses ResourceFileCloudFormationCollector ✓
  - All scanning modes flow through same code path ✓
  - format_results() used for all modes ✓

---

**Result**: scan_orchestrator uses single unified code path for all scanning modes (CloudFormation, file-based, AWS API). Phase 9 complete!
