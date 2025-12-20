# Phase 1: Scanner Error Handling

**Status**: Not started

---

## Checklist

[ ] Identify all collectors that can fail on wrong format:
  - ResourceFileIamPolicyCollector
  - ResourceFileIamRoleCollector
  - ResourceFileS3Collector
  - ResourceFileSgCollector
  - ResourceFileCloudFormationCollector

[ ] Add format validation to each collector
  - Validate structure before processing
  - Detect common format mismatches
  - Return clear error messages

[ ] Replace AttributeError crashes with validation errors
  - Check for required fields early
  - Provide helpful messages about expected format
  - Reference supported-features.md format specs

[ ] Add tests for error cases
  - Test each collector with wrong format
  - Verify helpful error messages returned
  - Ensure no stack traces for user errors

[ ] Update error handling in scan_orchestrator
  - Catch validation errors from collectors
  - Format error messages for CLI output
  - Exit with proper error code

---

## Example Error Messages

**Current** (bad):
```
AttributeError: 'str' object has no attribute 'get'
[PYI-53252:ERROR] Failed to execute script
```

**Target** (good):
```
Error: Invalid IAM role file format
Expected: {"role-name": {"assume_role_policy_document": {...}}}
Found: IAM policy format instead

Hint: Use 'aws-scanner iam --policies --file' for policy files
See supported-features.md §3.2 for role file format
```

---

## Files to Modify

- `src/aws_scanner/engines/iam_role/resource_file_iam_role_collector.py`
- `src/aws_scanner/engines/iam_policy/resource_file_iam_policy_collector.py`
- `src/aws_scanner/engines/s3/resource_file_s3_collector.py`
- `src/aws_scanner/engines/sg/resource_file_sg_collector.py`
- `src/aws_scanner/engines/cloudformation/resource_file_cloudformation_collector.py`
- `src/aws_scanner/scanners/scan_orchestrator.py`

---

## Testing

Test with intentional format mismatches:
- IAM policy file with role collector
- IAM role file with policy collector
- S3 file with SG collector
- Invalid JSON
- Empty files
