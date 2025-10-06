# CloudFormation Support - Feature Definition

**Feature Branch**: `feature/cloudformation-support`  
**Milestone**: 9  
**Status**: IN PROGRESS  
**Created**: 2025-09-29

---

## Feature Description

Enable CSSM to analyze AWS CloudFormation templates (YAML/JSON) for security misconfigurations.

### Current Limitation
CSSM can only scan individual AWS resource files. CloudFormation templates bundle multiple resources (IAM roles, S3 buckets, Security Groups) in a single file.

### Example Usage
```bash
# Scan single template
cssm --cloudformation file:infrastructure.yaml --output report.json

# Scan directory of templates
cssm --cloudformation dir:templates/ --output report.json
```

---

## Implementation Steps

### Phase 1: Integration Tests
[ ] Create example CloudFormation template with vulnerabilities
  - Template with IAM role (wildcard permissions)
  - Template with S3 bucket (public policy)
  - Template with Security Group (open ports)
  - Place in `examples/cloudformation/vulnerable_stack.yaml`

[ ] Create integration test for CloudFormation scanning
  - Test file: `tests/integration_tests/test_cloudformation_scanning.py`
  - Scan example template with `--cloudformation` flag
  - Verify IAM vulnerability detected
  - Verify S3 vulnerability detected
  - Verify Security Group vulnerability detected
  - Test will fail - that's expected (TDD)

### Phase 2: CloudFormation Reader

[ ] Research 3rd party CloudFormation parsers
  - Evaluate options (cfn-lint, pycfmodel, troposphere, others)
  - Consider: parsing capability, maintenance, dependencies
  - Document choice and reasoning

[ ] Define internal CloudFormation data structure
  - Object to represent parsed CloudFormation template
  - Must capture: Resources, resource types, properties
  - Keep it simple - only what we need for extraction

[ ] Create unit tests for CloudFormation reader
  - Test parsing YAML template
  - Test parsing JSON template
  - Test extracting Resources section
  - Test identifying resource types (AWS::IAM::Role, AWS::S3::Bucket, etc.)
  - Tests will fail initially (TDD)

[ ] Implement CloudFormation reader
  - Parse CloudFormation YAML/JSON
  - Extract Resources section
  - Return internal data structure
  - Make unit tests pass

### Phase 3: Architecture Changes
[ ] (To be defined based on Phase 1 & 2 results)

---

## Notes

- Use TDD for each step: write test first, then implement
- Each checkbox should be small enough to complete in one session
- Each checkbox can be split into smaller tasks if needed during implementation