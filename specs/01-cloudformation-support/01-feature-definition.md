# CloudFormation Support - Feature Definition

**Feature Branch**: `feature/cloudformation-support`  
**Milestone**: 9  
**Status**: IN PROGRESS  
**Created**: 2025-09-29

---

## ⚠️ API Precision Guidelines

**CRITICAL**: To avoid API mismatches between tests and implementations, follow these rules when writing or reading specs:

### Writing Tests From Specs
1. **Use EXACT method names** from specs - if spec says `get_by_id()`, don't use `get_resource()`
2. **Copy class names exactly** - including case and full paths
3. **Check existing code** - if spec references existing class, look at its actual API in the source file
4. **Ask for clarification** - if method name is ambiguous, request spec update

### Example of Good vs Bad Spec Writing
❌ **Bad**: "Test can retrieve bucket from collection"  
✅ **Good**: "Test can retrieve bucket using `collection.get_by_id(logical_id)` method"

❌ **Bad**: "Returns a resource collection"  
✅ **Good**: "Returns `ResourceCollection` (from `aws_scanner.engines.common.resource_definition`)"

### API Reference Location

**All core APIs are defined in**: `src/aws_scanner/engines/common/resource_definition.py`

Key classes to reference:
- `ResourceCollection` - Container for resources with methods: `add_resource()`, `get_by_id()`, `get_resources_by_type()`
- `ResourceDefinition` - Represents a single resource (has `logical_id`, `resource_type`, `properties`, `references`)
- `ResourceReference` - Represents a reference from one resource to another
- `ReferenceType` - Enum for reference types (INLINE, REF, etc.)

**Always check the source file for exact method signatures and field names before writing tests.**

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

### Phase 2: CloudFormation Reader

[x] Research 3rd party CloudFormation parsers
  - Evaluate options (cfn-lint, pycfmodel, troposphere, others)
  - Consider: parsing capability, maintenance, dependencies

[x] Define internal CloudFormation data structure
  - Object to represent parsed CloudFormation template
  - Must capture: Resources, resource types, properties
  - Keep it simple - only what we need for extraction

[x] Create unit tests for CloudFormation reader
  - Test parsing YAML template
  - Test parsing JSON template
  - Test extracting Resources section
  - Test identifying resource types (AWS::IAM::Role, AWS::S3::Bucket, etc.)
  - Tests will fail initially (TDD)

[x] Implement CloudFormation reader
  - Parse CloudFormation YAML/JSON
  - Extract Resources section
  - Return internal data structure
  - Make unit tests pass

### Phase 3: Create New File Collectors Using ResourceCollection

[x] Write unit tests for ResourceFileIamRoleCollector
  - Test file: `tests/unit_tests/engines/iam_role/test_resource_file_iam_role_collector.py`
  - Test collector returns ResourceCollection instead of List[IamRoleData]
  - Test IAM role becomes ResourceDefinition with resource_type="AWS::IAM::Role"
  - Test role properties in ResourceDefinition.properties (RoleName, AssumeRolePolicyDocument)
  - Test inline policies become separate ResourceDefinitions with references
  - Test attached policies become separate ResourceDefinitions with references
  - Test can retrieve role and policies from collection using `collection.get_by_id()`

[x] Implement ResourceFileIamRoleCollector
  - New file: `src/aws_scanner/engines/iam_role/resource_file_iam_role_collector.py`
  - Implement collect() returning ResourceCollection
  - Create ResourceDefinition for IAM role with properties
  - Create separate ResourceDefinition for each inline policy
  - Create separate ResourceDefinition for each attached policy
  - Add ResourceReferences from role to policies
  - Add all resources to collection

[x] Write unit tests for ResourceFileS3Collector
  - Test file: tests/unit_tests/engines/s3/test_resource_file_s3_collector.py
  - Test collector returns ResourceCollection instead of List[S3BucketData]
  - Test S3 bucket becomes ResourceDefinition with resource_type="AWS::S3::Bucket"
  - Test bucket properties (BucketName, PublicAccessBlockConfiguration, AclGrants, etc.)
  - Test bucket policy becomes separate ResourceDefinition if exists
  - Test ResourceReference from bucket to policy if policy exists
  - Test can retrieve bucket and policy from collection using `collection.get_by_id()`

[x] Implement ResourceFileS3Collector
  - New file: src/aws_scanner/engines/s3/resource_file_s3_collector.py
  - Implement collect() returning ResourceCollection
  - Create ResourceDefinition for S3 bucket with properties
  - If bucket policy exists, create separate ResourceDefinition for policy
  - Add ResourceReference from bucket to policy if policy exists
  - Add all resources to collection

[x] Write unit tests for ResourceFileSgCollector
  - Test file: tests/unit_tests/engines/sg/test_resource_file_sg_collector.py
  - Test collector returns ResourceCollection instead of List[SgData]
  - Test security group becomes ResourceDefinition with resource_type="AWS::EC2::SecurityGroup"
  - Test SG properties (GroupId, GroupName, VpcId, IngressRules, EgressRules)
  - Test can retrieve security group from collection using `collection.get_by_id()`

[x] Implement ResourceFileSgCollector
  - New file: src/aws_scanner/engines/sg/resource_file_sg_collector.py
  - Implement collect() returning ResourceCollection
  - Create ResourceDefinition for security group with properties
  - Add resource to collection

[x] Fix ResourceFileS3Collector backward compatibility
  - Support "acl" field as either string or array (matching FileS3Collector)
  - Convert ACL strings to grant objects:
    - "public-read" → READ grant to AllUsers
    - "public-read-write" → READ and WRITE grants to AllUsers  
    - "private" → Empty grants
    - Unknown values → Empty grants
  - Support field name aliases for PAB config: "public_access_block", "block_public_access", "pab_config"
  - Validate against examples/s3/public_s3_bucket.json (uses "acl": "public-read")
  - Ensures compatibility per supported-features.md §3.3 and §6.1
  
  REM: This task was added when the issue with broken backwards compatibility was found.

[x] Write unit tests for ResourceFileIamPolicyCollector
  - Test file: tests/unit_tests/engines/iam_policy/test_resource_file_iam_policy_collector.py
  - Test collector returns ResourceCollection instead of List[IamPolicyData]
  - Test IAM policy becomes ResourceDefinition with resource_type="AWS::IAM::Policy"
  - Test policy properties (PolicyName, PolicyDocument) in ResourceDefinition.properties
  - **Backward Compatibility (per supported-features.md §3.1):**
    - Test handles single policy format: `{"name": "...", "document": {...}}` (NO wrapper - see examples/iam/policies/wildcard_admin.json)
    - Test handles dict format: `{"policy-key": {"name": "...", "document": {...}}}` (multiple policies with keys)
    - Test handles list format: `[{"name": "...", "document": {...}}]` (array of policies)
    - Test handles AWS CLI metadata format: `{"Policies": [{"PolicyName": "...", "Arn": "..."}]}` (no documents)
    - Test handles policies with missing "document" field (should skip with warning)
    - Test handles policies with missing "name" field (should use key/index as fallback)
  - Test can retrieve policy from collection using `collection.get_by_id()`
  - Validate against examples/iam/policies/wildcard_admin.json, assume_role_wildcard.json, privilege_escalation.json

[x] Implement ResourceFileIamPolicyCollector
  - New file: src/aws_scanner/engines/iam_policy/resource_file_iam_policy_collector.py
  - Implement collect() returning ResourceCollection
  - Create ResourceDefinition for each IAM policy with properties
  - **Backward Compatibility Requirements:**
    - Support single policy format (direct object, no wrapper) - use policy name as logical_id
    - Support dict format (key becomes logical_id)
    - Support list format (use policy name as logical_id, or "policy-{index}" as fallback)
    - Support AWS CLI format with "Policies" key (create empty document with warning)
    - Skip policies without "document" field (log warning)
    - Extract name from multiple field variants: "name", "Name", "PolicyName", "policy_name"
    - Extract document from multiple field variants: "document", "Document", "PolicyDocument", "policy_document"
    - Handle stringified JSON documents (parse them)
  - Properties: {"PolicyName": name, "PolicyDocument": document}
  - Add all policies to collection
  - Ensures compatibility per supported-features.md §3.1

### Phase 4: Create New Analyzers Using ResourceDefinition

[x] Write unit tests for IAM Policy analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/iam_policy/test_resource_analyzer.py`
  - Test analyze_iam_policy_from_resource() function
  - Test accepts ResourceDefinition with resource_type="AWS::IAM::Policy"
  - Test extracts PolicyDocument from properties
  - Test returns same vulnerabilities as old analyzer
  - Test with various policy documents (wildcard, privilege escalation, etc.)
  - **Backward Compatibility:** Verify produces identical findings to existing analyze_policy() for same input

[ ] Implement IAM Policy analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/iam_policy/resource_analyzer.py`
  - Create analyze_iam_policy_from_resource(resource_def: ResourceDefinition)
  - Extract PolicyDocument from resource_def.properties
  - Call existing analyze_policy() function (reuse existing logic)
  - Return findings
  - **Backward Compatibility:** Must produce identical findings to current analyzer

[ ] Write unit tests for IAM Role analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/iam_role/test_resource_analyzer.py`
  - Test analyze_iam_role_from_resource() function
  - Test accepts ResourceDefinition and ResourceCollection
  - Test extracts AssumeRolePolicyDocument and analyzes trust policy
  - Test finds referenced policies via resource_def.references
  - Test retrieves policy ResourceDefinitions from collection using `collection.get_by_id()`
  - Test analyzes all referenced policies
  - Test aggregates findings from trust policy + all policies
  - **Backward Compatibility:** Verify produces identical findings to existing analyze_iam_role() for same input

[ ] Implement IAM Role analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/iam_role/resource_analyzer.py`
  - Create analyze_iam_role_from_resource(resource_def: ResourceDefinition, collection: ResourceCollection)
  - Extract and analyze AssumeRolePolicyDocument from properties
  - Iterate through resource_def.references
  - Get policy ResourceDefinitions from collection using `collection.get_by_id()`
  - Analyze each policy using analyze_iam_policy_from_resource()
  - Aggregate all findings with proper context
  - Return findings
  - **Backward Compatibility:** Must produce identical findings to current analyzer

[ ] Write unit tests for S3 Bucket analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/s3/test_resource_analyzer.py`
  - Test analyze_s3_bucket_from_resource() function
  - Test accepts ResourceDefinition and ResourceCollection
  - Test extracts bucket configuration from properties
  - Test finds referenced bucket policy via resource_def.references if exists
  - Test analyzes bucket with and without policy
  - **Backward Compatibility:** Verify produces identical findings to existing analyze_s3_bucket() for same input

[ ] Implement S3 Bucket analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/s3/resource_analyzer.py`
  - Create analyze_s3_bucket_from_resource(resource_def: ResourceDefinition, collection: ResourceCollection)
  - Extract bucket properties (PublicAccessBlockConfiguration, AclGrants, etc.)
  - Find referenced policy via resource_def.references if exists
  - Get policy ResourceDefinition from collection using `collection.get_by_id()` if referenced
  - Call existing S3 analysis functions with extracted data (reuse existing logic)
  - Return findings
  - **Backward Compatibility:** Must produce identical findings to current analyzer

[ ] Write unit tests for Security Group analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/sg/test_resource_analyzer.py`
  - Test analyze_sg_from_resource() function
  - Test accepts ResourceDefinition
  - Test extracts IngressRules from properties
  - **Backward Compatibility:** Verify produces identical findings to existing analyze_sg() for same input

[ ] Implement Security Group analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/sg/resource_analyzer.py`
  - Create analyze_sg_from_resource(resource_def: ResourceDefinition)
  - Extract IngressRules from resource_def.properties
  - Call existing SG analysis functions (reuse existing logic)
  - Return findings
  - **Backward Compatibility:** Must produce identical findings to current analyzer

### Phase 5: Update Scanners and Wire Components

[ ] Update iam_role_scanner.py to use new collector and analyzer
  - Import ResourceFileIamRoleCollector and analyze_iam_role_from_resource()
  - Change get_collector() to return new collector for file-based scanning
  - Update analyze_roles() to work with ResourceCollection
  - Use analyze_iam_role_from_resource() instead of old analyzer
  - Convert ResourceCollection findings back to old output format for compatibility
  - **CRITICAL:** Verify existing integration tests pass (tests/integration_tests/)
  - **CRITICAL:** Verify examples work: `aws-scanner iam --file examples/iam/roles/overly_permissive_lambda_role.json`

[ ] Update iam_policy_scanner.py to use new collector and analyzer
  - Import ResourceFileIamPolicyCollector and analyze_iam_policy_from_resource()
  - Change get_collector() to return new collector for file-based scanning
  - Update analyze_policies() to work with ResourceCollection
  - Use analyze_iam_policy_from_resource() instead of old analyzer
  - Convert findings to old output format
  - **CRITICAL:** Verify existing integration tests pass
  - **CRITICAL:** Verify examples work: `aws-scanner iam --policies --file examples/iam/policies/wildcard_admin.json`

[ ] Update s3_scanner.py to use new collector and analyzer
  - Import ResourceFileS3Collector and analyze_s3_bucket_from_resource()
  - Change get_collector() to return new collector for file-based scanning
  - Update analyze_buckets() to work with ResourceCollection
  - Use analyze_s3_bucket_from_resource() instead of old analyzer
  - Convert findings to old output format
  - **CRITICAL:** Verify existing integration tests pass
  - **CRITICAL:** Verify examples work: `aws-scanner s3 --file examples/s3/public_s3_bucket.json`

[ ] Update sg_scanner.py to use new collector and analyzer
  - Import ResourceFileSgCollector and analyze_sg_from_resource()
  - Change get_collector() to return new collector for file-based scanning
  - Update analyze_security_groups() to work with ResourceCollection
  - Use analyze_sg_from_resource() instead of old analyzer
  - Convert findings to old output format
  - **CRITICAL:** Verify existing integration tests pass
  - **CRITICAL:** Verify examples work: `aws-scanner sg --file examples/sg/open_security_group.json`

[ ] Update scan_orchestrator.py and verify integration tests pass
  - Verify all scanners work together
  - Run full integration test suite: `pytest tests/integration_tests/`
  - Verify all example files still work correctly
  - All tests should be green
  - **Backward Compatibility Check:** No regressions in existing functionality

### Phase 6: Cleanup and Deprecation

[ ] Delete old data classes and unused code
  - Remove IamRoleData, IamPolicyData, S3BucketData, SgData classes
  - Remove old analyzer functions that used old data classes
  - Remove unused collector abstract classes
  - Keep utility functions that are still used

[ ] Clean up imports and verify all tests pass
  - Remove imports of deleted classes
  - Update all import statements
  - Run full test suite
  - Verify no regressions

### Phase 7: CloudFormation Integration

[ ] Create CloudFormation scanner module
  - Use CloudFormationReader to get ResourceCollection
  - Filter resources by type (IAM roles, S3 buckets, security groups)
  - Call new analyzers for each resource type
  - Aggregate results in same format as other scanners

[ ] Wire CloudFormation scanner into CLI
  - Add --cloudformation flag handling
  - Route to CloudFormation scanner
  - Output results using existing report generator

[ ] Verify CloudFormation integration test passes
  - Run test_cloudformation_scanning.py
  - All CloudFormation vulnerabilities should be detected
  - Test should pass

---

## Backward Compatibility Summary

**Maintains 100% compatibility with:**
- IAM Policy file format (supported-features.md §3.1) - single object, dict, list, AWS CLI formats
- IAM Role file format (supported-features.md §3.2) - dict with role names as keys
- S3 Bucket file format (supported-features.md §3.3) - dict with bucket names as keys, ACL string conversion
- Security Group file format (supported-features.md §3.4) - single object format
- All field aliases (trust_policy_document, pab_config, block_public_access, ingress_permissions)
- All existing example files in examples/ directory
- All existing CLI commands and flags
- All vulnerability detection rules (identical findings)

**No breaking changes in:**
- Phase 3: New collectors support all existing file formats
- Phase 4: New analyzers produce identical findings
- Phase 5: Scanner updates maintain output format compatibility
- Phase 6: Cleanup only removes internal classes, not external APIs

---

## Notes

- Use TDD for each step: write test first, then implement
- Each checkbox is a separate commit
- Test checkboxes and implementation checkboxes are separate
- Maintain backward compatibility until Phase 6 cleanup
- Always use exact method names from API Reference section above
- When in doubt about API, check existing code in `src/aws_scanner/engines/common/resource_definition.py`
- **CRITICAL**: Every undone task explicitly mentions backward compatibility requirements where applicable
- Validate all changes against existing example files before considering task complete