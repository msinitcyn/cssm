# CloudFormation Support - Feature Definition

**Feature Branch**: `feature/cloudformation-support`
**Milestone**: 9
**Status**: IN PROGRESS
**Created**: 2025-09-29
**Updated**: 2025-10-26

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

## Architecture Decisions

### Analyzer Separation of Concerns

**Decision**: Each analyzer focuses ONLY on its own resource type, without following references or analyzing related resources.

**Rationale**:
- Simpler, more maintainable analyzers
- Cleaner separation of concerns
- Better suited for CloudFormation's flat resource structure
- Orchestration layer handles resource relationships

**Analyzer Responsibilities**:

| Analyzer | Input | Analyzes | Does NOT Analyze |
|----------|-------|----------|------------------|
| IAM Role | `ResourceDefinition` (role) | Trust policy only (AssumeRolePolicyDocument) | Attached/inline policies |
| IAM Policy | `ResourceDefinition` (policy) | Policy document | - |
| S3 Bucket | `ResourceDefinition` (bucket) | Bucket configuration (PAB, ACL, CORS, etc.) | Bucket policies |
| Security Group | `ResourceDefinition` (SG) | Ingress/Egress rules | - |

**Orchestrator Responsibilities**:
- Iterate through `ResourceCollection`
- Route each resource to appropriate analyzer based on `resource_type`
- Aggregate all findings
- Format output

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

### Phase 4: Create New Analyzers Using ResourceDefinition

**CRITICAL - Architecture Change**: Each analyzer focuses ONLY on its own resource configuration:
- IAM Role analyzer → analyzes trust policy ONLY
- IAM Policy analyzer → analyzes policy document ONLY
- S3 Bucket analyzer → analyzes bucket configuration ONLY (no bucket policies)
- Security Group analyzer → analyzes SG rules ONLY

**NO analyzer follows references or analyzes related resources**. The orchestration layer (Phase 5) handles resource relationships.

**Why inline everything?**
- policy_analyzer_utils.py depends on IamPolicyData (will be deprecated)
- New analyzers should have zero dependencies on deprecated code
- Makes Phase 6 cleanup straightforward (just delete old modules)
- Each analyzer is self-contained and maintainable

[x] Write unit tests for IAM Policy analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/iam_policy/test_resource_analyzer.py`
  - Test analyze_iam_policy_from_resource() function
  - Test accepts ResourceDefinition with resource_type="AWS::IAM::Policy"
  - Test extracts PolicyDocument from properties
  - Test returns vulnerabilities for wildcard, privilege escalation, etc.
  - **Note**: Findings format may differ from old analyzer (no policy_name/policy_type context)

[x] Implement IAM Policy analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/iam_policy/resource_analyzer.py`
  - Create analyze_iam_policy_from_resource(resource_def: ResourceDefinition)
  - Extract PolicyDocument from resource_def.properties
  - **DO NOT import or use IamPolicyData, analyze_policy(), or analyze_statement()**
  - **INLINE all analysis logic** from policy_analyzer_utils.py:
    - Copy constants: RESTRICTIVE_KEYS, SENSITIVE_ACTIONS, PRIVILEGE_ESCALATION_PATTERNS
    - Copy helper functions as private: _is_restrictive(), _has_privilege_escalation(), etc.
    - Copy statement analysis logic inline
  - Iterate through statements in PolicyDocument
  - For each Allow statement, apply all vulnerability checks
  - Aggregate findings from all statements
  - Return findings list

[x] Write unit tests for IAM Role analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/iam_role/test_resource_analyzer.py`
  - Test analyze_iam_role_from_resource() function
  - Test accepts ResourceDefinition (role only, no ResourceCollection parameter)
  - Test extracts AssumeRolePolicyDocument and analyzes trust policy
  - Test returns findings for trust policy vulnerabilities
  - **Does NOT test policy analysis** - policies are separate resources analyzed separately
  - Test with role that has broad trust policy (Principal: "*")
  - Test with role that has restrictive trust policy

[ ] Implement IAM Role analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/iam_role/resource_analyzer.py`
  - Create analyze_iam_role_from_resource(resource_def: ResourceDefinition)
  - Extract AssumeRolePolicyDocument from resource_def.properties
  - **INLINE trust policy analysis logic** (from analyze_assume_role_policy()):
    - Check for wildcard principals
    - Check for missing conditions
    - Check for broad AssumeRole permissions
  - Return findings list
  - **DO NOT**:
    - Iterate through resource_def.references
    - Retrieve or analyze policy resources
    - Use IamRoleData or IamPolicyData
    - Call old analyzer functions

[ ] Write unit tests for S3 Bucket analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/s3/test_resource_analyzer.py`
  - Test analyze_s3_bucket_from_resource() function
  - Test accepts ResourceDefinition (bucket only, no ResourceCollection parameter)
  - Test extracts bucket configuration from properties
  - Test analyzes PAB config, ACL grants, CORS, website config, encryption, etc.
  - **Does NOT test bucket policy analysis** - policies are separate resources
  - Test with bucket that has public ACL
  - Test with bucket that has disabled PAB
  - Test with bucket that has no encryption

[ ] Implement S3 Bucket analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/s3/resource_analyzer.py`
  - Create analyze_s3_bucket_from_resource(resource_def: ResourceDefinition)
  - Extract bucket properties directly from resource_def.properties
  - **INLINE S3 analysis logic** from s3/analyzer.py:
    - Check PublicAccessBlockConfiguration
    - Check AclGrants for public access
    - Check CORS configuration
    - Check website hosting
    - Check encryption settings
    - Check versioning and MFA delete
  - Return findings list
  - **DO NOT**:
    - Look for referenced bucket policies via resource_def.references
    - Retrieve or analyze policy resources
    - Use S3BucketData
    - Call old analyzer functions

[ ] Write unit tests for Security Group analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/sg/test_resource_analyzer.py`
  - Test analyze_sg_from_resource() function
  - Test accepts ResourceDefinition (SG only)
  - Test extracts IngressRules and EgressRules from properties
  - Test detects open ports, management ports, database ports
  - Test detects all-ports-open rules
  - Test with SG that has SSH open to 0.0.0.0/0
  - Test with SG that has database ports open

[ ] Implement Security Group analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/sg/resource_analyzer.py`
  - Create analyze_sg_from_resource(resource_def: ResourceDefinition)
  - Extract IngressRules and EgressRules from resource_def.properties
  - **INLINE SG analysis logic** from sg/analyzer.py:
    - Check for dangerous ports open to public
    - Check for management ports (SSH/RDP)
    - Check for database ports
    - Check for all-ports-open rules
    - Check for overly broad CIDR ranges
  - Return findings list
  - **DO NOT**:
    - Use SgData
    - Call old analyzer functions

### Phase 5: Create Universal Resource Orchestrator

**Goal**: Create a single orchestrator that can analyze any ResourceCollection by routing each resource to the appropriate analyzer.

[ ] Write unit tests for universal resource orchestrator
  - Test file: `tests/unit_tests/core/test_resource_orchestrator.py`
  - Test orchestrator accepts ResourceCollection
  - Test iterates through all resources
  - Test routes AWS::IAM::Role to analyze_iam_role_from_resource()
  - Test routes AWS::IAM::Policy to analyze_iam_policy_from_resource()
  - Test routes AWS::S3::Bucket to analyze_s3_bucket_from_resource()
  - Test routes AWS::EC2::SecurityGroup to analyze_sg_from_resource()
  - Test aggregates findings from all analyzers
  - Test handles unknown resource types gracefully (skip with warning)
  - Test with ResourceCollection containing multiple resource types

[ ] Implement universal resource orchestrator
  - New file: `src/aws_scanner/core/resource_orchestrator.py`
  - Create analyze_resources(collection: ResourceCollection) function
  - Iterate through all resources in collection using `collection.resources`
  - For each resource, check resource_type:
    - "AWS::IAM::Role" → call analyze_iam_role_from_resource(resource_def)
    - "AWS::IAM::Policy" → call analyze_iam_policy_from_resource(resource_def)
    - "AWS::IAM::ManagedPolicy" → call analyze_iam_policy_from_resource(resource_def)
    - "AWS::S3::Bucket" → call analyze_s3_bucket_from_resource(resource_def)
    - "AWS::EC2::SecurityGroup" → call analyze_sg_from_resource(resource_def)
    - Unknown type → log warning and skip
  - Aggregate all findings into single list
  - Return findings list
  - Keep it simple - just routing and aggregation

[ ] Create CloudFormation scanner using orchestrator
  - New file: `src/aws_scanner/engines/cloudformation/cloudformation_scanner.py`
  - Create scan_cloudformation_template(file_path: str) function
  - Use CloudFormationReader to parse template
  - Get ResourceCollection from reader
  - Pass collection to resource_orchestrator.analyze_resources()
  - Return findings in standard format
  - Add metadata about source template

[ ] Wire CloudFormation scanner into CLI
  - Update `src/aws_scanner/cli/arg_parser.py`:
    - Add --cloudformation flag with file/dir argument
    - Document usage
  - Update `src/aws_scanner/cli/config_builder.py`:
    - Add CloudFormationConfig
    - Handle --cloudformation flag
  - Update `src/aws_scanner/core/scan_orchestrator.py`:
    - Import CloudFormation scanner
    - Route --cloudformation requests to CloudFormation scanner
    - Use existing report generator for output
  - Validate with integration test

[ ] Verify CloudFormation integration test passes
  - Run test_cloudformation_scanning.py
  - All CloudFormation vulnerabilities should be detected
  - Test should pass
  - Verify examples work: `aws-scanner --cloudformation examples/cloudformation/vulnerable_stack.yaml`

### Phase 6: Deprecation and Cleanup

**Goal**: Remove old data classes and analyzer code that is no longer needed.

[ ] Delete old data classes
  - Remove `src/aws_scanner/engines/iam_role/iam_role_data.py` (IamRoleData)
  - Remove `src/aws_scanner/engines/common/iam_policy_data.py` (IamPolicyData)
  - Remove `src/aws_scanner/engines/s3/s3_bucket_data.py` (S3BucketData)
  - Remove `src/aws_scanner/engines/sg/sg_data.py` (SgData)

[ ] Delete old analyzer files
  - Remove old analyzers that used data classes:
    - Parts of `src/aws_scanner/engines/iam_role/analyzer.py` (keep if AWS API scanning still needs it)
    - Parts of `src/aws_scanner/engines/iam_policy/analyzer.py`
    - Parts of `src/aws_scanner/engines/s3/analyzer.py`
    - Parts of `src/aws_scanner/engines/sg/analyzer.py`
  - Remove `src/aws_scanner/engines/iam_policy/policy_analyzer_utils.py`

[ ] Delete old scanner files (if fully replaced)
  - Evaluate if these are still needed for AWS API scanning:
    - `src/aws_scanner/engines/iam_role/iam_role_scanner.py`
    - `src/aws_scanner/engines/iam_policy/iam_policy_scanner.py`
    - `src/aws_scanner/engines/s3/s3_scanner.py`
    - `src/aws_scanner/engines/sg/sg_scanner.py`
  - If AWS API scanning still uses them, keep them
  - If file-based scanning has fully migrated to orchestrator, remove them

[ ] Clean up imports and verify all tests pass
  - Remove imports of deleted classes throughout codebase
  - Update all import statements
  - Run full test suite: `pytest`
  - Run integration tests: `pytest tests/integration_tests/`
  - Verify no regressions
  - All tests should be green

---

## Backward Compatibility Summary

**Breaking Changes**:
- **Findings format**: New analyzers do not add `policy_name` and `policy_type` context fields
  - Old: `{"id": "...", "policy_name": "MyPolicy", "policy_type": "inline", ...}`
  - New: `{"id": "...", ...}` (orchestrator may add context in future if needed)
- This is acceptable - will handle compatibility later if needed

**Maintains 100% compatibility with**:
- IAM Policy file format (supported-features.md §3.1) - single object, dict, list, AWS CLI formats
- IAM Role file format (supported-features.md §3.2) - dict with role names as keys
- S3 Bucket file format (supported-features.md §3.3) - dict with bucket names as keys, ACL string conversion
- Security Group file format (supported-features.md §3.4) - single object format
- All field aliases (trust_policy_document, pab_config, block_public_access, ingress_permissions)
- All existing example files in examples/ directory
- All existing CLI commands and flags (except new --cloudformation)
- Vulnerability detection rules (same vulnerabilities detected)

**No breaking changes in**:
- Phase 3: New collectors support all existing file formats
- Phase 5: Orchestrator produces findings for same vulnerabilities
- Phase 6: Cleanup only removes internal classes, not external APIs

---

## Notes

- Use TDD for each step: write test first, then implement
- Each checkbox is a separate commit
- Test checkboxes and implementation checkboxes are separate
- Always use exact method names from API Reference section above
- When in doubt about API, check existing code in `src/aws_scanner/engines/common/resource_definition.py`
- **CRITICAL**: Analyzers are simple and focused - they analyze only their own resource type
- **CRITICAL**: Orchestrator handles resource relationships and routing
- Validate changes against existing example files where applicable