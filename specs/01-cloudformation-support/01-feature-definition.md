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
  - Test can retrieve role and policies from collection

[ ] Implement ResourceFileIamRoleCollector
  - New file: `src/aws_scanner/engines/iam_role/resource_file_iam_role_collector.py`
  - Implement collect() returning ResourceCollection
  - Create ResourceDefinition for IAM role with properties
  - Create separate ResourceDefinition for each inline policy
  - Create separate ResourceDefinition for each attached policy
  - Add ResourceReferences from role to policies
  - Add all resources to collection

[ ] Write unit tests for ResourceFileS3Collector
  - Test file: `tests/unit_tests/engines/s3/test_resource_file_s3_collector.py`
  - Test collector returns ResourceCollection instead of List[S3BucketData]
  - Test S3 bucket becomes ResourceDefinition with resource_type="AWS::S3::Bucket"
  - Test bucket properties (BucketName, PublicAccessBlockConfiguration, AclGrants, etc.)
  - Test bucket policy becomes separate ResourceDefinition if exists
  - Test ResourceReference from bucket to policy if policy exists
  - Test can retrieve bucket and policy from collection

[ ] Implement ResourceFileS3Collector
  - New file: `src/aws_scanner/engines/s3/resource_file_s3_collector.py`
  - Implement collect() returning ResourceCollection
  - Create ResourceDefinition for S3 bucket with properties
  - If bucket policy exists, create separate ResourceDefinition for policy
  - Add ResourceReference from bucket to policy if policy exists
  - Add all resources to collection

[ ] Write unit tests for ResourceFileSgCollector
  - Test file: `tests/unit_tests/engines/sg/test_resource_file_sg_collector.py`
  - Test collector returns ResourceCollection instead of List[SgData]
  - Test security group becomes ResourceDefinition with resource_type="AWS::EC2::SecurityGroup"
  - Test SG properties (GroupId, GroupName, VpcId, IngressRules, EgressRules)
  - Test can retrieve security group from collection

[ ] Implement ResourceFileSgCollector
  - New file: `src/aws_scanner/engines/sg/resource_file_sg_collector.py`
  - Implement collect() returning ResourceCollection
  - Create ResourceDefinition for security group with properties
  - Add resource to collection

### Phase 4: Create New Analyzers Using ResourceDefinition

[ ] Write unit tests for IAM Policy analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/iam_policy/test_resource_analyzer.py`
  - Test analyze_iam_policy_from_resource() function
  - Test accepts ResourceDefinition with resource_type="AWS::IAM::Policy"
  - Test extracts PolicyDocument from properties
  - Test returns same vulnerabilities as old analyzer
  - Test with various policy documents (wildcard, privilege escalation, etc.)

[ ] Implement IAM Policy analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/iam_policy/resource_analyzer.py`
  - Create analyze_iam_policy_from_resource(resource_def: ResourceDefinition)
  - Extract PolicyDocument from resource_def.properties
  - Call existing analyze_policy() function
  - Return findings

[ ] Write unit tests for IAM Role analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/iam_role/test_resource_analyzer.py`
  - Test analyze_iam_role_from_resource() function
  - Test accepts ResourceDefinition and ResourceCollection
  - Test extracts AssumeRolePolicyDocument and analyzes trust policy
  - Test finds referenced policies via resource_def.references
  - Test retrieves policy ResourceDefinitions from collection
  - Test analyzes all referenced policies
  - Test aggregates findings from trust policy + all policies
  - Test returns same vulnerabilities as old analyzer

[ ] Implement IAM Role analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/iam_role/resource_analyzer.py`
  - Create analyze_iam_role_from_resource(resource_def: ResourceDefinition, collection: ResourceCollection)
  - Extract and analyze AssumeRolePolicyDocument from properties
  - Iterate through resource_def.references
  - Get policy ResourceDefinitions from collection
  - Analyze each policy using analyze_iam_policy_from_resource()
  - Aggregate all findings with proper context
  - Return findings

[ ] Write unit tests for S3 Bucket analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/s3/test_resource_analyzer.py`
  - Test analyze_s3_bucket_from_resource() function
  - Test accepts ResourceDefinition and ResourceCollection
  - Test extracts bucket configuration from properties
  - Test finds referenced bucket policy via references if exists
  - Test analyzes bucket with and without policy
  - Test returns same vulnerabilities as old analyzer

[ ] Implement S3 Bucket analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/s3/resource_analyzer.py`
  - Create analyze_s3_bucket_from_resource(resource_def: ResourceDefinition, collection: ResourceCollection)
  - Extract bucket properties (PublicAccessBlockConfiguration, AclGrants, etc.)
  - Find referenced policy via resource_def.references if exists
  - Get policy ResourceDefinition from collection if referenced
  - Call existing S3 analysis functions with extracted data
  - Return findings

[ ] Write unit tests for Security Group analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/sg/test_resource_analyzer.py`
  - Test analyze_sg_from_resource() function
  - Test accepts ResourceDefinition
  - Test extracts IngressRules from properties
  - Test returns same vulnerabilities as old analyzer

[ ] Implement Security Group analyzer using ResourceDefinition
  - New file: `src/aws_scanner/engines/sg/resource_analyzer.py`
  - Create analyze_sg_from_resource(resource_def: ResourceDefinition)
  - Extract IngressRules from resource_def.properties
  - Call existing SG analysis functions
  - Return findings

### Phase 5: Update Scanners and Wire Components

[ ] Update iam_role_scanner.py to use new collector and analyzer
  - Change FileIamRoleCollector to return ResourceCollection
  - Use analyze_iam_role_from_resource() instead of old analyzer
  - Convert ResourceCollection findings back to old output format for compatibility
  - Verify existing integration tests pass

[ ] Update iam_policy_scanner.py to use new collector and analyzer
  - Change collector to return ResourceCollection
  - Use analyze_iam_policy_from_resource() instead of old analyzer
  - Convert findings to old output format
  - Verify existing integration tests pass

[ ] Update s3_scanner.py to use new collector and analyzer
  - Change FileS3Collector to return ResourceCollection
  - Use analyze_s3_bucket_from_resource() instead of old analyzer
  - Convert findings to old output format
  - Verify existing integration tests pass

[ ] Update sg_scanner.py to use new collector and analyzer
  - Change FileSgCollector to return ResourceCollection
  - Use analyze_sg_from_resource() instead of old analyzer
  - Convert findings to old output format
  - Verify existing integration tests pass

[ ] Update scan_orchestrator.py and verify integration tests pass
  - Verify all scanners work together
  - Run full integration test suite
  - All tests should be green

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

Notes

Use TDD for each step: write test first, then implement
Each checkbox is a separate commit
Test checkboxes and implementation checkboxes are separate
Maintain backward compatibility until Phase 6 cleanup
