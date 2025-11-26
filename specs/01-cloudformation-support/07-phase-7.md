### Phase 7: Restore AWS API Scanning with Resource Collectors

**Goal**: Migrate AWS API scanning from old data class path to new resource-based path using ResourceCollection.

**Architecture**:
```
CLI → pick_collector(config) → ResourceCollection → resource_orchestrator.analyze_resources() → format_results() → generate_report()
```

**Current State**:
- AWS API scanning raises NotImplementedError (degraded in Phase 6)
- Old path: `AWS collectors → List[DataClass] → old analyzers → old scanners`

**Target State**:
- AWS API scanning uses: `Resource AWS collectors → ResourceCollection → resource_orchestrator → format_results`
- Unified path for both file-based and AWS API scanning

---

#### 7.1 Create Resource AWS IAM Policy Collector

[x] Write unit tests for ResourceAwsIamPolicyCollector
  - Test file: `tests/unit_tests/engines/iam_policy/test_resource_aws_iam_policy_collector.py`
  - Test `collect()` returns ResourceCollection
  - Test IAM policies become ResourceDefinition with type "AWS::IAM::Policy"
  - Test policy properties include PolicyName and PolicyDocument
  - Test handles attached_only=True parameter
  - Test handles attached_only=False (all policies)
  - Test handles pagination
  - Test handles get_policy errors gracefully
  - Test handles get_policy_version errors gracefully
  - All tests should FAIL initially (TDD)

[x] Implement ResourceAwsIamPolicyCollector
  - New file: `src/aws_scanner/engines/iam_policy/resource_aws_iam_policy_collector.py`
  - Create `ResourceAwsIamPolicyCollector(boto3_wrapper, attached_only)`
  - Implement `collect() -> ResourceCollection`
  - Use boto3 to call list_policies, get_policy, get_policy_version
  - Create ResourceDefinition for each policy:
    - logical_id: PolicyName
    - resource_type: "AWS::IAM::Policy"
    - properties: {"PolicyName": name, "PolicyDocument": document}
  - Handle pagination with paginator
  - Handle errors gracefully
  - Make all tests pass

---

#### 7.2 Create Resource AWS IAM Role Collector

[ ] Write unit tests for ResourceAwsIamRoleCollector
  - Test file: `tests/unit_tests/engines/iam_role/test_resource_aws_iam_role_collector.py`
  - Test `collect()` returns ResourceCollection
  - Test IAM roles become ResourceDefinition with type "AWS::IAM::Role"
  - Test role properties include RoleName and AssumeRolePolicyDocument
  - Test inline policies are extracted as separate ResourceDefinitions (type "AWS::IAM::Policy")
  - Test attached policies are extracted as separate ResourceDefinitions
  - Test handles get_role errors gracefully
  - Test handles list_role_policies errors gracefully
  - Test handles list_attached_role_policies errors gracefully
  - All tests should FAIL initially (TDD)

[ ] Implement ResourceAwsIamRoleCollector
  - New file: `src/aws_scanner/engines/iam_role/resource_aws_iam_role_collector.py`
  - Create `ResourceAwsIamRoleCollector(boto3_wrapper)`
  - Implement `collect() -> ResourceCollection`
  - Use boto3 to call list_roles, get_role, list_role_policies, list_attached_role_policies
  - Create ResourceDefinition for each role:
    - logical_id: RoleName
    - resource_type: "AWS::IAM::Role"
    - properties: {"RoleName": name, "AssumeRolePolicyDocument": trust_policy}
  - Extract inline policies as separate ResourceDefinitions (type "AWS::IAM::Policy")
  - Extract attached policies as separate ResourceDefinitions (type "AWS::IAM::ManagedPolicy")
  - Handle errors gracefully
  - Make all tests pass

---

#### 7.3 Create Resource AWS S3 Collector

[ ] Write unit tests for ResourceAwsS3Collector
  - Test file: `tests/unit_tests/engines/s3/test_resource_aws_s3_collector.py`
  - Test `collect()` returns ResourceCollection
  - Test S3 buckets become ResourceDefinition with type "AWS::S3::Bucket"
  - Test bucket properties include BucketName, PublicAccessBlockConfiguration
  - Test bucket properties include ACL (Grants), Policy, CorsConfiguration, etc.
  - Test handles get_bucket_policy errors (NoSuchBucketPolicy)
  - Test handles get_public_access_block errors (NoSuchPublicAccessBlockConfiguration)
  - Test handles bucket_name parameter (scan specific bucket)
  - Test handles no bucket_name parameter (scan all buckets)
  - All tests should FAIL initially (TDD)

[ ] Implement ResourceAwsS3Collector
  - New file: `src/aws_scanner/engines/s3/resource_aws_s3_collector.py`
  - Create `ResourceAwsS3Collector(boto3_wrapper, bucket_name=None)`
  - Implement `collect() -> ResourceCollection`
  - Use boto3 to call list_buckets, get_bucket_acl, get_bucket_policy, get_public_access_block, etc.
  - Create ResourceDefinition for each bucket:
    - logical_id: BucketName
    - resource_type: "AWS::S3::Bucket"
    - properties: All S3 configurations as CloudFormation-style properties
  - Handle NoSuchBucketPolicy error (bucket has no policy)
  - Handle NoSuchPublicAccessBlockConfiguration error
  - Handle errors gracefully
  - Make all tests pass

---

#### 7.4 Create Resource AWS Security Group Collector

[ ] Write unit tests for ResourceAwsSecurityGroupCollector
  - Test file: `tests/unit_tests/engines/sg/test_resource_aws_security_group_collector.py`
  - Test `collect()` returns ResourceCollection
  - Test security groups become ResourceDefinition with type "AWS::EC2::SecurityGroup"
  - Test SG properties include GroupId, GroupName, SecurityGroupIngress
  - Test handles regions parameter (list of regions)
  - Test handles describe_security_groups errors gracefully
  - Test collects from multiple regions when specified
  - All tests should FAIL initially (TDD)

[ ] Implement ResourceAwsSecurityGroupCollector
  - New file: `src/aws_scanner/engines/sg/resource_aws_security_group_collector.py`
  - Create `ResourceAwsSecurityGroupCollector(boto3_wrapper, regions)`
  - Implement `collect() -> ResourceCollection`
  - Use boto3 to call describe_security_groups
  - Create ResourceDefinition for each security group:
    - logical_id: GroupId
    - resource_type: "AWS::EC2::SecurityGroup"
    - properties: {"GroupId": id, "GroupName": name, "SecurityGroupIngress": ingress_rules}
  - Iterate over all specified regions
  - Handle errors gracefully
  - Make all tests pass

---

#### 7.5 Wire Resource AWS Collectors into scan_orchestrator

[ ] Write unit tests for scan_orchestrator with AWS collectors
  - Test file: `tests/unit_tests/scanners/test_scan_orchestrator_aws.py`
  - Test IAM policy AWS path: ResourceAwsIamPolicyCollector → resource_orchestrator → format_results
  - Test IAM role AWS path: ResourceAwsIamRoleCollector → resource_orchestrator → format_results
  - Test S3 AWS path: ResourceAwsS3Collector → resource_orchestrator → format_results
  - Test SG AWS path: ResourceAwsSecurityGroupCollector → resource_orchestrator → format_results
  - Test boto3_wrapper is passed to collectors
  - All tests should FAIL initially (TDD)

[ ] Update scan_orchestrator to use Resource AWS collectors
  - File: `src/aws_scanner/scanners/scan_orchestrator.py`
  - Update `_get_collector(config)`:
    - If iam_policy + no file: return ResourceAwsIamPolicyCollector(boto3_wrapper, config.iam_policy.attached_only)
    - If iam_role + no file: return ResourceAwsIamRoleCollector(boto3_wrapper)
    - If s3 + no file: return ResourceAwsS3Collector(boto3_wrapper)
    - If sg + no file: return ResourceAwsSecurityGroupCollector(boto3_wrapper, config.sg.regions)
  - Remove NotImplementedError raises
  - Ensure boto3_wrapper is available in run_scan()
  - Make all tests pass

---

#### 7.6 Verify All Scanning Works (File + AWS API)

[ ] Run full test suite
  - Run: `pytest tests/unit_tests/`
  - All tests should pass

[ ] Test AWS API scanning manually (requires AWS credentials)
  - Test: `cssm iam --policies` (scans all IAM policies via AWS API)
  - Test: `cssm iam --roles` (scans all IAM roles via AWS API)
  - Test: `cssm s3` (scans all S3 buckets via AWS API)
  - Test: `cssm sg --regions us-east-1` (scans security groups via AWS API)
  - Verify vulnerabilities are detected
  - Verify same output format as before

[ ] Verify file-based scanning still works
  - Test: `cssm --cloudformation examples/cloudformation/vulnerable_stack.yaml`
  - Test: `cssm iam --policies --file examples/iam/policies/wildcard_admin.json`
  - Verify same vulnerabilities detected as before

---

**Result**: All scanning (CloudFormation, file-based, AWS API) now uses unified resource path.
