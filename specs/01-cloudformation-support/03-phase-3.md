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

