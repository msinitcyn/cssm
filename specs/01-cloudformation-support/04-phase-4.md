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

[x] Implement IAM Role analyzer using ResourceDefinition
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

[x] Write unit tests for S3 Bucket analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/s3/test_resource_analyzer.py`
  - Test analyze_s3_bucket_from_resource() function
  - Test accepts ResourceDefinition (bucket only, no ResourceCollection parameter)
  - Test extracts bucket configuration from properties
  - Test analyzes PAB config, ACL grants, CORS, website config, encryption, etc.
  - **Does NOT test bucket policy analysis** - policies are separate resources
  - Test with bucket that has public ACL
  - Test with bucket that has disabled PAB
  - Test with bucket that has no encryption

[x] Implement S3 Bucket analyzer using ResourceDefinition
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

[x] Write unit tests for Security Group analyzer using ResourceDefinition
  - Test file: `tests/unit_tests/engines/sg/test_resource_analyzer.py`
  - Test analyze_sg_from_resource() function
  - Test accepts ResourceDefinition (SG only)
  - Test extracts IngressRules and EgressRules from properties
  - Test detects open ports, management ports, database ports
  - Test detects all-ports-open rules
  - Test with SG that has SSH open to 0.0.0.0/0
  - Test with SG that has database ports open

[x] Implement Security Group analyzer using ResourceDefinition
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

