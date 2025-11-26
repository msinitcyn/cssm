### Phase 5: Create Universal Resource Orchestrator

**Goal**: Create a single orchestrator that can analyze any ResourceCollection by routing each resource to the appropriate analyzer.

[x] Write unit tests for universal resource orchestrator
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

[x] Implement universal resource orchestrator
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

[x] Create CloudFormation scanner using orchestrator
  - New file: `src/aws_scanner/engines/cloudformation/cloudformation_scanner.py`
  - Create scan_cloudformation_template(file_path: str) function
  - Use CloudFormationReader to parse template
  - Extract inline IAM policies from roles and analyze separately
  - Handle AWS::S3::BucketPolicy resources with public policy detection
  - Resolve CloudFormation !Ref references
  - Return findings grouped by resource type (iam_roles, s3_buckets, security_groups)

[x] Wire CloudFormation scanner into CLI
  - Update `src/aws_scanner/cli/cli_parser.py`:
    - Add --cloudformation flag with file argument
    - Document usage
  - Update `src/aws_scanner/cli/config_builder.py`:
    - Add CloudFormationConfig
    - Handle --cloudformation flag
  - Update `src/aws_scanner/core/configs.py`:
    - Add CloudFormationConfig dataclass
  - Update `src/aws_scanner/scanners/scan_orchestrator.py`:
    - Import CloudFormation scanner
    - Route --cloudformation requests to CloudFormation scanner
    - Use existing report generator for output
  - Validate with integration test

[x] Verify CloudFormation integration test passes
  - Run test_cloudformation_scanning.py
  - All CloudFormation vulnerabilities should be detected
  - Test should pass
  - Verify examples work: `aws-scanner --cloudformation examples/cloudformation/vulnerable_stack.yaml`

