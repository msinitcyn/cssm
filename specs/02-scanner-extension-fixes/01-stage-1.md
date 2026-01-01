### Stage 1 (Tests): CloudFormation BucketPolicy Support

[x] CloudFormation files with AWS::S3::BucketPolicy scan successfully
  - Template: `examples/cloudformation/vulnerable_stack.yaml` has BucketPolicy resource
  - Collector extracts it and converts to IAM Policy

[x] Bucket policies extracted and analyzed
  - File: `src/aws_scanner/engines/cloudformation/resource_file_cloudformation_collector.py:47-79`
  - Method `_extract_bucket_policies()` converts BucketPolicy → IAM Policy
  - Orchestrator routes it as IAM Policy and analyzes it

[x] Vulnerabilities in bucket policies detected
  - Integration test: `tests/integration_tests/test_cloudformation_scanning.py` PASSES
  - BucketPolicy vulnerabilities detected correctly
