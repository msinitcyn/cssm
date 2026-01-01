### Stage 2 (Implementation): Add BucketPolicy Scanner

[x] Add AWS::S3::BucketPolicy to CloudFormation resource mapping
  - File: `src/aws_scanner/engines/cloudformation/resource_file_cloudformation_collector.py:48`
  - BucketPolicy resources are identified and processed

[x] Extract bucket policy from resource properties
  - File: `src/aws_scanner/engines/cloudformation/resource_file_cloudformation_collector.py:51`
  - PolicyDocument extracted from BucketPolicy properties

[x] Analyze policy for vulnerabilities
  - File: `src/aws_scanner/engines/cloudformation/resource_file_cloudformation_collector.py:67-75`
  - BucketPolicy converted to IAM Policy ResourceDefinition
  - Original BucketPolicy resource deleted from collection (line 79)
  - Orchestrator analyzes it as IAM Policy - no special handling needed
