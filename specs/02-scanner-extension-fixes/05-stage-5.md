### Stage 5 (Tests): Extension CloudFormation Support

[x] Command registered: `aws-scanner.scanCloudFormation`
  - File: `vscode-extension/src/extension.ts:20`
  - Command is registered and functional

[x] Calls scanner with correct `--cloudformation` flag
  - File: `vscode-extension/src/extension.ts:115`
  - Scanner is called with correct arguments

[x] Displays mixed resource types correctly
  - File: `vscode-extension/src/extension.ts:186-234`
  - Function `displayCloudFormationResults()` handles IAM roles, S3 buckets, and security groups
  - Results grouped by resource type and displayed correctly
