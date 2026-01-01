### Stage 6 (Implementation): Add Extension CloudFormation Command

[x] Register CloudFormation scan command
  - File: `vscode-extension/src/extension.ts:20`
  - Command registered: `aws-scanner.scanCloudFormation`
  - Function: `scanCloudFormationFile()` at line 89

[x] Use `--cloudformation` flag
  - File: `vscode-extension/src/extension.ts:115`
  - Scanner called with: `['--cloudformation', filePath, '--output', '/tmp/vscode-scan-result.json']`

[x] Parse and display mixed results (IAM/S3/SG from single template)
  - File: `vscode-extension/src/extension.ts:186-234`
  - Displays IAM roles, S3 buckets, and security groups
  - Groups findings by resource type
  - Shows resource counts and vulnerability counts
