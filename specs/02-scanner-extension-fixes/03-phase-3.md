# Phase 3: CloudFormation Extension Support

**Status**: Not started

---

## Checklist

[ ] Add CloudFormation scan command to extension
  - Register new command: `aws-scanner.scanCloudFormation`
  - Add to package.json command palette
  - Create command handler

[ ] Update extension to call scanner with --cloudformation flag
  - Pass file path to scanner
  - Handle both YAML and JSON templates
  - Parse and display results

[ ] Add CloudFormation result display logic
  - Extract resources from scan results
  - Group findings by resource type
  - Show resource logical IDs

[ ] Update extension README
  - Document CloudFormation command
  - Add usage examples
  - List supported resource types

---

## Command Implementation

```typescript
vscode.commands.registerCommand('aws-scanner.scanCloudFormation', () => {
  scanCloudFormationFile();
});

async function scanCloudFormationFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('No active file to scan');
    return;
  }

  const filePath = editor.document.fileName;
  const cliPath = getBundledCliPath();

  const args = ['--cloudformation', filePath, '--output', '/tmp/vscode-scan-result.json'];

  const { stdout, stderr } = await execFileAsync(cliPath, args);

  // Parse and display results
  const results = JSON.parse(fs.readFileSync('/tmp/vscode-scan-result.json', 'utf8'));
  displayCloudFormationResults(results);
}
```

---

## Result Display Format

```
📊 CloudFormation Scan Results (5 resources):
==================================================

1. MyS3Bucket (AWS::S3::Bucket)
   🚨 Found 2 security issue(s):
   1. 🔴 [HIGH] Bucket policy allows public access
      💡 Fix: Restrict policy to specific principals
   2. 🟡 [MEDIUM] Versioning not enabled
      💡 Fix: Enable bucket versioning

2. MyIamRole (AWS::IAM::Role)
   ✅ No security issues found

...
```

---

## Files to Modify

- `vscode-extension/package.json` (add command)
- `vscode-extension/src/extension.ts` (add handler)

---

## Testing

- Test with examples/cloudformation/*.yaml
- Test with examples/cloudformation/*.json
- Verify all resource types detected
- Check findings are properly displayed
