# Phase 2: Extension File Validation

**Status**: Not started

---

## Checklist

[ ] Investigate "no items found" issue
  - Debug why IAM policy scanning returns empty results
  - Check result key mapping in extension
  - Verify collector returns proper data

[ ] Add file validation before scanning
  - Peek at file structure to detect type
  - Show error if wrong command used for file type
  - Suggest correct command

[ ] Improve error display in extension
  - Show error in output channel with context
  - Display helpful hints for common mistakes
  - Link to documentation

[ ] Add file type detection helper
  - Function to detect IAM policy vs role vs S3 vs SG
  - Based on file structure, not just extension
  - Returns detected type and confidence

[ ] Update command handlers
  - Validate file type before calling scanner
  - Show warning if mismatch detected
  - Allow override if user knows better

---

## File Type Detection Logic

```typescript
function detectFileType(content: any): string {
  // IAM Policy indicators
  if (content.document || content.PolicyDocument) {
    return 'iam-policy';
  }

  // IAM Role indicators (dict with role names as keys)
  if (typeof content === 'object' && !Array.isArray(content)) {
    const firstKey = Object.keys(content)[0];
    if (content[firstKey]?.assume_role_policy_document) {
      return 'iam-role';
    }
  }

  // S3 bucket indicators
  if (content.acl || content.policy || content.public_access_block) {
    return 's3';
  }

  // Security group indicators
  if (content.group_id && content.ingress_rules) {
    return 'sg';
  }

  // CloudFormation indicators
  if (content.AWSTemplateFormatVersion || content.Resources) {
    return 'cloudformation';
  }

  return 'unknown';
}
```

---

## Files to Modify

- `vscode-extension/src/extension.ts`

---

## Testing

- Test with examples/iam/policies/*.json
- Test with examples/iam/roles/*.json
- Test with examples/s3/*.json
- Test with examples/sg/*.json
- Verify error messages are helpful
