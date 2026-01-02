### Stage 12 (Implementation): Extension Displays All Result Sections

**Goal**: Extension displays all sections with findings instead of picking single section based on scan type.

#### Checklist

[ ] Remove getResultKey and getItemName functions
  - File: `vscode-extension/src/extension.ts:236-256`
  - Functions no longer needed
  - All scanners use unified display logic

[ ] Update displayResults to show all sections
  - File: `vscode-extension/src/extension.ts:142-184`
  - Loop through all sections: iam_roles, iam_policies, s3_buckets, security_groups
  - Display each section that has items
  - Similar logic to displayCloudFormationResults

[ ] Update scanCurrentFile to use new display
  - File: `vscode-extension/src/extension.ts:75`
  - Call displayResults without scanType parameter
  - Remove extraFlag parameter

[ ] Unify display functions (optional)
  - Rename displayCloudFormationResults to displayAllResults
  - Use same function for all scan commands
  - Consistent output format

#### Implementation

```typescript
function displayAllResults(results: any) {
    const sections = [
        { key: 'iam_roles', label: 'IAM Roles', getName: (item: any) => item.role_name || 'Unknown' },
        { key: 'iam_policies', label: 'IAM Policies', getName: (item: any) => item.policy_name || 'Unknown' },
        { key: 's3_buckets', label: 'S3 Buckets', getName: (item: any) => item.bucket_name || 'Unknown' },
        { key: 'security_groups', label: 'Security Groups', getName: (item: any) => item.group_id || 'Unknown' }
    ];

    sections.forEach(section => {
        const items = results[section.key] || [];
        if (items.length > 0) {
            outputChannel.appendLine(`\n${section.label}: ${items.length} item(s)`);
            outputChannel.appendLine('='.repeat(50));

            items.forEach((item: any, index: number) => {
                outputChannel.appendLine(`\n${index + 1}. ${section.getName(item)}`);

                if (item.error) {
                    outputChannel.appendLine(`   Error: ${item.error}`);
                    return;
                }

                const vulnerabilities = item.vulnerabilities || [];
                if (vulnerabilities.length === 0) {
                    outputChannel.appendLine('   No security issues found');
                    return;
                }

                outputChannel.appendLine(`   Found ${vulnerabilities.length} security issue(s):`);
                vulnerabilities.forEach((vuln: any, vulnIndex: number) => {
                    const severity = vuln.severity?.toUpperCase() || 'UNKNOWN';
                    outputChannel.appendLine(`   ${vulnIndex + 1}. [${severity}] ${vuln.description}`);
                    if (vuln.remediation) {
                        outputChannel.appendLine(`      Fix: ${vuln.remediation}`);
                    }
                });
            });
        }
    });
}
```
