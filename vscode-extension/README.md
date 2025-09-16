# AWS Cloud Security Scanner for Misconfigurations (CSSM) VSCode Extension

A Visual Studio Code extension for scanning AWS configurations for security misconfigurations.

## Features

- Scan IAM roles and policies
- Scan S3 bucket configurations
- Scan Security Group configurations
- Display results with severity levels and remediation suggestions

## Commands

- `AWS Scanner: Scan IAM Role` - Scan current file as IAM role
- `AWS Scanner: Scan IAM Policy` - Scan current file as IAM policy
- `AWS Scanner: Scan S3 Configuration` - Scan current file as S3 config
- `AWS Scanner: Scan Security Group` - Scan current file as Security Group

## Settings

- `aws-scanner.cliPath`: Path to aws-scanner executable (default: "aws-scanner")
- `aws-scanner.autoSave`: Auto-save file before scanning (default: true)

## Usage

1. Open an AWS configuration JSON file
2. Press `Ctrl+Shift+P` to open command palette
3. Type "AWS Scanner" and select the appropriate scan command
4. View results in the output panel

## Development

```bash
cd vscode-extension
npm install
npm run compile
```

Press F5 to launch extension development host.

## License

MIT License - see [LICENSE](LICENSE) file for details.