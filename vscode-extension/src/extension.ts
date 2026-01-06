import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execFileAsync = promisify(execFile);

let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
    console.log('AWS Scanner extension is now active');
    
    outputChannel = vscode.window.createOutputChannel('AWS Scanner');
    
    const commands = [
        vscode.commands.registerCommand('aws-scanner.scanIamRole', () => scanCurrentFile('iam')),
        vscode.commands.registerCommand('aws-scanner.scanIamPolicy', () => scanCurrentFile('iam', '--policies')),
        vscode.commands.registerCommand('aws-scanner.scanS3', () => scanCurrentFile('s3')),
        vscode.commands.registerCommand('aws-scanner.scanSecurityGroup', () => scanCurrentFile('sg')),
        vscode.commands.registerCommand('aws-scanner.scanCloudFormation', () => scanCloudFormationFile())
    ];
    
    commands.forEach(command => context.subscriptions.push(command));
    context.subscriptions.push(outputChannel);
}

function getBundledCliPath(): string {
    const extensionPath = __dirname;
    const binPath = path.join(extensionPath, '..', 'bin', 'aws-scanner-linux');
    return binPath;
}

async function scanCurrentFile(scanType: string, extraFlag?: string) {
    const editor = vscode.window.activeTextEditor;

    if (!editor) {
        vscode.window.showErrorMessage('No active file to scan');
        return;
    }

    const document = editor.document;
    const filePath = document.fileName;

    const config = vscode.workspace.getConfiguration('aws-scanner');
    const autoSave = config.get<boolean>('autoSave', true);

    if (autoSave && document.isDirty) {
        await document.save();
    }

    const cliPath = getBundledCliPath();

    try {
        outputChannel.clear();
        outputChannel.show(true);
        outputChannel.appendLine(`Scanning ${filePath} with ${scanType} scanner...`);
        outputChannel.appendLine('');

        const args = [scanType, '--file', filePath, '--output', '/tmp/vscode-scan-result.json'];
        if (extraFlag) {
            args.splice(1, 0, extraFlag);
        }

        const { stdout, stderr } = await execFileAsync(cliPath, args);

        if (stderr) {
            outputChannel.appendLine('Warnings:');
            outputChannel.appendLine(stderr);
            outputChannel.appendLine('');
        }

        try {
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('/tmp/vscode-scan-result.json', 'utf8'));
            displayAllResults(results);
        } catch (parseError) {
            outputChannel.appendLine('Scan completed successfully');
            if (stdout) {
                outputChannel.appendLine(stdout);
            }
        }

    } catch (error: any) {
        outputChannel.appendLine(`Error running scanner: ${error.message}`);
        vscode.window.showErrorMessage(`Scanner error: ${error.message}`);
    }
}

async function scanCloudFormationFile() {
    const editor = vscode.window.activeTextEditor;

    if (!editor) {
        vscode.window.showErrorMessage('No active file to scan');
        return;
    }

    const document = editor.document;
    const filePath = document.fileName;

    const config = vscode.workspace.getConfiguration('aws-scanner');
    const autoSave = config.get<boolean>('autoSave', true);

    if (autoSave && document.isDirty) {
        await document.save();
    }

    const cliPath = getBundledCliPath();

    try {
        outputChannel.clear();
        outputChannel.show(true);
        outputChannel.appendLine(`Scanning CloudFormation template ${filePath}...`);
        outputChannel.appendLine('');

        const args = ['--cloudformation', filePath, '--output', '/tmp/vscode-scan-result.json'];

        const { stdout, stderr } = await execFileAsync(cliPath, args);

        if (stderr) {
            outputChannel.appendLine('Warnings:');
            outputChannel.appendLine(stderr);
            outputChannel.appendLine('');
        }

        try {
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('/tmp/vscode-scan-result.json', 'utf8'));
            displayAllResults(results);
        } catch (parseError) {
            outputChannel.appendLine('Scan completed successfully');
            if (stdout) {
                outputChannel.appendLine(stdout);
            }
        }

    } catch (error: any) {
        outputChannel.appendLine(`Error running scanner: ${error.message}`);
        vscode.window.showErrorMessage(`Scanner error: ${error.message}`);
    }
}

function displayAllResults(results: any) {
    const sections = [
        { key: 'iam_roles', label: 'IAM Roles', getName: (item: any) => item.role_name || 'Unknown' },
        { key: 'iam_policies', label: 'IAM Policies', getName: (item: any) => item.policy_name || 'Unknown' },
        { key: 's3_buckets', label: 'S3 Buckets', getName: (item: any) => item.bucket_name || 'Unknown' },
        { key: 'security_groups', label: 'Security Groups', getName: (item: any) => item.group_id || 'Unknown' }
    ];

    let totalItems = 0;
    let totalVulnerabilities = 0;

    sections.forEach(section => {
        const items = results[section.key] || [];
        if (items.length > 0) {
            totalItems += items.length;
            outputChannel.appendLine(`\n${section.label}: ${items.length} item(s)`);
            outputChannel.appendLine('='.repeat(50));

            items.forEach((item: any, index: number) => {
                outputChannel.appendLine(`\n${index + 1}. ${section.getName(item)}`);

                if (item.error) {
                    outputChannel.appendLine(`   Error: ${item.error}`);
                    return;
                }

                const vulnerabilities = item.vulnerabilities || [];
                totalVulnerabilities += vulnerabilities.length;

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

    if (totalItems === 0) {
        outputChannel.appendLine('No resources found to scan');
    } else {
        outputChannel.appendLine('\n' + '='.repeat(50));
        outputChannel.appendLine(`Scan completed: ${totalItems} resources, ${totalVulnerabilities} issues found`);
    }
}

export function deactivate() {}