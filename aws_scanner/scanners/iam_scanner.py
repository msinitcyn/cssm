# aws_scanner/scanners/iam_scanner.py

import boto3
import botocore.exceptions

def is_policy_too_permissive(policy_doc):
    statements = policy_doc.get('Statement')

    if not statements:
        return False

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return False

    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue

        action = stmt.get('Action', [])
        resource = stmt.get('Resource', [])

        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]

        if '*' in action and '*' in resource:
            return True
    return False

def analyze_inline_policies(iam, role_name):
    findings = []
    try:
        response = iam.list_role_policies(RoleName=role_name)
        for policy_name in response.get('PolicyNames', []):
            policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            policy_doc = policy.get('PolicyDocument', {})
            if is_policy_too_permissive(policy_doc):
                findings.append({
                    'role': role_name,
                    'policy_type': 'inline',
                    'policy_name': policy_name,
                    'issue': 'Too permissive (Action="*", Resource="*")'
                })
    except botocore.exceptions.ClientError as e:
        findings.append({'role': role_name, 'error': str(e)})
    return findings

def analyze_attached_policies(iam, role_name):
    findings = []
    try:
        response = iam.list_attached_role_policies(RoleName=role_name)
        for policy in response.get('AttachedPolicies', []):
            policy_arn = policy['PolicyArn']
            policy_name = policy['PolicyName']
            try:
                version_info = iam.get_policy(PolicyArn=policy_arn)
                default_version_id = version_info['Policy']['DefaultVersionId']
                version = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version_id
                )
                policy_doc = version['PolicyVersion']['Document']
                if is_policy_too_permissive(policy_doc):
                    findings.append({
                        'role': role_name,
                        'policy_type': 'attached',
                        'policy_name': policy_name,
                        'policy_arn': policy_arn,
                        'issue': 'Too permissive (Action="*", Resource="*")'
                    })
            except botocore.exceptions.ClientError as e:
                findings.append({
                    'role': role_name,
                    'policy_type': 'attached',
                    'policy_name': policy_name,
                    'policy_arn': policy_arn,
                    'error': str(e)
                })
    except botocore.exceptions.ClientError as e:
        findings.append({'role': role_name, 'error': str(e)})
    return findings

def find_overpermissive_roles(iam=None):
    if iam is None:
        iam = boto3.client('iam')

    results = []
    paginator = iam.get_paginator('list_roles')

    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            results += analyze_inline_policies(iam, role_name)
            results += analyze_attached_policies(iam, role_name)

    return results
