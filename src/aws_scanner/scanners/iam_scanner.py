import sys
import logging
import botocore.exceptions

from .iam.collector import collect_iam_roles
from .iam.role_analyzer import analyze_iam_role

def find_overpermissive_roles(config):
    results = []
    try:
        roles = collect_iam_roles()
    except botocore.exceptions.ClientError as e:
        return [{"role": "<error>", "error": str(e)}]

    for role_data in roles:
        try:
            findings = analyze_iam_role(role_data)
            results.append(findings)
        except Exception as e:
            results.append({
                "role": role_data.name,
                "error": str(e)
            })

    return results

def run_iam_scanner(config):
    logging.info("Scanning IAM roles for over-permissive policies...")
    try:
        results = find_overpermissive_roles(config)
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found. Aborting IAM scan.")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"IAM endpoint error: {e}")
        sys.exit(1)

    for role_result in results:
        if not isinstance(role_result, dict):
            logging.warning(f"IAM scan error or unexpected result: {role_result}")
            continue
        role = role_result.get("role", "<unknown>")
        policies = role_result.get("policies", [])
        for policy in policies:
            policy_type = policy.get("type", "")
            policy_name = policy.get("name", "")
            issues = policy.get("issues", [])
            if issues:
                for issue in issues:
                    logging.warning(f"{role}: {policy_type} policy '{policy_name}' is over-permissive: {issue.get('description', issue.get('id', ''))}")
    return results
