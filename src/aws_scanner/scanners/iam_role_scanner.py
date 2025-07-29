import sys
import logging
import botocore.exceptions

from aws_scanner.core.configs import IamRoleConfig
from aws_scanner.engines.iam_role.collector import collect_iam_roles
from aws_scanner.engines.iam_role.analyzer import analyze_iam_role

def find_issues(iam_role_config: IamRoleConfig):
    results = []
    items = collect_iam_roles()
    for item in items:
        try:
            findings = analyze_iam_role(item)
            results.append({
                "role_name": item.name,
                "vulnerabilities": findings
            })
        except Exception as e:
            results.append({
                "role_name": item.name,
                "error": str(e)
            })
    return results

def run_scanner(iam_role_config: IamRoleConfig):
    logging.info("Starting IAM role scanner")
    try:
        results = find_issues(iam_role_config)
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"Connection error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        sys.exit(1)

    for result in results:
        if "error" in result:
            logging.error(f"Error scanning {result.get('role_name')}: {result['error']}")
            continue

        for vuln in result.get("vulnerabilities", []):
            logging.warning(f"Role {result['role_name']}: {vuln.get('description', 'Unknown vulnerability')}")

    return results