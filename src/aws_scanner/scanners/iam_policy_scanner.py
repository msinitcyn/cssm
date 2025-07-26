import sys
import logging
import botocore.exceptions

from aws_scanner.core.configs import IamPolicyConfig
from aws_scanner.engines.iam_policy.collector import collect_iam_policies
from aws_scanner.engines.iam_policy.analyzer import analyze_policy

def find_issues(iam_policy_config: IamPolicyConfig):
    results = []
    try:
        items = collect_iam_policies()
        for item in items:
            try:
                findings = analyze_policy(item)
                results.append({
                    "policy_arn": item.arn,
                    "policy_name": item.name,
                    "vulnerabilities": findings
                })
            except Exception as e:
                results.append({
                    "policy_arn": item.arn,
                    "policy_name": item.name,
                    "error": str(e)
                })
    except Exception as e:
        results.append({"error": str(e)})
    return results

def run_scanner(iam_policy_config: IamPolicyConfig):
    logging.info("Starting IAM policy scanner")
    try:
        results = find_issues(iam_policy_config)
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"Connection error: {e}")
        sys.exit(1)

    for result in results:
        if "error" in result:
            logging.error(f"Error scanning {result.get('policy_arn')}: {result['error']}")
            continue

        for vuln in result.get("vulnerabilities", []):
            logging.warning(f"Policy {result['policy_name']} ({result['policy_arn']}): {vuln.get('description', 'Unknown vulnerability')}")

    return results