import sys
import logging
import botocore.exceptions
from aws_scanner.core.configs import IamPolicyConfig
from aws_scanner.engines.iam_policy.analyzer import analyze_policy
from aws_scanner.engines.iam_policy.aws_iam_policy_collector import AwsIamPolicyCollector
from aws_scanner.engines.iam_policy.file_iam_policy_collector import FileIamPolicyCollector
from aws_scanner.core.boto3_wrapper import Boto3Wrapper

def get_collector(config: IamPolicyConfig, boto3_wrapper: Boto3Wrapper):
    if config.file:
        return FileIamPolicyCollector(config.file)
    return AwsIamPolicyCollector(boto3_wrapper, config.attached_only)

def analyze_policies(items):
    results = []
    for item in items:
        try:
            findings = analyze_policy(item)
            results.append({
                "policy_arn": item.arn,
                "policy_name": item.name,
                "vulnerabilities": findings
            })
        except Exception as e:
            logging.error(f"Error analyzing policy {item.name} ({item.arn}): {str(e)}")
            results.append({
                "policy_arn": item.arn,
                "policy_name": item.name,
                "error": str(e)
            })
    return results

def run_scanner(iam_policy_config: IamPolicyConfig, boto3_wrapper: Boto3Wrapper):
    logging.info("Starting IAM policy scanner")

    try:
        collector = get_collector(iam_policy_config, boto3_wrapper)
        items = collector.collect()
        return analyze_policies(items)
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"Connection error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        sys.exit(1)