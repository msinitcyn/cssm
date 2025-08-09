import sys
import logging
import botocore.exceptions

from aws_scanner.core.configs import SgConfig
from aws_scanner.engines.sg.aws_sg_collector import AwsSgCollector
from aws_scanner.engines.sg.analyzer import analyze_sg

from aws_scanner.core.boto3_wrapper import Boto3Wrapper

def get_collector(sg_config: SgConfig, boto3_wrapper: Boto3Wrapper):
    return AwsSgCollector(boto3_wrapper, sg_config.regions)

def analyze_security_groups(items):
    results = []
    for item in items:
        try:
            findings = analyze_sg(item)
            results.append({
                "group_id": item.group_id,
                "group_name": item.group_name,
                "vulnerabilities": findings
            })
        except Exception as e:
            results.append({
                "group_id": item.group_id,
                "group_name": item.group_name,
                "error": str(e)
            })
    return results

def run_scanner(sg_config: SgConfig, boto3_wrapper: Boto3Wrapper):
    logging.info("Starting Security Group scanner")
    try:
        collector = get_collector(sg_config, boto3_wrapper)
        items = collector.collect()
        return analyze_security_groups(items)
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"Connection error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        sys.exit(1)