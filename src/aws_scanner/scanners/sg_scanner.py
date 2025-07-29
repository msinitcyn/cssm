import sys
import logging
import botocore.exceptions

from aws_scanner.core.configs import SgConfig
from aws_scanner.engines.sg.collector import collect_security_groups
from aws_scanner.engines.sg.analyzer import analyze_sg

def find_issues(sg_config: SgConfig):
    results = []
    items = collect_security_groups(regions=sg_config.regions)
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

def run_scanner(sg_config: SgConfig):
    logging.info("Starting Security Group scanner")
    try:
        results = find_issues(sg_config)
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
            logging.error(f"Error scanning {result.get('group_id')}: {result['error']}")
            continue

        for vuln in result.get("vulnerabilities", []):
            logging.warning(f"SG {result['group_id']} ({result['group_name']}): {vuln.get('description', 'Unknown vulnerability')}")

    return results