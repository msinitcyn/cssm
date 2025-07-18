import sys
import logging
import botocore.exceptions

from .sg.collector import collect_security_groups
from .sg.analyzer import analyze_sg

def scan_security_groups(regions=None):
    results = []
    groups = collect_security_groups(regions)
    for sg in groups:
        issues = analyze_sg(sg)
        results.append({
            "group_id": sg.group_id,
            "group_name": sg.group_name,
            "issues": issues
        })
    return results

def run_sg_scanner(sg_config: dict):
    regions = sg_config.get("regions")  # <-- ключевой момент
    logging.info("Scanning security groups for open ports...")

    try:
        results = scan_security_groups(regions=regions)
    except botocore.exceptions.NoCredentialsError:
        logging.critical("No AWS credentials found. Aborting SG scan.")
        sys.exit(1)
    except botocore.exceptions.EndpointConnectionError as e:
        logging.critical(f"SG endpoint error: {e}")
        sys.exit(1)

    for item in results:
        if "error" in item:
            logging.warning(f"Security group scan error: {item['error']}")
            continue

        group_id = item.get("group_id", "<unknown>")
        group_name = item.get("group_name", "")
        issues = item.get("issues", [])

        for issue in issues:
            issue_id = issue.get("id", "<unknown>")
            raw = issue.get("raw_data", {})
            from_port = raw.get("from_port")
            cidr = raw.get("cidr") or raw.get("CidrIp") or raw.get("CidrIpv6")

            msg = f"{group_id} ({group_name}) — {issue_id}"
            if from_port is not None and cidr:
                msg += f": port {from_port} open to {cidr}"
            logging.warning(msg)

    return results
