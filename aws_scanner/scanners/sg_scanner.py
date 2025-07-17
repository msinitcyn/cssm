# aws_scanner/scanners/sg_scanner.py

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
