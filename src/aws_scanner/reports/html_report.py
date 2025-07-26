from jinja2 import Environment, FileSystemLoader
from pathlib import Path

def generate_html_report(json_data: dict, output_path: Path):
    env = Environment(loader=FileSystemLoader("src/templates"))
    template = env.get_template("report.html.j2")
    
    processed_data = {
        "s3_buckets": [{
            "bucket": item["bucket_name"],
            "vulnerabilities": item.get("vulnerabilities", []),
            "error": item.get("error")
        } for item in json_data.get("s3_buckets", [])],
        "iam_roles": [{
            "role": item["role_name"],
            "vulnerabilities": item.get("vulnerabilities", []),
            "error": item.get("error")
        } for item in json_data.get("iam_roles", [])],
        "iam_policies": [{
            "policy": item["policy_arn"],
            "policy_name": item["policy_name"],
            "vulnerabilities": item.get("vulnerabilities", []),
            "error": item.get("error")
        } for item in json_data.get("iam_policies", [])],
        "security_groups": [{
            "group_id": item["group_id"],
            "group_name": item["group_name"],
            "vulnerabilities": item.get("vulnerabilities", []),
            "error": item.get("error")
        } for item in json_data.get("security_groups", [])]
    }

    html = template.render(**processed_data)
    output_path.with_suffix(".html").write_text(html, encoding="utf-8")