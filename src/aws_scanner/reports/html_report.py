from jinja2 import Environment, FileSystemLoader
from pathlib import Path

def generate_html_report(json_data: dict, output_path: Path):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report.html.j2")
    html = template.render(
        s3=json_data.get("s3_buckets", []),
        iam=json_data.get("iam_roles", []),
        sg=json_data.get("security_groups", [])
    )
    output_path.with_suffix(".html").write_text(html, encoding="utf-8")
