import json
from pathlib import Path
from .html_report import generate_html_report

def generate_report(config: dict, results: dict):
    output_path: Path = config["path"]

    # 1. Save JSON
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # 2. Optionally save HTML
    if config.get("html"):
        generate_html_report(results, output_path)
