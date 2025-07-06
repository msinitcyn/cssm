# aws_scanner/main.py

import json
from pathlib import Path
from scanners.s3_scanner import find_public_s3_buckets

def main():
    print("Scanning S3 buckets for public access...\n")

    results = find_public_s3_buckets()

    for item in results:
        bucket = item["bucket"]
        if item.get("error"):
            print(f"{bucket}: ERROR — {item['error']}")
        elif item.get("public"):
            print(f"{bucket} is PUBLIC")
        else:
            print(f"{bucket} is private")

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "report.json"

    with report_path.open("w") as f:
        json.dump(results, f, indent=2)

    print(f"\nReport saved to {report_path.resolve()}")

if __name__ == "__main__":
    main()