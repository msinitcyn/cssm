import json
from pathlib import Path
from scanners.s3_scanner import find_public_s3_buckets
from scanners.iam_scanner import find_overpermissive_roles
from scanners.sg_scanner import find_open_security_groups

def main():
    print("Scanning S3 buckets for public access...\n")
    s3_results = find_public_s3_buckets()

    for item in s3_results:
        bucket = item["bucket"]
        if item.get("error"):
            print(f"{bucket}: ERROR — {item['error']}")
        elif item.get("public"):
            print(f"{bucket} is PUBLIC")
        else:
            print(f"{bucket} is private")

    print("\nScanning IAM roles for over-permissive policies...\n")
    iam_results = find_overpermissive_roles()

    for item in iam_results:
        role = item.get("role", "<unknown>")
        error = item.get("error")
        policy_type = item.get("policy_type", "")
        policy_name = item.get("policy_name", "")
        if error:
            print(f"{role}: ERROR — {error}")
        else:
            print(f"{role}: {policy_type} policy '{policy_name}' is over-permissive")

    print("\nScanning security groups for open ports...\n")
    sg_results = find_open_security_groups()

    for item in sg_results:
        if "error" in item:
            print(f"Security group scan error: {item['error']}")
            continue

        group_id = item.get("group_id", "<unknown>")
        group_name = item.get("group_name", "")
        from_port = item.get("from_port")
        cidr = item.get("cidr")
        print(f"{group_id} ({group_name}): Port {from_port} open to {cidr}")

    # Save combined results
    output = {
        "s3_public_buckets": s3_results,
        "overpermissive_iam_roles": iam_results,
        "sg_open_ports": sg_results,
    }

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "report.json"

    with report_path.open("w") as f:
        json.dump(output, f, indent=2)

    print(f"\nReport saved to {report_path.resolve()}")

if __name__ == "__main__":
    main()
