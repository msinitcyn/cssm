import subprocess
import json
from pathlib import Path
import sys
import pytest


def test_cloudformation_scanning():
    """
    Integration test for CloudFormation template scanning.

    This test scans the vulnerable_stack.yaml CloudFormation template
    and verifies that vulnerabilities are detected in:
    - IAM Role (wildcard permissions)
    - S3 Bucket (public access)
    - Security Group (open ports)

    Expected to fail until CloudFormation scanning is implemented (TDD approach).
    """

    # Setup paths
    template_path = Path("examples/cloudformation/vulnerable_stack.yaml")
    output_path = Path("output/cloudformation_test_report.json")

    # Ensure template exists
    if not template_path.exists():
        pytest.fail(f"CloudFormation template not found at {template_path}")

    # Clean up any existing output
    if output_path.exists():
        output_path.unlink()

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Run the scanner with --cloudformation flag
    cmd = [
        sys.executable, "-m", "aws_scanner.cli.main",
        "--cloudformation", str(template_path),
        "--output", str(output_path)
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=True
        )

        # Verify output file was created
        if not output_path.exists():
            pytest.fail(f"Output file was not created at {output_path}")

        # Load and parse the results
        with open(output_path, 'r') as f:
            scan_results = json.load(f)

        # Verify structure contains expected sections
        assert "iam_roles" in scan_results, "Results should contain 'iam_roles' section"
        assert "s3_buckets" in scan_results, "Results should contain 's3_buckets' section"
        assert "security_groups" in scan_results, "Results should contain 'security_groups' section"

        # Verify IAM Policy vulnerabilities detected
        iam_roles = scan_results["iam_roles"]
        assert len(iam_roles) > 0, "Should detect at least one IAM policy"

        # Check for wildcard permission vulnerabilities in any detected policy
        all_iam_vulnerabilities = []
        for role in iam_roles:
            all_iam_vulnerabilities.extend(role.get("vulnerabilities", []))

        assert len(all_iam_vulnerabilities) > 0, "Should have IAM policy vulnerabilities"

        iam_vuln_ids = {vuln["id"] for vuln in all_iam_vulnerabilities}
        expected_iam_vulns = {
            "IAM_POLICY_WILDCARD_ALL",
            "IAM_POLICY_WILDCARD_WITHOUT_RESTRICTIVE_CONDITION",
            "IAM_POLICY_PRIVILEGE_ESCALATION",
            "IAM_POLICY_ASSUME_ROLE_WILDCARD"
        }

        missing_iam_vulns = expected_iam_vulns - iam_vuln_ids
        assert not missing_iam_vulns, f"Missing IAM vulnerabilities: {missing_iam_vulns}"

        iam_vulnerabilities = all_iam_vulnerabilities

        # Verify S3 Bucket vulnerabilities detected
        s3_buckets = scan_results["s3_buckets"]
        assert len(s3_buckets) > 0, "Should detect at least one S3 bucket"

        vulnerable_bucket = next(
            (bucket for bucket in s3_buckets if bucket.get("bucket_name") == "VulnerableS3Bucket"),
            None
        )
        assert vulnerable_bucket is not None, "Should find VulnerableS3Bucket in results"

        # Check for public access vulnerabilities
        s3_vulnerabilities = vulnerable_bucket.get("vulnerabilities", [])
        assert len(s3_vulnerabilities) > 0, "Vulnerable bucket should have vulnerabilities"

        s3_vuln_ids = {vuln["id"] for vuln in s3_vulnerabilities}
        expected_s3_vulns = {
            "S3_PUBLIC_POLICY"
        }

        missing_s3_vulns = expected_s3_vulns - s3_vuln_ids
        assert not missing_s3_vulns, f"Missing S3 vulnerabilities: {missing_s3_vulns}"

        # Verify Security Group vulnerabilities detected
        security_groups = scan_results["security_groups"]
        assert len(security_groups) > 0, "Should detect at least one security group"

        vulnerable_sg = next(
            (sg for sg in security_groups if sg.get("group_name") == "VulnerableSecurityGroup"),
            None
        )
        assert vulnerable_sg is not None, "Should find VulnerableSecurityGroup in results"

        # Check for open port vulnerabilities
        sg_vulnerabilities = vulnerable_sg.get("vulnerabilities", [])
        assert len(sg_vulnerabilities) > 0, "VulnerableSecurityGroup should have vulnerabilities"

        sg_vuln_ids = {vuln["id"] for vuln in sg_vulnerabilities}
        expected_sg_vulns = {
            "SG_OPEN_MANAGEMENT_PORT",  # SSH and RDP
            "SG_ALL_PORTS_OPEN_PUBLIC"  # All TCP ports
        }

        missing_sg_vulns = expected_sg_vulns - sg_vuln_ids
        assert not missing_sg_vulns, f"Missing Security Group vulnerabilities: {missing_sg_vulns}"

        print("\n✓ CloudFormation scanning test passed!")
        print(f"  - Found {len(iam_vulnerabilities)} IAM role vulnerabilities")
        print(f"  - Found {len(s3_vulnerabilities)} S3 bucket vulnerabilities")
        print(f"  - Found {len(sg_vulnerabilities)} Security Group vulnerabilities")

    except subprocess.CalledProcessError as e:
        pytest.fail(
            f"Scanner command failed with exit code {e.returncode}\n"
            f"STDOUT: {e.stdout}\n"
            f"STDERR: {e.stderr}"
        )
    except subprocess.TimeoutExpired:
        pytest.fail("Scanner command timed out after 30 seconds")
    except json.JSONDecodeError as e:
        pytest.fail(f"Failed to parse scanner output as JSON: {e}")
    except FileNotFoundError as e:
        pytest.fail(f"File not found: {e}")
    finally:
        # Clean up output file
        if output_path.exists():
            output_path.unlink()


if __name__ == "__main__":
    test_cloudformation_scanning()