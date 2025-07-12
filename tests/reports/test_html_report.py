import tempfile
from pathlib import Path
import os
from aws_scanner.reports.html_report import generate_html_report

import pytest

def sample_json_data():
    return {
        "s3_public_buckets": [
            {
                "bucket": "test-bucket",
                "group": "AllUsers",
                "access_vector": "READ",
                "public": True,
                "risk": "high",
                "reason": "Bucket is public"
            }
        ],
        "overpermissive_iam_roles": [
            {
                "role": "AdminRole",
                "policy_type": "inline",
                "policy_name": "FullAccess"
            }
        ],
        "sg_open_ports": [
            {
                "group_id": "sg-123456",
                "group_name": "default",
                "from_port": 22,
                "cidr": "0.0.0.0/0"
            }
        ]
    }


def test_generate_html_report(tmp_path):
    json_data = sample_json_data()
    output_path = tmp_path / "report.html"
    generate_html_report(json_data, output_path)
    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")
    # Check for S3 bucket
    assert "test-bucket" in html
    assert "Bucket is public" in html
    # Check for IAM role
    assert "AdminRole" in html
    assert "FullAccess" in html
    # Check for SG
    assert "sg-123456" in html
    assert "default" in html
    assert "22" in html
    assert "0.0.0.0/0" in html


def test_generate_html_report_empty(tmp_path):
    json_data = {}
    output_path = tmp_path / "report.html"
    generate_html_report(json_data, output_path)
    html = output_path.read_text(encoding="utf-8")
    assert "No S3 buckets found" in html
    assert "No over-permissive IAM roles found" in html
    assert "No open security groups found" in html
