import pytest
from aws_scanner.core.result_formatter import format_results


def test_format_results_groups_by_entity_type():
    findings = [
        {"entity_type": "iam_role", "entity_name": "role1", "vulnerability": "WILDCARD_ACTION"},
        {"entity_type": "s3_bucket", "entity_name": "bucket1", "vulnerability": "PUBLIC_ACCESS"},
        {"entity_type": "security_group", "entity_name": "sg1", "vulnerability": "OPEN_INGRESS"},
        {"entity_type": "iam_role", "entity_name": "role2", "vulnerability": "ADMIN_ACCESS"},
    ]

    results = format_results(findings)

    assert "iam_roles" in results
    assert "s3_buckets" in results
    assert "security_groups" in results
    assert len(results["iam_roles"]) == 2
    assert len(results["s3_buckets"]) == 1
    assert len(results["security_groups"]) == 1


def test_format_results_creates_expected_structure():
    findings = [
        {"entity_type": "iam_role", "entity_name": "role1", "vulnerability": "WILDCARD_ACTION"},
        {"entity_type": "s3_bucket", "entity_name": "bucket1", "vulnerability": "PUBLIC_ACCESS"},
    ]

    results = format_results(findings)

    assert isinstance(results, dict)
    assert "iam_roles" in results
    assert "s3_buckets" in results
    assert "security_groups" in results
    assert isinstance(results["iam_roles"], list)
    assert isinstance(results["s3_buckets"], list)
    assert isinstance(results["security_groups"], list)


def test_format_results_groups_findings_per_entity():
    findings = [
        {"entity_type": "iam_role", "entity_name": "role1", "vulnerability": "WILDCARD_ACTION"},
        {"entity_type": "iam_role", "entity_name": "role1", "vulnerability": "ADMIN_ACCESS"},
        {"entity_type": "iam_role", "entity_name": "role2", "vulnerability": "WILDCARD_ACTION"},
    ]

    results = format_results(findings)

    assert len(results["iam_roles"]) == 2

    role1_result = next(r for r in results["iam_roles"] if r["role_name"] == "role1")
    assert len(role1_result["vulnerabilities"]) == 2

    role2_result = next(r for r in results["iam_roles"] if r["role_name"] == "role2")
    assert len(role2_result["vulnerabilities"]) == 1


def test_format_results_handles_empty_findings():
    findings = []

    results = format_results(findings)

    assert results == {
        "iam_roles": [],
        "s3_buckets": [],
        "security_groups": []
    }


def test_format_results_handles_unknown_entity_types():
    findings = [
        {"entity_type": "unknown_type", "entity_name": "entity1", "vulnerability": "SOME_VULN"},
        {"entity_type": "iam_role", "entity_name": "role1", "vulnerability": "WILDCARD_ACTION"},
    ]

    results = format_results(findings)

    assert len(results["iam_roles"]) == 1
    assert len(results["s3_buckets"]) == 0
    assert len(results["security_groups"]) == 0


def test_format_results_handles_iam_policy_type():
    findings = [
        {"entity_type": "iam_policy", "entity_name": "policy1", "vulnerability": "WILDCARD_ACTION"},
    ]

    results = format_results(findings)

    assert len(results["iam_roles"]) == 1
    role_result = results["iam_roles"][0]
    assert role_result["role_name"] == "policy1"
    assert len(role_result["vulnerabilities"]) == 1


def test_format_results_with_s3_buckets():
    findings = [
        {"entity_type": "s3_bucket", "entity_name": "bucket1", "vulnerability": "PUBLIC_ACCESS"},
        {"entity_type": "s3_bucket", "entity_name": "bucket1", "vulnerability": "NO_ENCRYPTION"},
        {"entity_type": "s3_bucket", "entity_name": "bucket2", "vulnerability": "PUBLIC_ACCESS"},
    ]

    results = format_results(findings)

    assert len(results["s3_buckets"]) == 2

    bucket1_result = next(r for r in results["s3_buckets"] if r["bucket_name"] == "bucket1")
    assert len(bucket1_result["vulnerabilities"]) == 2

    bucket2_result = next(r for r in results["s3_buckets"] if r["bucket_name"] == "bucket2")
    assert len(bucket2_result["vulnerabilities"]) == 1


def test_format_results_with_security_groups():
    findings = [
        {"entity_type": "security_group", "entity_name": "sg1", "vulnerability": "OPEN_INGRESS"},
        {"entity_type": "security_group", "entity_name": "sg1", "vulnerability": "OPEN_SSH"},
    ]

    results = format_results(findings)

    assert len(results["security_groups"]) == 1

    sg1_result = results["security_groups"][0]
    assert sg1_result["group_name"] == "sg1"
    assert len(sg1_result["vulnerabilities"]) == 2
