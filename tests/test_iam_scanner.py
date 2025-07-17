from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from aws_scanner.scanners.iam_scanner import find_overpermissive_roles

def test_find_overpermissive_roles_normal():
    # Setup mock roles and findings
    mock_role1 = MagicMock()
    mock_role1.name = 'Role1'
    mock_role2 = MagicMock()
    mock_role2.name = 'Role2'

    # Mock the collector to return our test roles
    original_collect = find_overpermissive_roles.__globals__['collect_iam_roles']
    find_overpermissive_roles.__globals__['collect_iam_roles'] = MagicMock(return_value=[mock_role1, mock_role2])

    # Mock the analyzer to return test findings
    original_analyze = find_overpermissive_roles.__globals__['analyze_iam_role']
    find_overpermissive_roles.__globals__['analyze_iam_role'] = MagicMock(side_effect=[
        {"role": "Role1", "findings": []},
        {"role": "Role2", "findings": []}
    ])

    results = find_overpermissive_roles()
    assert len(results) == 2
    assert all(r["role"] in ["Role1", "Role2"] for r in results)

    # Restore original functions
    find_overpermissive_roles.__globals__['collect_iam_roles'] = original_collect
    find_overpermissive_roles.__globals__['analyze_iam_role'] = original_analyze

def test_find_overpermissive_roles_collect_error():
    # Mock collector to raise error
    original_collect = find_overpermissive_roles.__globals__['collect_iam_roles']
    find_overpermissive_roles.__globals__['collect_iam_roles'] = MagicMock(
        side_effect=ClientError({'Error': {'Code': 'AccessDenied'}}, 'operation')
    )

    results = find_overpermissive_roles()
    assert len(results) == 1
    assert results[0]["role"] == "<error>"
    assert "AccessDenied" in results[0]["error"]

    find_overpermissive_roles.__globals__['collect_iam_roles'] = original_collect

def test_find_overpermissive_roles_analyze_error():
    # Setup mock role
    mock_role = MagicMock()
    mock_role.name = 'ProblemRole'

    # Mock collector to return our test role
    original_collect = find_overpermissive_roles.__globals__['collect_iam_roles']
    find_overpermissive_roles.__globals__['collect_iam_roles'] = MagicMock(return_value=[mock_role])

    # Mock analyzer to raise error
    original_analyze = find_overpermissive_roles.__globals__['analyze_iam_role']
    find_overpermissive_roles.__globals__['analyze_iam_role'] = MagicMock(
        side_effect=Exception("Analysis failed")
    )

    results = find_overpermissive_roles()
    assert len(results) == 1
    assert results[0]["role"] == "ProblemRole"
    assert "Analysis failed" in results[0]["error"]

    # Restore original functions
    find_overpermissive_roles.__globals__['collect_iam_roles'] = original_collect
    find_overpermissive_roles.__globals__['analyze_iam_role'] = original_analyze