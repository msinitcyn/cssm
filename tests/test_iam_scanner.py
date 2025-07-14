import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from aws_scanner.scanners.iam_scanner import find_overpermissive_roles


def test_find_overpermissive_roles_normal():
    mock_iam = MagicMock()
    mock_role1 = MagicMock()
    mock_role1.name = 'Role1'
    mock_role2 = MagicMock()
    mock_role2.name = 'Role2'
    roles = [mock_role1, mock_role2]
    findings_role1 = [{"role": "Role1", "issue": "Too permissive"}]
    findings_role2 = [{"role": "Role2", "issue": "OK"}]

    with patch('aws_scanner.scanners.iam_scanner.collect_iam_roles', return_value=roles) as mock_collect, \
         patch('aws_scanner.scanners.iam_scanner.analyze_iam_role', side_effect=[findings_role1, findings_role2]) as mock_analyze:
        results = find_overpermissive_roles(iam=mock_iam)
        assert findings_role1[0] in results
        assert findings_role2[0] in results
        mock_collect.assert_called_once_with(mock_iam)
        assert mock_analyze.call_count == 2


def test_find_overpermissive_roles_collect_error():
    mock_iam = MagicMock()
    error = ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'Not authorized'}}, 'ListRoles')
    with patch('aws_scanner.scanners.iam_scanner.collect_iam_roles', side_effect=error):
        results = find_overpermissive_roles(iam=mock_iam)
        assert len(results) == 1
        assert results[0]["role"] == "<error>"
        assert "Not authorized" in results[0]["error"]


def test_find_overpermissive_roles_analyze_error():
    mock_iam = MagicMock()
    mock_role = MagicMock()
    mock_role.name = 'Role1'
    roles = [mock_role]
    with patch('aws_scanner.scanners.iam_scanner.collect_iam_roles', return_value=roles), \
         patch('aws_scanner.scanners.iam_scanner.analyze_iam_role', side_effect=Exception("analyze error")):
        results = find_overpermissive_roles(iam=mock_iam)
        assert len(results) == 1
        assert results[0]["role"] == "Role1"
        assert "analyze error" in results[0]["error"]


def test_find_overpermissive_roles_uses_default_iam():
    # Patch boto3.client to check that it's called if iam is None
    with patch('boto3.client') as mock_boto_client, \
         patch('aws_scanner.scanners.iam_scanner.collect_iam_roles', return_value=[]):
        find_overpermissive_roles(iam=None)
        mock_boto_client.assert_called_once_with('iam')
