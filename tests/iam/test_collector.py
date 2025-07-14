import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from aws_scanner.scanners.iam.collector import collect_iam_roles
from aws_scanner.scanners.iam.iam_policy_data import IamPolicyData
from aws_scanner.scanners.iam.iam_role_data import IamRoleData

def test_collect_iam_roles_normal():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "RoleA"}]}
    ]
    # Inline
    mock_iam.list_role_policies.return_value = {"PolicyNames": ["Inline1"]}
    mock_iam.get_role_policy.return_value = {"PolicyDocument": {"Statement": []}}
    # Attached
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "Attached1", "PolicyArn": "arn:aws:iam::1:policy/Attached1"}]
    }
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {"PolicyVersion": {"Document": {"Statement": []}}}

    roles = collect_iam_roles(iam=mock_iam)
    assert len(roles) == 1
    role = roles[0]
    assert role.name == "RoleA"
    assert "Inline1" in role.inline_policies
    assert isinstance(role.inline_policies["Inline1"], IamPolicyData)
    assert "Attached1" in role.attached_policies
    assert isinstance(role.attached_policies["Attached1"], IamPolicyData)

def test_collect_iam_roles_inline_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "RoleB"}]}
    ]
    mock_iam.list_role_policies.side_effect = ClientError({'Error': {'Code': 'Denied', 'Message': 'fail'}}, 'ListRolePolicies')
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    roles = collect_iam_roles(iam=mock_iam)
    assert len(roles) == 1
    role = roles[0]
    assert "<inline_policy_error>" in role.inline_policies
    assert isinstance(role.inline_policies["<inline_policy_error>"], IamPolicyData)

def test_collect_iam_roles_attached_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "RoleC"}]}
    ]
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.side_effect = ClientError({'Error': {'Code': 'Denied', 'Message': 'fail'}}, 'ListAttachedRolePolicies')
    roles = collect_iam_roles(iam=mock_iam)
    assert len(roles) == 1
    role = roles[0]
    assert role.attached_policies == {}

def test_collect_iam_roles_attached_policy_version_error():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "RoleD"}]}
    ]
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "Attached2", "PolicyArn": "arn:aws:iam::1:policy/Attached2"}]
    }
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.side_effect = ClientError({'Error': {'Code': 'Denied', 'Message': 'fail'}}, 'GetPolicyVersion')
    roles = collect_iam_roles(iam=mock_iam)
    assert len(roles) == 1
    role = roles[0]
    assert "Attached2" in role.attached_policies
    assert role.attached_policies["Attached2"].document == {}

def test_collect_iam_roles_no_roles():
    mock_iam = MagicMock()
    mock_iam.get_paginator.return_value.paginate.return_value = [{"Roles": []}]
    roles = collect_iam_roles(iam=mock_iam)
    assert roles == []
