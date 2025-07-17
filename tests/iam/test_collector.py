from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from aws_scanner.core.boto3_wrapper import Boto3Wrapper
from aws_scanner.scanners.iam.collector import collect_iam_roles
from aws_scanner.scanners.iam.iam_policy_data import IamPolicyData

def test_collect_iam_roles_normal():
    original_boto3 = Boto3Wrapper.get_iam
    mock_iam = MagicMock()
    Boto3Wrapper.get_iam = MagicMock(return_value=mock_iam)

    mock_iam.get_paginator.return_value.paginate.return_value = [{"Roles": [{"RoleName": "RoleA"}]}]
    mock_iam.list_role_policies.return_value = {"PolicyNames": ["Inline1"]}
    mock_iam.get_role_policy.return_value = {"PolicyDocument": {"Statement": []}}
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "Attached1", "PolicyArn": "arn:aws:iam::1:policy/Attached1"}]
    }
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {"PolicyVersion": {"Document": {"Statement": []}}}

    roles = collect_iam_roles()
    assert len(roles) == 1
    assert roles[0].name == "RoleA"
    assert "Inline1" in roles[0].inline_policies
    assert "Attached1" in roles[0].attached_policies

    Boto3Wrapper.get_iam = original_boto3

def test_collect_iam_roles_inline_error():
    original_boto3 = Boto3Wrapper.get_iam
    mock_iam = MagicMock()
    Boto3Wrapper.get_iam = MagicMock(return_value=mock_iam)

    mock_iam.get_paginator.return_value.paginate.return_value = [{"Roles": [{"RoleName": "RoleB"}]}]
    mock_iam.list_role_policies.side_effect = ClientError({'Error': {'Code': 'Denied', 'Message': 'fail'}}, 'ListRolePolicies')
    mock_iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

    roles = collect_iam_roles()
    assert len(roles) == 1
    assert "<inline_policy_error>" in roles[0].inline_policies

    Boto3Wrapper.get_iam = original_boto3

def test_collect_iam_roles_attached_error():
    original_boto3 = Boto3Wrapper.get_iam
    mock_iam = MagicMock()
    Boto3Wrapper.get_iam = MagicMock(return_value=mock_iam)

    mock_iam.get_paginator.return_value.paginate.return_value = [{"Roles": [{"RoleName": "RoleC"}]}]
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.side_effect = ClientError({'Error': {'Code': 'Denied', 'Message': 'fail'}}, 'ListAttachedRolePolicies')

    roles = collect_iam_roles()
    assert len(roles) == 1
    assert roles[0].attached_policies == {}

    Boto3Wrapper.get_iam = original_boto3

def test_collect_iam_roles_attached_policy_version_error():
    original_boto3 = Boto3Wrapper.get_iam
    mock_iam = MagicMock()
    Boto3Wrapper.get_iam = MagicMock(return_value=mock_iam)

    mock_iam.get_paginator.return_value.paginate.return_value = [{"Roles": [{"RoleName": "RoleD"}]}]
    mock_iam.list_role_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "Attached2", "PolicyArn": "arn:aws:iam::1:policy/Attached2"}]
    }
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.side_effect = ClientError({'Error': {'Code': 'Denied', 'Message': 'fail'}}, 'GetPolicyVersion')

    roles = collect_iam_roles()
    assert len(roles) == 1
    assert roles[0].attached_policies["Attached2"].document == {}

    Boto3Wrapper.get_iam = original_boto3

def test_collect_iam_roles_no_roles():
    original_boto3 = Boto3Wrapper.get_iam
    mock_iam = MagicMock()
    Boto3Wrapper.get_iam = MagicMock(return_value=mock_iam)

    mock_iam.get_paginator.return_value.paginate.return_value = [{"Roles": []}]

    roles = collect_iam_roles()
    assert roles == []

    Boto3Wrapper.get_iam = original_boto3