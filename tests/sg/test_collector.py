import pytest
from aws_scanner.scanners.sg.collector import collect_security_groups
from aws_scanner.scanners.sg.security_group_data import SecurityGroupData

class DummyEC2:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-abc",
                    "GroupName": "test",
                    "OwnerId": "1111",
                    "IpPermissions": [
                        {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
                },
                {
                    "GroupId": "sg-def",
                    "GroupName": "test2",
                    "OwnerId": "2222",
                    "IpPermissions": []
                }
            ]
        }

def test_collect_security_groups_returns_security_group_data():
    ec2 = DummyEC2()
    groups = collect_security_groups(ec2)
    assert isinstance(groups, list)
    assert all(isinstance(g, SecurityGroupData) for g in groups)
    assert groups[0].group_id == "sg-abc"
    assert groups[1].group_id == "sg-def"
    assert groups[0].ingress_permissions[0]["FromPort"] == 22
