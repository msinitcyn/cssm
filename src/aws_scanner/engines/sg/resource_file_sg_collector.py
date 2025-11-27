import json
from aws_scanner.engines.common.resource_definition import (
    ResourceCollection,
    ResourceDefinition
)


class ResourceFileSgCollector:
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> ResourceCollection:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        collection = ResourceCollection()

        if isinstance(raw_data, dict):
            if raw_data:
                self._process_security_group(raw_data, collection)
        elif isinstance(raw_data, list):
            for sg_data in raw_data:
                self._process_security_group(sg_data, collection)

        return collection

    def _process_security_group(self, sg_data: dict, collection: ResourceCollection):
        group_id = sg_data.get("group_id")
        if not group_id:
            return

        ingress_rules = sg_data.get("ingress_rules") or sg_data.get("ingress_permissions", [])
        egress_rules = sg_data.get("egress_rules", [])

        mapped_ingress = self._map_rules(ingress_rules)
        mapped_egress = self._map_rules(egress_rules)

        properties = {
            "GroupId": group_id,
            "GroupName": sg_data.get("group_name"),
            "SecurityGroupIngress": mapped_ingress,
            "SecurityGroupEgress": mapped_egress
        }

        if "vpc_id" in sg_data:
            properties["VpcId"] = sg_data.get("vpc_id")

        if "owner_id" in sg_data:
            properties["OwnerId"] = sg_data.get("owner_id")

        sg_resource = ResourceDefinition(
            logical_id=group_id,
            resource_type="AWS::EC2::SecurityGroup",
            properties=properties
        )

        collection.add_resource(sg_resource)

    def _map_rules(self, rules: list) -> list:
        mapped_rules = []
        for rule in rules:
            mapped_rule = {}

            if "protocol" in rule:
                mapped_rule["IpProtocol"] = rule["protocol"]
            elif "ip_protocol" in rule:
                mapped_rule["IpProtocol"] = rule["ip_protocol"]

            if "from_port" in rule:
                mapped_rule["FromPort"] = rule["from_port"]
            elif "FromPort" in rule:
                mapped_rule["FromPort"] = rule["FromPort"]

            if "to_port" in rule:
                mapped_rule["ToPort"] = rule["to_port"]
            elif "ToPort" in rule:
                mapped_rule["ToPort"] = rule["ToPort"]

            if "cidr_blocks" in rule:
                for cidr in rule["cidr_blocks"]:
                    rule_copy = mapped_rule.copy()
                    rule_copy["CidrIp"] = cidr
                    if "description" in rule:
                        rule_copy["Description"] = rule["description"]
                    mapped_rules.append(rule_copy)
            elif "CidrIp" in rule:
                mapped_rule["CidrIp"] = rule["CidrIp"]
                if "Description" in rule:
                    mapped_rule["Description"] = rule["Description"]
                mapped_rules.append(mapped_rule)
            elif "CidrIpv6" in rule:
                mapped_rule["CidrIpv6"] = rule["CidrIpv6"]
                if "Description" in rule:
                    mapped_rule["Description"] = rule["Description"]
                mapped_rules.append(mapped_rule)
            else:
                mapped_rules.append(mapped_rule)

        return mapped_rules