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

        properties = {
            "GroupId": group_id,
            "GroupName": sg_data.get("group_name"),
            "IngressRules": ingress_rules,
            "EgressRules": egress_rules
        }

        if "vpc_id" in sg_data:
            properties["VpcId"] = sg_data.get("vpc_id")

        sg_resource = ResourceDefinition(
            logical_id=group_id,
            resource_type="AWS::EC2::SecurityGroup",
            properties=properties
        )

        collection.add_resource(sg_resource)