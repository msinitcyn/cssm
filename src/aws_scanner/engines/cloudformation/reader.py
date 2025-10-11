import json
from typing import Dict, Any

try:
    from cfn_tools import load_yaml, load_json
    HAS_CFN_FLIP = True
except ImportError:
    HAS_CFN_FLIP = False

from aws_scanner.engines.common.resource_definition import (
    ResourceDefinition,
    ResourceCollection
)


class CloudFormationReader:
    def read(self, content: str) -> ResourceCollection:
        template = self._parse(content)
        resources_dict = self._extract_resources(template)
        return self._to_resource_collection(resources_dict)

    def _parse(self, content: str) -> Dict[str, Any]:
        content = content.strip()

        if content.startswith('{'):
            return self._parse_json(content)
        else:
            return self._parse_yaml(content)

    def _parse_json(self, content: str) -> Dict[str, Any]:
        if HAS_CFN_FLIP:
            return load_json(content)
        return json.loads(content)

    def _parse_yaml(self, content: str) -> Dict[str, Any]:
        if not HAS_CFN_FLIP:
            raise ImportError(
                "cfn-flip is required for YAML parsing with CloudFormation intrinsic functions. "
                "Add 'cfn-flip>=1.3.0' to dependencies and run: pip install -e ."
            )
        return load_yaml(content)

    def _extract_resources(self, template: Dict[str, Any]) -> Dict[str, Any]:
        return template.get("Resources", {})

    def _to_resource_collection(self, resources_dict: Dict[str, Any]) -> ResourceCollection:
        collection = ResourceCollection()

        for logical_id, resource_data in resources_dict.items():
            resource_type = resource_data.get("Type", "")
            properties = resource_data.get("Properties", {})

            resource = ResourceDefinition(
                logical_id=logical_id,
                resource_type=resource_type,
                properties=properties
            )

            collection.add_resource(resource)

        return collection