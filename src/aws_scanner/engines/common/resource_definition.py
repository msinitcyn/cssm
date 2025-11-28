from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class ReferenceType(Enum):
    REF = "Ref"
    GET_ATT = "GetAtt"
    SUB = "Sub"
    DEPENDS_ON = "DependsOn"
    INLINE = "Inline"
    UNKNOWN = "Unknown"


@dataclass
class ResourceReference:
    target_logical_id: str
    reference_type: ReferenceType


@dataclass
class ResourceDefinition:
    logical_id: str
    resource_type: str
    properties: Dict[str, Any]
    references: List[ResourceReference] = field(default_factory=list)


@dataclass
class ResourceCollection:
    resources: Dict[str, ResourceDefinition] = field(default_factory=dict)

    def add_resource(self, resource: ResourceDefinition) -> None:
        self.resources[resource.logical_id] = resource

    def get_by_id(self, logical_id: str) -> Optional[ResourceDefinition]:
        return self.resources.get(logical_id)

    def get_resources_by_type(self, resource_type: str) -> List[ResourceDefinition]:
        return [r for r in self.resources.values() if r.resource_type == resource_type]