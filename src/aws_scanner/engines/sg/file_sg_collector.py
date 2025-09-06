import json
from typing import List, Dict, Any, Optional
from .sg_collector import SgCollector
from .sg_data import SgData

class FileSgCollector(SgCollector):
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> List[SgData]:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        results = []

        if isinstance(raw_data, dict):
            if self._is_single_sg(raw_data):
                sg_data = self._create_sg_from_dict(raw_data, raw_data.get("group_id", raw_data.get("name", "sg-unknown")))
                if sg_data:
                    results.append(sg_data)
            else:
                for idx, (sg_key, sg_dict) in enumerate(raw_data.items()):
                    group_id = sg_dict.get("group_id", sg_dict.get("name", f"sg-{idx}"))
                    sg_data = self._create_sg_from_dict(sg_dict, group_id)
                    if sg_data:
                        results.append(sg_data)
        elif isinstance(raw_data, list):
            for idx, sg_dict in enumerate(raw_data):
                group_id = sg_dict.get("group_id", sg_dict.get("name", f"sg-{idx}"))
                sg_data = self._create_sg_from_dict(sg_dict, group_id)
                if sg_data:
                    results.append(sg_data)

        return results

    def _is_single_sg(self, data: Dict[str, Any]) -> bool:
        sg_indicators = {
            "group_id", "group_name", "owner_id", "ingress_rules",
            "ingress_permissions", "name", "resource_type"
        }
        return any(field in data for field in sg_indicators)

    def _create_sg_from_dict(self, sg_dict: Dict[str, Any], group_id: str) -> Optional[SgData]:
        group_name = sg_dict.get("group_name", sg_dict.get("name", ""))
        owner_id = sg_dict.get("owner_id", "")
        region = sg_dict.get("region")

        ingress_rules = sg_dict.get("ingress_rules") or sg_dict.get("ingress_permissions") or []

        normalized_rules = []
        for rule in ingress_rules:
            normalized_rule = self._normalize_rule(rule)
            if normalized_rule:
                normalized_rules.append(normalized_rule)

        return SgData(
            group_id=group_id,
            group_name=group_name,
            owner_id=owner_id,
            ingress_rules=normalized_rules,
            region=region
        )

    def _normalize_rule(self, rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        normalized = {}

        if "protocol" in rule:
            normalized["IpProtocol"] = rule["protocol"]
        elif "IpProtocol" in rule:
            normalized["IpProtocol"] = rule["IpProtocol"]

        if "from_port" in rule:
            normalized["FromPort"] = rule["from_port"]
        elif "FromPort" in rule:
            normalized["FromPort"] = rule["FromPort"]

        if "to_port" in rule:
            normalized["ToPort"] = rule["to_port"]
        elif "ToPort" in rule:
            normalized["ToPort"] = rule["ToPort"]

        ip_ranges = []
        if "cidr_blocks" in rule:
            for cidr in rule["cidr_blocks"]:
                ip_ranges.append({"CidrIp": cidr})
        elif "IpRanges" in rule:
            ip_ranges = rule["IpRanges"]

        if ip_ranges:
            normalized["IpRanges"] = ip_ranges

        ipv6_ranges = []
        if "ipv6_cidr_blocks" in rule:
            for cidr in rule["ipv6_cidr_blocks"]:
                ipv6_ranges.append({"CidrIpv6": cidr})
        elif "Ipv6Ranges" in rule:
            ipv6_ranges = rule["Ipv6Ranges"]

        if ipv6_ranges:
            normalized["Ipv6Ranges"] = ipv6_ranges

        if "source_security_group_id" in rule:
            normalized["UserIdGroupPairs"] = [{"GroupId": rule["source_security_group_id"]}]
        elif "UserIdGroupPairs" in rule:
            normalized["UserIdGroupPairs"] = rule["UserIdGroupPairs"]

        if "description" in rule:
            normalized["Description"] = rule["description"]
        elif "Description" in rule:
            normalized["Description"] = rule["Description"]

        return normalized if normalized else None