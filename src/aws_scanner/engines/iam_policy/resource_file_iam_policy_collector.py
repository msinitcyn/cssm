import json
import logging
from typing import Dict, Any, List, Optional
from aws_scanner.engines.common.resource_definition import (
    ResourceCollection,
    ResourceDefinition
)


class ResourceFileIamPolicyCollector:
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> ResourceCollection:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        collection = ResourceCollection()

        if isinstance(raw_data, dict):
            self._process_dict_format(raw_data, collection)
        elif isinstance(raw_data, list):
            self._process_list_format(raw_data, collection)

        return collection

    def _process_dict_format(self, raw_data: Dict[str, Any], collection: ResourceCollection):
        if "Policies" in raw_data:
            logging.warning("Detected AWS CLI list-policies format. This contains metadata only, not policy documents. Use get-policy-version to get actual policy content.")
            self._process_aws_cli_policies(raw_data["Policies"], collection)
            return

        if self._is_single_policy(raw_data):
            policy_name = self._extract_policy_name(raw_data, "single-policy")
            self._create_policy_resource(raw_data, policy_name, collection)
        else:
            for policy_key, policy_dict in raw_data.items():
                if not isinstance(policy_dict, dict):
                    continue
                policy_name = self._extract_policy_name(policy_dict, policy_key)
                self._create_policy_resource(policy_dict, policy_key, collection)

    def _process_list_format(self, raw_data: List[Dict[str, Any]], collection: ResourceCollection):
        for i, policy_dict in enumerate(raw_data):
            if not isinstance(policy_dict, dict):
                logging.warning(f"Policy at index {i} is not a dictionary, skipping")
                continue

            policy_name = self._extract_policy_name(policy_dict, f"policy-{i}")
            logical_id = policy_name
            self._create_policy_resource(policy_dict, logical_id, collection)

    def _process_aws_cli_policies(self, policies_list: List[Dict[str, Any]], collection: ResourceCollection):
        for policy_meta in policies_list:
            policy_name = policy_meta.get("PolicyName", "unknown")
            logical_id = policy_name

            policy_resource = ResourceDefinition(
                logical_id=logical_id,
                resource_type="AWS::IAM::Policy",
                properties={
                    "PolicyName": policy_name,
                    "PolicyDocument": {}
                }
            )
            collection.add_resource(policy_resource)

    def _create_policy_resource(self, policy_dict: Dict[str, Any], logical_id: str, collection: ResourceCollection):
        policy_document = self._extract_policy_document(policy_dict)

        if policy_document is None:
            logging.warning(f"No policy document found for policy '{logical_id}', skipping")
            return

        policy_name = self._extract_policy_name(policy_dict, logical_id)

        policy_resource = ResourceDefinition(
            logical_id=logical_id,
            resource_type="AWS::IAM::Policy",
            properties={
                "PolicyName": policy_name,
                "PolicyDocument": policy_document
            }
        )
        collection.add_resource(policy_resource)

    def _is_single_policy(self, data: Dict[str, Any]) -> bool:
        policy_indicators = {
            "name", "policy_type", "document", "Document",
            "PolicyDocument", "PolicyName", "arn", "Arn", "policy_name"
        }
        return any(field in data for field in policy_indicators)

    def _extract_policy_name(self, policy_dict: Dict[str, Any], fallback: str) -> str:
        name_fields = ["name", "Name", "PolicyName", "policy_name"]
        for field in name_fields:
            if field in policy_dict and policy_dict[field]:
                return policy_dict[field]
        return fallback

    def _extract_policy_document(self, policy_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        doc_fields = ["document", "Document", "PolicyDocument", "policy_document"]

        for field in doc_fields:
            if field in policy_dict:
                doc = policy_dict[field]

                if isinstance(doc, str):
                    try:
                        return json.loads(doc)
                    except json.JSONDecodeError:
                        logging.warning(f"Failed to parse stringified policy document for field '{field}'")
                        return None

                return doc

        return None