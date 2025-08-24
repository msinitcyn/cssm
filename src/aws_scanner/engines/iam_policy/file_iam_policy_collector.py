from typing import List, Dict, Any, Union, Optional
import json
import logging
from aws_scanner.engines.common.iam_policy_data import IamPolicyData
from .iam_policy_collector import IamPolicyCollector

class FileIamPolicyCollector(IamPolicyCollector):
    def __init__(self, file_path: str):
        self._file_path = file_path

    def collect(self) -> List[IamPolicyData]:
        with open(self._file_path, 'r') as f:
            raw_data = json.load(f)

        if isinstance(raw_data, dict):
            return self._process_dict_format(raw_data)
        elif isinstance(raw_data, list):
            return self._process_list_format(raw_data)
        else:
            raise ValueError(f"Unsupported file format. Expected dict or list, got {type(raw_data)}")

    def _process_dict_format(self, raw_data: Dict[str, Any]) -> List[IamPolicyData]:
        if "Policies" in raw_data:
            logging.warning("Detected AWS CLI list-policies format. This contains metadata only, not policy documents. Use get-policy-version to get actual policy content.")
            return self._process_aws_cli_policies(raw_data["Policies"])

        if self._is_single_policy(raw_data):
            policy_data = self._create_policy_from_dict(raw_data, raw_data.get("name", "single-policy"))
            return [policy_data] if policy_data else []

        policies = []
        for policy_key, policy_dict in raw_data.items():
            policy_data = self._create_policy_from_dict(policy_dict, policy_key)
            if policy_data:
                policies.append(policy_data)

        return policies

    def _process_list_format(self, raw_data: List[Dict[str, Any]]) -> List[IamPolicyData]:
        policies = []

        for i, policy_dict in enumerate(raw_data):
            if not isinstance(policy_dict, dict):
                logging.warning(f"Policy at index {i} is not a dictionary, skipping")
                continue

            if self._is_aws_cli_metadata(policy_dict):
                logging.warning(f"Policy at index {i} appears to be AWS CLI metadata only (no Document field)")
                continue

            policy_name = self._extract_policy_name(policy_dict, f"policy-{i}")
            policy_data = self._create_policy_from_dict(policy_dict, policy_name)
            if policy_data:
                policies.append(policy_data)

        return policies

    def _process_aws_cli_policies(self, policies_list: List[Dict[str, Any]]) -> List[IamPolicyData]:
        result = []
        for policy_meta in policies_list:
            result.append(IamPolicyData(
                name=policy_meta.get("PolicyName", "unknown"),
                policy_type="attached",
                document={},
                arn=policy_meta.get("Arn"),
                is_inline=False
            ))
        return result

    def _is_single_policy(self, data: Dict[str, Any]) -> bool:
        policy_indicators = {
            "name", "policy_type", "document", "Document",
            "PolicyDocument", "PolicyName", "arn", "Arn"
        }
        return any(field in data for field in policy_indicators)

    def _is_aws_cli_metadata(self, data: Dict[str, Any]) -> bool:
        metadata_fields = {"PolicyName", "PolicyId", "Arn", "DefaultVersionId", "AttachmentCount"}
        has_metadata = any(field in data for field in metadata_fields)
        has_document = any(field in data for field in ["document", "Document", "PolicyDocument"])
        return has_metadata and not has_document

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
                        logging.warning(f"Failed to parse JSON document in field '{field}'")
                        continue
                elif isinstance(doc, dict):
                    return doc

        return None

    def _create_policy_from_dict(self, policy_dict: Dict[str, Any], fallback_name: str) -> Optional[IamPolicyData]:
        document = self._extract_policy_document(policy_dict)
        if not document:
            logging.warning(f"No policy document found for policy '{fallback_name}', skipping")
            return None

        policy_type = policy_dict.get("policy_type", policy_dict.get("PolicyType", "attached"))
        arn = policy_dict.get("arn", policy_dict.get("Arn"))
        is_inline = policy_dict.get("is_inline", policy_type == "inline")

        if "policy_type" not in policy_dict and "PolicyType" not in policy_dict:
            if arn and "aws:policy" in arn:
                policy_type = "aws_managed"
            elif is_inline:
                policy_type = "inline"
            else:
                policy_type = "attached"

        try:
            return IamPolicyData(
                name=self._extract_policy_name(policy_dict, fallback_name),
                policy_type=policy_type,
                document=document,
                arn=arn,
                is_inline=is_inline
            )
        except KeyError as e:
            logging.error(f"Failed to create policy '{fallback_name}': missing required field {e}")
            return None