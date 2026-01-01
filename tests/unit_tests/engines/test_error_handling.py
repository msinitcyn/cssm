import pytest
import tempfile
import json
from pathlib import Path
import yaml
from aws_scanner.engines.iam_policy.resource_file_iam_policy_collector import ResourceFileIamPolicyCollector
from aws_scanner.engines.cloudformation.resource_file_cloudformation_collector import ResourceFileCloudFormationCollector


def test_malformed_json_raises_json_decode_error():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{"broken": json content}')
        malformed_path = f.name

    try:
        collector = ResourceFileIamPolicyCollector(malformed_path)

        with pytest.raises(json.JSONDecodeError):
            collector.collect()
    finally:
        Path(malformed_path).unlink()


def test_malformed_yaml_raises_yaml_error():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write('Resources:\n  - invalid: [yaml: structure')
        malformed_path = f.name

    try:
        collector = ResourceFileCloudFormationCollector(malformed_path)

        with pytest.raises(yaml.YAMLError):
            collector.collect()
    finally:
        Path(malformed_path).unlink()


def test_file_not_found_raises_file_not_found_error():
    nonexistent_path = "/tmp/nonexistent_file_12345.json"

    collector = ResourceFileIamPolicyCollector(nonexistent_path)

    with pytest.raises(FileNotFoundError):
        collector.collect()
