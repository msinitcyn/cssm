### Stage 3 (Tests): Error Handling

[x] Malformed JSON produces clear error message
  - Test: `test_malformed_json_raises_json_decode_error` in `tests/unit_tests/engines/test_error_handling.py:10`
  - Verifies JSONDecodeError is raised for malformed JSON

[x] Malformed YAML produces clear error message
  - Test: `test_malformed_yaml_raises_yaml_error` in `tests/unit_tests/engines/test_error_handling.py:24`
  - Verifies YAMLError is raised for malformed YAML

[x] Error messages include file path
  - Test: `test_file_not_found_raises_file_not_found_error` in `tests/unit_tests/engines/test_error_handling.py:38`
  - Verifies FileNotFoundError is raised for missing files
