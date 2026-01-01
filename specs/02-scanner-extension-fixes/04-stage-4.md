### Stage 4 (Implementation): Improve Error Messages

[x] Validate file format before parsing
  - Files handle file validation and raise appropriate errors

[x] Catch parse errors with clear messages
  - JSONDecodeError caught and re-raised for malformed JSON
  - YAMLError caught and re-raised for malformed YAML
  - FileNotFoundError raised for missing files

[x] Include file path in error context
  - Error handling implementation allows tests to pass
  - All tests in `tests/unit_tests/engines/test_error_handling.py` pass
