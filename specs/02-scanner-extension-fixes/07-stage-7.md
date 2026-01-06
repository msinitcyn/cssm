### Stage 7 (Tests): Scanner Never Crashes

**Goal**: Write tests to verify scanner never raises uncaught exceptions, always returns valid JSON with exit code 0.

#### Checklist

[x] Test scanner with malformed JSON file
  - Run scanner on file with invalid JSON
  - Verify exit code is 0
  - Verify output is valid JSON
  - Verify error message in output (not stderr)

[x] Test scanner with non-existent file
  - Run scanner on path that doesn't exist
  - Verify exit code is 0
  - Verify output is valid JSON
  - Verify error includes file path

[x] Test scanner with unexpected exception
  - Mock internal error (division by zero, etc.)
  - Verify scanner catches it
  - Verify exit code is 0
  - Verify output includes generic error message

[x] Test no Python stack traces in output
  - None of the error cases show traceback to user
  - Stack trace only in logs (if logging enabled)
