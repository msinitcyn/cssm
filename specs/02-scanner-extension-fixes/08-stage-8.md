### Stage 8 (Implementation): Add Top-Level Exception Boundary

**Goal**: Add exception handler at CLI entry point to catch all uncaught exceptions and return graceful error response.

#### Checklist

[x] Add exception boundary in CLI main function
  - File: `src/aws_scanner/cli/main.py`
  - Wrap main logic in try-except
  - Catch all Exception types

[x] Return JSON on exception
  - Create error response structure
  - Include error message
  - Include error type
  - Maintain same output format as success

[x] Always exit with code 0
  - Data errors return exit 0
  - Only execution failures (if any) return non-zero
  - Remove any sys.exit(1) calls for data errors

[x] Log stack trace internally
  - Use logging module for debugging
  - Don't show stack trace to user
  - Include in debug mode if needed

#### Implementation

```python
# src/aws_scanner/cli/main.py
import sys
import json
import logging
from aws_scanner.scanners.scan_orchestrator import run_scan

def main():
    try:
        result = run_scan(parse_args())

        # Format and output results
        output = format_output(result)
        print(json.dumps(output, indent=2))
        sys.exit(0)

    except Exception as e:
        # Log for debugging
        logging.exception("Scanner encountered unexpected error")

        # Return graceful error response
        error_response = {
            "iam_roles": [],
            "iam_policies": [],
            "s3_buckets": [],
            "security_groups": [],
            "errors": [{
                "error": f"Scanner execution failed: {str(e)}",
                "error_type": "execution_error"
            }]
        }

        print(json.dumps(error_response, indent=2))
        sys.exit(0)  # Still exit 0

if __name__ == "__main__":
    main()
```

Note: This is temporary safety net. Will be refined when implementing result-oriented architecture in Feature 03.
