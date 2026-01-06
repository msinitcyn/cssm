import sys
import json
import logging
from aws_scanner.scanners.scan_orchestrator import run_scan
from .cli_parser import get_args
from .config_builder import create_run_config

def main():
    try:
        args = get_args()
        config = create_run_config(args)
        run_scan(config)
        sys.exit(0)

    except Exception as e:
        logging.debug("Scanner encountered unexpected error", exc_info=True)

        error_response = {
            "iam_roles": [],
            "s3_buckets": [],
            "security_groups": [],
            "errors": [{
                "error": f"Scanner execution failed: {str(e)}",
                "error_type": "execution_error"
            }]
        }

        print(json.dumps(error_response, indent=2))
        sys.exit(0)

if __name__ == "__main__":
    main()