from aws_scanner.scanners.scan_orchestrator import run_scan
from .cli_parser import get_args
from .config_builder import create_run_config

def main():
    args = get_args()
    config = create_run_config(args)
    run_scan(config)

if __name__ == "__main__":
    main()