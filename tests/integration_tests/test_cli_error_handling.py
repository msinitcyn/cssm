import subprocess
import json
import sys
import tempfile
from pathlib import Path


def test_scanner_handles_malformed_json():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{ invalid json content }')
        malformed_file = f.name

    try:
        cmd = [
            sys.executable, "-m", "aws_scanner.cli.main",
            "s3",
            "--file", malformed_file
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"Expected exit code 0, got {result.returncode}"

        output = json.loads(result.stdout)

        assert "errors" in output or "error" in str(output), "Expected error message in output"

        assert "Traceback" not in result.stdout, "Stack trace should not appear in stdout"
        assert "Traceback" not in result.stderr, "Stack trace should not appear in stderr"

    finally:
        Path(malformed_file).unlink()
