import subprocess
import json
from pathlib import Path
import sys
from tests.integration_tests.example import Example


def get_examples():
    examples_file = Path("tests/integration_tests/examples_to_test.json")

    if not examples_file.exists():
        raise FileNotFoundError(f"Examples configuration file not found: {examples_file}")

    with open(examples_file, 'r') as f:
        examples_data = json.load(f)

    if isinstance(examples_data, dict):
        examples_data = [examples_data]
    elif not isinstance(examples_data, list):
        raise ValueError("Examples file should contain a dict or list of dicts")

    examples = []
    for example_data in examples_data:
        required_fields = ['service', 'entity_type', 'name', 'vulnerabilities']
        if not all(field in example_data for field in required_fields):
            raise ValueError(f"Example missing required fields {required_fields}: {example_data}")

        example = Example(
            service=example_data['service'],
            entity_type=example_data['entity_type'],
            name=example_data['name'],
            vulnerabilities=example_data['vulnerabilities']
        )
        examples.append(example)

    return examples


def run_scanner(example: Example):
    output_path = Path(example.get_output_path())
    if output_path.exists():
        output_path.unlink()

    if example.service == "iam" and example.entity_type == "policies":
        cmd = [
            sys.executable, "-m", "aws_scanner.cli.main",
            "--output", example.get_output_path(),
            "iam",
            "--policies",
            "--file", example.get_path()
        ]
    elif example.service == "s3" and example.entity_type == "":
        cmd = [
            sys.executable, "-m", "aws_scanner.cli.main",
            "--output", example.get_output_path(),
            "s3",
            "--file", example.get_path()
        ]
    else:
        raise ValueError(f"Unsupported example configuration: service={example.service}, entity_type={example.entity_type}")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=Path.cwd()
    )

    if result.returncode != 0:
        raise RuntimeError(f"CLI command failed with return code {result.returncode}.\nStdout: {result.stdout}\nStderr: {result.stderr}")

    if not output_path.exists():
        raise RuntimeError(f"Output file was not created: {output_path}")

    with open(output_path, 'r') as f:
        output_data = json.load(f)

    return output_data


def validate_results(example: Example, scanner_output):
    if not isinstance(scanner_output, dict):
        raise AssertionError(f"Scanner output should be a dict, got {type(scanner_output)}")

    if example.service == "iam" and example.entity_type == "policies":
        result_key = 'iam_policies'
    elif example.service == "s3" and example.entity_type == "":
        result_key = 's3_buckets'
    else:
        raise ValueError(f"Unknown result key for service={example.service}, entity_type={example.entity_type}")

    if result_key not in scanner_output:
        raise AssertionError(f"Scanner output missing '{result_key}' field. Available fields: {list(scanner_output.keys())}")

    results = scanner_output[result_key]
    if not isinstance(results, list):
        raise AssertionError(f"{result_key} should be a list, got {type(results)}")

    if len(results) == 0:
        raise AssertionError(f"{result_key} is empty - no results found")

    result = results[0]

    if 'vulnerabilities' not in result:
        raise AssertionError(f"Result missing 'vulnerabilities' field. Available fields: {list(result.keys())}")

    vulnerabilities = result['vulnerabilities']
    if not isinstance(vulnerabilities, list):
        raise AssertionError(f"Vulnerabilities should be a list, got {type(vulnerabilities)}")

    found_vuln_ids = {vuln['id'] for vuln in vulnerabilities}
    expected_vuln_ids = set(example.vulnerabilities)

    missing_vulns = expected_vuln_ids - found_vuln_ids
    extra_vulns = found_vuln_ids - expected_vuln_ids

    if missing_vulns or extra_vulns:
        error_msg = []
        if missing_vulns:
            error_msg.append(f"Missing expected vulnerabilities: {missing_vulns}")
        if extra_vulns:
            error_msg.append(f"Found unexpected vulnerabilities: {extra_vulns}")
        error_msg.extend([
            f"Expected vulnerabilities: {expected_vuln_ids}",
            f"Found vulnerabilities: {found_vuln_ids}"
        ])
        raise AssertionError("\n".join(error_msg))

    print(f"Example '{example.service}/{example.entity_type}/{example.name}' passed validation:")
    print(f"Expected vulnerabilities: {sorted(expected_vuln_ids)}")
    print(f"Found vulnerabilities: {sorted(found_vuln_ids)}")


def test_examples():
    try:
        examples = get_examples()
        print(f"Running tests for {len(examples)} example(s)...")

        for i, example in enumerate(examples, 1):
            print(f"\n--- Test {i}/{len(examples)}: {example.service}/{example.entity_type}/{example.name} ---")

            input_path = Path(example.get_path())
            if not input_path.exists():
                raise FileNotFoundError(f"Input file not found: {input_path}")

            try:
                scanner_output = run_scanner(example)
                validate_results(example, scanner_output)
                print(f"✓ Test {i} passed: {example.service}/{example.entity_type}/{example.name}")

            except subprocess.TimeoutExpired:
                raise AssertionError(f"CLI command timed out after 30 seconds for example: {example.name}")
            except FileNotFoundError as e:
                raise AssertionError(f"File not found for example {example.name}: {e}")
            except RuntimeError as e:
                raise AssertionError(f"Runtime error for example {example.name}: {e}")
            except json.JSONDecodeError as e:
                raise AssertionError(f"Invalid JSON output for example {example.name}: {e}")
            finally:
                output_path = Path(example.get_output_path())
                if output_path.exists():
                    output_path.unlink()

        print(f"\nAll {len(examples)} tests passed!")

    except Exception as e:
        print(f"\nTest failed: {e}")
        raise


if __name__ == "__main__":
    test_examples()