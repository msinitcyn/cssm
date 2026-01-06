### Stage 10 (Implementation): Add iam_policies Output Key

**Goal**: Add separate `iam_policies` key to scanner output, distinct from `iam_roles`.

#### Checklist

[x] Add iam_policies key to result structure
  - File: `src/aws_scanner/core/result_formatter.py:6-10`
  - Add `"iam_policies": []` to results dict

[x] Route IAM policy findings to correct key
  - File: `src/aws_scanner/core/result_formatter.py:18-23`
  - Separate `iam_role` and `iam_policy` routing
  - Put policy findings in `iam_policies`
  - Put role findings in `iam_roles`

[x] Format IAM policy results
  - File: `src/aws_scanner/core/result_formatter.py:25-41`
  - Add `iam_policies` branch in formatting loop
  - Use `policy_name` and `policy_arn` fields
  - Structure: `{"policy_name": "...", "policy_arn": "...", "vulnerabilities": [...]}`

#### Implementation

```python
def format_results(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    results = {
        "iam_roles": [],
        "iam_policies": [],      # Add this
        "s3_buckets": [],
        "security_groups": []
    }

    entities_by_type = defaultdict(lambda: defaultdict(list))

    for finding in findings:
        entity_type = finding.get("entity_type", "")
        entity_name = finding.get("entity_name", "unknown")

        if entity_type == "iam_role":
            entities_by_type["iam_roles"][entity_name].append(finding)
        elif entity_type == "iam_policy":
            entities_by_type["iam_policies"][entity_name].append(finding)
        elif entity_type == "s3_bucket":
            entities_by_type["s3_buckets"][entity_name].append(finding)
        elif entity_type == "security_group":
            entities_by_type["security_groups"][entity_name].append(finding)

    for entity_type, entities in entities_by_type.items():
        for entity_name, entity_findings in entities.items():
            if entity_type == "iam_roles":
                results["iam_roles"].append({
                    "role_name": entity_name,
                    "vulnerabilities": entity_findings
                })
            elif entity_type == "iam_policies":
                results["iam_policies"].append({
                    "policy_name": entity_name,
                    "policy_arn": entity_findings[0].get("entity_arn", ""),
                    "vulnerabilities": entity_findings
                })
            # ... handle other types

    return results
```
