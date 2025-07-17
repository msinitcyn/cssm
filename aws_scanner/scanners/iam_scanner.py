import botocore.exceptions

from .iam.collector import collect_iam_roles
from .iam.role_analyzer import analyze_iam_role

def find_overpermissive_roles():
    results = []
    try:
        roles = collect_iam_roles()
    except botocore.exceptions.ClientError as e:
        return [{"role": "<error>", "error": str(e)}]

    for role_data in roles:
        try:
            findings = analyze_iam_role(role_data)
            results.append(findings)
        except Exception as e:
            results.append({
                "role": role_data.name,
                "error": str(e)
            })

    return results
