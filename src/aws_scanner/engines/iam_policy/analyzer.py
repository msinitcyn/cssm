from typing import Dict, Any
from aws_scanner.engines.common.policy_analyzer_utils import analyze_policy as analyze_iam_policy
from aws_scanner.engines.common.iam_policy_data import IamPolicyData

def analyze_policy(policy: IamPolicyData) -> Dict[str, Any]:
    return analyze_iam_policy(policy)