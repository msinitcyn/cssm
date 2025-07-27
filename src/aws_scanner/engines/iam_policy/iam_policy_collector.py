from abc import ABC, abstractmethod
from typing import List
from aws_scanner.engines.common.iam_policy_data import IamPolicyData


class IamPolicyCollector(ABC):
    @abstractmethod
    def collect(self) -> List[IamPolicyData]:
        pass