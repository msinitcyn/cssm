from abc import ABC, abstractmethod
from typing import List
from aws_scanner.engines.iam_role.iam_role_data import IamRoleData


class IamRoleCollector(ABC):
    @abstractmethod
    def collect(self) -> List[IamRoleData]:
        pass