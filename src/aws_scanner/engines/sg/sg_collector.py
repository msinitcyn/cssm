from abc import ABC, abstractmethod
from typing import List
from .sg_data import SgData


class SgCollector(ABC):
    @abstractmethod
    def collect(self) -> List[SgData]:
        pass