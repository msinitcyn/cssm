from dataclasses import dataclass
from typing import List


@dataclass
class Example:
    type: str
    name: str
    vulnerabilities: List[str]

    def get_path(self) -> str:
        return f'examples/{self.type}/{self.name}.json'

    def get_output_path(self) -> str:
        return f'examples/{self.type}/{self.name}.output.json'