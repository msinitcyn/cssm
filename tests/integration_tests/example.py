from dataclasses import dataclass
from typing import List


@dataclass
class Example:
    name: str
    vulnerabilities: List[str]
    
    def get_path(self) -> str:
        return f'examples/iam_policies/{self.name}.json'
    
    def get_output_path(self) -> str:
        return f'examples/iam_policies/{self.name}.output.json'