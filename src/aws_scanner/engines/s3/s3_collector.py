from abc import ABC, abstractmethod
from typing import List
from .s3_bucket_data import S3BucketData


class S3Collector(ABC):
    @abstractmethod
    def collect(self) -> List[S3BucketData]:
        pass