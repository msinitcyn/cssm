from unittest.mock import MagicMock
import botocore
from aws_scanner.scanners.s3_scanner import find_public_s3_buckets

class TestS3Scanner:
    def test_all_success(self):
        original_collect = find_public_s3_buckets.__globals__['collect_s3_bucket_data']
        original_analyze = find_public_s3_buckets.__globals__['analyze_s3_bucket']

        find_public_s3_buckets.__globals__['collect_s3_bucket_data'] = MagicMock(
            return_value=[{"Name": "bucket1"}, {"Name": "bucket2"}]
        )
        find_public_s3_buckets.__globals__['analyze_s3_bucket'] = MagicMock(
            side_effect=lambda x: {"bucket": x["Name"], "public": False}
        )

        result = find_public_s3_buckets()

        assert len(result) == 2
        assert all(r["public"] is False for r in result)

        find_public_s3_buckets.__globals__['collect_s3_bucket_data'] = original_collect
        find_public_s3_buckets.__globals__['analyze_s3_bucket'] = original_analyze

    def test_collect_error(self):
        original_collect = find_public_s3_buckets.__globals__['collect_s3_bucket_data']
        find_public_s3_buckets.__globals__['collect_s3_bucket_data'] = MagicMock(
            side_effect=botocore.exceptions.ClientError(
                {"Error": {"Code": "AccessDenied"}}, "operation"
            )
        )

        result = find_public_s3_buckets()
        assert len(result) == 1
        assert result[0]["bucket"] == "<collection_error>"

        find_public_s3_buckets.__globals__['collect_s3_bucket_data'] = original_collect

    def test_analyze_error(self):
        original_collect = find_public_s3_buckets.__globals__['collect_s3_bucket_data']
        original_analyze = find_public_s3_buckets.__globals__['analyze_s3_bucket']

        find_public_s3_buckets.__globals__['collect_s3_bucket_data'] = MagicMock(
            return_value=[{"Name": "problem-bucket"}]
        )
        find_public_s3_buckets.__globals__['analyze_s3_bucket'] = MagicMock(
            side_effect=botocore.exceptions.ClientError(
                {"Error": {"Code": "AnalyzeError"}}, "operation"
            )
        )

        result = find_public_s3_buckets()
        assert len(result) == 1
        assert result[0]["bucket"] == "problem-bucket"
        assert "AnalyzeError" in result[0]["error"]

        find_public_s3_buckets.__globals__['collect_s3_bucket_data'] = original_collect
        find_public_s3_buckets.__globals__['analyze_s3_bucket'] = original_analyze