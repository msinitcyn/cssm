import botocore.exceptions
import json
from typing import Optional
from aws_scanner.engines.common.resource_definition import ResourceCollection, ResourceDefinition
from aws_scanner.core.boto3_wrapper import Boto3Wrapper


class ResourceAwsS3Collector:
    def __init__(self, boto3_wrapper: Boto3Wrapper, bucket_name: Optional[str] = None):
        self._boto3_wrapper = boto3_wrapper
        self._bucket_name = bucket_name

    def collect(self) -> ResourceCollection:
        s3 = self._boto3_wrapper.get_s3()
        collection = ResourceCollection()

        if self._bucket_name:
            buckets = [{"Name": self._bucket_name}]
        else:
            try:
                buckets = s3.list_buckets().get("Buckets", [])
            except botocore.exceptions.ClientError:
                return collection

        for bucket in buckets:
            bucket_name = bucket["Name"]
            properties = self._collect_bucket_properties(s3, bucket_name)

            bucket_resource = ResourceDefinition(
                logical_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                properties=properties
            )
            collection.add_resource(bucket_resource)

        return collection

    def _collect_bucket_properties(self, s3, bucket_name: str) -> dict:
        properties = {"BucketName": bucket_name}

        try:
            pab = s3.get_public_access_block(Bucket=bucket_name).get("PublicAccessBlockConfiguration")
            if pab:
                properties["PublicAccessBlockConfiguration"] = pab
        except botocore.exceptions.ClientError:
            pass

        try:
            acl_grants = s3.get_bucket_acl(Bucket=bucket_name).get("Grants", [])
            if acl_grants:
                properties["AclGrants"] = acl_grants
        except botocore.exceptions.ClientError:
            pass

        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket_name).get("Policy")
            if policy_str:
                try:
                    policy_doc = json.loads(policy_str)
                    properties["Policy"] = policy_doc
                except json.JSONDecodeError:
                    pass
        except botocore.exceptions.ClientError:
            pass

        try:
            cors_response = s3.get_bucket_cors(Bucket=bucket_name)
            cors_rules = cors_response.get("CORSRules", [])
            if cors_rules:
                properties["CorsConfiguration"] = {"CorsRules": cors_rules}
        except botocore.exceptions.ClientError:
            pass

        try:
            website_config = s3.get_bucket_website(Bucket=bucket_name)
            if website_config:
                properties["WebsiteConfiguration"] = website_config
        except botocore.exceptions.ClientError:
            pass

        try:
            logging_response = s3.get_bucket_logging(Bucket=bucket_name)
            logging_enabled = logging_response.get("LoggingEnabled")
            if logging_enabled:
                properties["LoggingConfiguration"] = {"LoggingEnabled": logging_enabled}
        except botocore.exceptions.ClientError:
            pass

        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if versioning:
                properties["VersioningConfiguration"] = versioning
        except botocore.exceptions.ClientError:
            pass

        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            if encryption:
                properties["BucketEncryption"] = encryption
        except botocore.exceptions.ClientError:
            pass

        try:
            versioning_for_mfa = s3.get_bucket_versioning(Bucket=bucket_name)
            mfa_delete_status = versioning_for_mfa.get("MFADelete")
            if mfa_delete_status:
                properties["MfaDelete"] = mfa_delete_status == "Enabled"
            else:
                properties["MfaDelete"] = False
        except botocore.exceptions.ClientError:
            pass

        return properties
