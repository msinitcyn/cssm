import boto3

class Boto3Wrapper:
    def get_iam(self):
        return boto3.client('iam')

    def get_s3(self):
        return boto3.client('s3')

    def get_ec2(self, region=None):
        if region:
            return boto3.client('ec2', region_name=region)
        return boto3.client('ec2')