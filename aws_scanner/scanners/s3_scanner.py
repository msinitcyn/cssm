# aws_scanner/scanners/s3_scanner.py

import botocore
import boto3
import json

ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'

def check_public_access_block(s3, bucket_name):
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab.get('PublicAccessBlockConfiguration', {})
        if any([
            config.get('BlockPublicAcls'),
            config.get('IgnorePublicAcls'),
            config.get('BlockPublicPolicy'),
            config.get('RestrictPublicBuckets')
        ]):
            return False
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code != 'NoSuchPublicAccessBlock':
            return False
    return None  # None means no block, continue checking

def check_bucket_acl(s3, bucket_name):
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == ALL_USERS_URI:
                return True
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code in ('NoSuchBucket', 'NoSuchBucketAcl'):
            pass  # treat as not public
        else:
            raise
    return False

def check_bucket_policy(s3, bucket_name):
    try:
        policy_str = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
        policy = json.loads(policy_str)
        for statement in policy.get('Statement', []):
            if (
                statement.get('Effect') == 'Allow' and
                (
                    statement.get('Principal') == '*' or
                    statement.get('Principal') == {'AWS': '*'}
                ) and
                (
                    's3:GetObject' in statement.get('Action', []) or
                    's3:*' in statement.get('Action', []) or
                    (isinstance(statement.get('Action', []), list) and
                     ('s3:GetObject' in statement['Action'] or 's3:*' in statement['Action']))
                )
            ):
                return True
    except botocore.exceptions.ClientError:
        pass
    return False

def is_bucket_public(s3, bucket_name):
    pab_result = check_public_access_block(s3, bucket_name)
    if pab_result is False:
        return False
    if check_bucket_acl(s3, bucket_name):
        return True
    if check_bucket_policy(s3, bucket_name):
        return True
    return False

def find_public_s3_buckets(s3=None):
    if s3 is None:
        s3 = boto3.client('s3')
    result = []

    paginator = s3.get_paginator('list_buckets')
    for page in paginator.paginate():
        for bucket in page['Buckets']:
            bucket_name = bucket['Name']
            try:
                public = is_bucket_public(s3, bucket_name)
                result.append({'bucket': bucket_name, 'public': public})
            except botocore.exceptions.ClientError as e:
                result.append({'bucket': bucket_name, 'error': str(e)})

    return result
