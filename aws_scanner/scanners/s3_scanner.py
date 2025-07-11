import boto3
import botocore
import json

ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'


def get_public_access_block_config(s3, bucket_name):
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        return resp.get("PublicAccessBlockConfiguration", {})
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlock":
            return {}  # no block config = everything allowed
        else:
            raise


def analyze_pab_flags(pab):
    block_acls = pab.get("BlockPublicAcls", False)
    ignore_acls = pab.get("IgnorePublicAcls", False)
    block_policy = pab.get("BlockPublicPolicy", False)
    restrict_policy = pab.get("RestrictPublicBuckets", False)

    can_use_acl = not ignore_acls
    can_use_policy = not (block_policy and restrict_policy)

    if can_use_acl and can_use_policy:
        group = "ACL+Policy"
    elif can_use_acl:
        group = "ACL-only"
    elif can_use_policy:
        group = "Policy-only"
    else:
        group = "Blocked"

    return {
        "can_use_acl": can_use_acl,
        "can_use_policy": can_use_policy,
        "group": group
    }


def check_bucket_acl(s3, bucket_name):
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") == ALL_USERS_URI:
                return True
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("NoSuchBucket", "NoSuchBucketAcl"):
            pass  # ignore
        else:
            raise
    return False


def check_bucket_policy(s3, bucket_name):
    try:
        policy_str = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        policy = json.loads(policy_str)

        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue

            principal = stmt.get("Principal")
            if principal != "*" and principal != {"AWS": "*"}:
                continue

            action = stmt.get("Action", [])
            if isinstance(action, str):
                action = [action]

            if not any(a in action for a in ["s3:GetObject", "s3:*"]):
                continue

            if stmt.get("Condition"):
                return {"potentially_public": True, "reason": "has condition"}

            return {"public": True}

    except botocore.exceptions.ClientError:
        pass
    return {}


def is_bucket_public(s3, bucket_name):
    pab = get_public_access_block_config(s3, bucket_name)
    perms = analyze_pab_flags(pab)

    if perms["can_use_acl"]:
        if check_bucket_acl(s3, bucket_name):
            return {"public": True, "access_vector": "ACL", "group": perms["group"]}

    if perms["can_use_policy"]:
        policy_result = check_bucket_policy(s3, bucket_name)
        if policy_result.get("public"):
            return {"public": True, "access_vector": "Policy", "group": perms["group"]}
        if policy_result.get("potentially_public"):
            return {"potentially_public": True, "reason": policy_result["reason"], "access_vector": "Policy", "group": perms["group"]}

    return {"public": False, "group": perms["group"]}


def find_public_s3_buckets(s3=None):
    if s3 is None:
        s3 = boto3.client("s3")

    results = []
    try:
        buckets = s3.list_buckets()["Buckets"]
    except botocore.exceptions.ClientError as e:
        return [{"bucket": "<list_error>", "error": str(e)}]

    for bucket in buckets:
        name = bucket["Name"]
        try:
            pub = is_bucket_public(s3, name)
            pub["bucket"] = name
            results.append(pub)
        except botocore.exceptions.ClientError as e:
            results.append({"bucket": name, "error": str(e)})

    return results
