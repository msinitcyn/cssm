ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'

def score_risk(report, bucket_data):
    if report.get("public"):
        cors = bucket_data.cors_config or {}
        cors_rules = cors.get("CORSRules", [])
        for rule in cors_rules:
            if "*" in rule.get("AllowedOrigins", []):
                return "high"
        return "medium"
    elif report.get("potentially_public"):
        return "low"
    return "low"

def analyze_s3_bucket(bucket_data):
    pab = bucket_data.pab_config
    policy = bucket_data.policy_doc or {}
    acl = bucket_data.acl_grants or []

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

    is_public_acl = any(
        grant.get("Grantee", {}).get("URI") == ALL_USERS_URI
        for grant in acl
    ) if can_use_acl else False

    is_public_policy = False
    condition_present = False
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal not in ("*", {"AWS": "*"}):
            continue
        action = stmt.get("Action")
        if isinstance(action, str):
            action = [action]
        if any(a in action for a in ("s3:GetObject", "s3:*")):
            if stmt.get("Condition"):
                condition_present = True
            else:
                is_public_policy = True

    result = {
        "bucket": bucket_data.name,
        "group": group,
        "access_vector": None,
        "public": False,
        "risk": "low"
    }

    if is_public_acl:
        result.update({"public": True, "access_vector": "ACL"})
    elif is_public_policy:
        result.update({"public": True, "access_vector": "Policy"})
    elif condition_present:
        result.update({"potentially_public": True, "access_vector": "Policy", "reason": "Condition present"})

    result["risk"] = score_risk(result, bucket_data)
    return result