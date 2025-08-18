# Privilege Escalation via IAM Role Creation

This policy allows creating new IAM roles and attaching policies to them.

**Risk Level**: Critical

**Security Issues**:
- User can create a new role with admin permissions
- User can attach any managed policy (including PowerUserAccess, AdministratorAccess)
- No restrictions on what policies can be attached
- Classic privilege escalation vector

**Attack Scenario**:
1. Create new role: `aws iam create-role --role-name NewAdminRole --assume-role-policy-document file://trust.json`
2. Attach admin policy: `aws iam attach-role-policy --role-name NewAdminRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`
3. Assume the role: `aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/NewAdminRole`

**Expected Scanner Findings**:
- Privilege escalation path detection
- Wildcard resource with sensitive IAM actions
- High/Critical risk level

**Remediation**:
- Limit to specific role ARNs in Resource
- Add conditions to restrict policy attachment
- Use `iam:PassedToService` condition
- Consider using AWS managed policies for developers instead