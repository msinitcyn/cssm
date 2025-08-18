# Wildcard Admin Access Policy

This IAM policy grants unrestricted access to all AWS services and resources.

**Risk Level**: Critical

**Security Issues**:
- `"Action": "*"` allows all possible AWS actions
- `"Resource": "*"` applies to all AWS resources
- No conditions or restrictions
- Violates principle of least privilege

**Expected Scanner Findings**:
- Wildcard action detection
- Wildcard resource detection
- Missing condition blocks
- Critical risk level assignment

**Real-World Impact**:
If attached to a role or user, this policy grants complete control over the AWS account, including ability to:
- Delete all resources
- Access sensitive data
- Create new admin users
- Modify billing and account settings

**Remediation**:
Replace with specific actions and resources needed for the actual use case.