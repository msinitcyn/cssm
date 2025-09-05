# Root User Access Keys

This root user has active access keys and lacks MFA protection, violating AWS security best practices.

**Risk Level**: Critical

**Security Issues**:
- Root user has active access keys (should never exist)
- No multi-factor authentication enabled
- Root user provides unrestricted access to all AWS services and billing
- Access keys create permanent, high-privilege programmatic access

**Expected Scanner Findings**:
- `IAM_ROOT_USER_ACCESS_KEYS` for active access keys on root user
- `IAM_ROOT_USER_NO_MFA` for root user without MFA protection

**Real-World Impact**:
Compromised root user credentials provide complete control over the AWS account, including ability to delete all resources, modify billing settings, and access all data across all services.

**Attack Scenarios**:
- Root access keys accidentally committed to code repositories
- Compromise through credential stuffing or phishing attacks
- Insider threats with unrestricted account access
- Lateral movement to other AWS accounts if keys are reused

**Remediation**:
Delete root user access keys immediately and enable MFA. Use IAM users with appropriate permissions for day-to-day operations instead of root user access.