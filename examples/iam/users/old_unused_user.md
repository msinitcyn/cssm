# Old Unused User Account

This IAM user account has been inactive for over a year but still retains active credentials and high-privilege access.

**Risk Level**: High

**Security Issues**:
- User account inactive for over 1 year (password_last_used: 2023-07-20)
- Access key last used over 1 year ago (2023-08-15)
- Still has active `PowerUserAccess` policy attached
- Likely represents former employee account that wasn't properly deactivated

**Expected Scanner Findings**:
- `IAM_USER_STALE_ACCOUNT` for inactive user >365 days
- `IAM_USER_INACTIVE_ACCESS_KEY` for unused access key
- `IAM_USER_OLD_ACCESS_KEY` for key created in 2021

**Real-World Impact**:
Stale accounts with high privileges represent a significant security risk, especially if they belong to former employees who may still have access to stored credentials or system knowledge.

**Attack Scenarios**:
- Former employee using retained access for unauthorized access
- Compromise of old credentials stored in personal systems
- Privilege escalation through forgotten high-privilege accounts

**Remediation**:
Immediately disable the account by deactivating access keys and login profile. Conduct audit of account activity and remove all permissions before deletion.