# User With Inactive Access Keys

This IAM user has access keys that haven't been used for extended periods, creating unnecessary security risks.

**Risk Level**: Medium to High

**Security Issues**:
- Access key unused for over 2 years (last_used: 2022-03-20)  
- Access key created but never used (last_used: null)
- Stale credentials increase attack surface
- Forgotten keys may be embedded in old systems

**Expected Scanner Findings**:
- `IAM_USER_INACTIVE_ACCESS_KEY` for keys unused >90 days
- `IAM_USER_UNUSED_ACCESS_KEY` for keys never used
- `IAM_USER_OLD_ACCESS_KEY` for keys created >365 days ago

**Real-World Impact**:
If these old access keys are compromised, attackers gain programmatic access without detection since the keys aren't monitored for normal usage patterns.

**Attack Scenarios**:
- Keys found in old code repositories or configuration files
- Compromise of third-party services that stored these credentials
- Former employees or contractors with access to deprecated systems

**Remediation**:
Deactivate unused access keys immediately and delete after confirming no business impact. Implement regular key rotation policies for active credentials.