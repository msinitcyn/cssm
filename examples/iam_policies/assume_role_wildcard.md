# AssumeRole Wildcard Resource Policy

This policy allows assuming any IAM role in any AWS account without restrictions.

**Risk Level**: Critical

**Security Issues**:
- `sts:AssumeRole` action with wildcard resource (`"Resource": "*"`)
- No conditions to restrict which roles can be assumed
- Enables cross-account privilege escalation
- Violates principle of least privilege

**Attack Scenarios**:

1. **Cross-Account Privilege Escalation**:
   ```bash
   # Discover assumable roles in target accounts
   aws sts assume-role --role-arn arn:aws:iam::TARGET-ACCOUNT:role/AdminRole --role-session-name attack
   ```

2. **Lateral Movement Within Account**:
   ```bash
   # Assume higher-privileged roles within the same account
   aws sts assume-role --role-arn arn:aws:iam::123456789012:role/DatabaseAdminRole --role-session-name lateral
   ```

3. **Service Role Abuse**:
   ```bash
   # Assume service roles to access resources indirectly
   aws sts assume-role --role-arn arn:aws:iam::123456789012:role/EC2-S3-AccessRole --role-session-name service
   ```

**Expected Scanner Findings**:
- `IAM_POLICY_ASSUME_ROLE_WILDCARD` detection
- Critical severity rating
- Specific remediation guidance

**Real-World Impact**:
If attached to a user or role, this policy effectively grants:
- **Account takeover** potential in any account with permissive trust policies
- **Cross-account data access** if trust relationships exist
- **Service impersonation** capabilities
- **Compliance violations** in regulated environments

**Common Misuse Patterns**:
- Development/testing accounts with overly permissive policies
- Cross-account access automation without proper scoping
- Service accounts with excessive assume-role permissions
- Break-glass access that's too broad

**Detection in the Wild**:
This pattern is commonly found in:
- CI/CD pipeline roles that need multi-account access
- Support/operations roles with broad access requirements
- Third-party integrations with poor security practices
- Legacy configurations that haven't been reviewed

**Remediation Options**:

1. **Restrict to Specific Roles**:
   ```json
   {
     "Effect": "Allow",
     "Action": "sts:AssumeRole",
     "Resource": [
       "arn:aws:iam::123456789012:role/DatabaseReadOnlyRole",
       "arn:aws:iam::123456789012:role/S3BackupRole"
     ]
   }
   ```

2. **Add Account Restrictions**:
   ```json
   {
     "Effect": "Allow",
     "Action": "sts:AssumeRole",
     "Resource": "*",
     "Condition": {
       "StringEquals": {
         "aws:RequestedRegion": "us-east-1"
       },
       "StringLike": {
         "aws:userid": "AIDACKCEVSQ6C2EXAMPLE:*"
       }
     }
   }
   ```

3. **Path-Based Restrictions**:
   ```json
   {
     "Effect": "Allow",
     "Action": "sts:AssumeRole",
     "Resource": "arn:aws:iam::*:role/CrossAccountAccess/*"
   }
   ```

4. **Time-Based Access**:
   ```json
   {
     "Effect": "Allow",
     "Action": "sts:AssumeRole",
     "Resource": "arn:aws:iam::123456789012:role/EmergencyAccessRole",
     "Condition": {
       "DateGreaterThan": {
         "aws:TokenIssueTime": "2024-01-01T00:00:00Z"
       },
       "DateLessThan": {
         "aws:TokenIssueTime": "2024-12-31T23:59:59Z"
       }
     }
   }
   ```

**Prevention Best Practices**:
- Always scope `sts:AssumeRole` to specific role ARNs when possible
- Use conditions to restrict when and how roles can be assumed
- Implement regular policy reviews and automated scanning
- Apply least-privilege principles consistently
- Monitor CloudTrail for unexpected AssumeRole activity
- Use AWS Organizations SCPs to prevent overly permissive policies

**Related Vulnerabilities**:
- Trust policy misconfigurations allowing broad principals
- Missing MFA requirements in assume-role policies
- Excessive session durations
- Weak external ID requirements for cross-account access