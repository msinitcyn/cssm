# Sensitive Actions Without Restrictive Conditions

This policy allows sensitive S3 actions without any conditions to restrict access.

**Risk Level**: Medium

**Security Issues**:
- Sensitive actions (`s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`) granted without conditions
- No IP address restrictions, MFA requirements, or time-based limitations
- Access could be used from anywhere, at any time, by any authenticated principal
- Violates defense-in-depth security principles

**Expected Scanner Findings**:
- `IAM_POLICY_SENSITIVE_ACTIONS_WITHOUT_CONDITIONS` detection
- Medium severity rating
- Specific remediation guidance about adding conditions

**Attack Scenarios**:

1. **Compromised Credentials**:
   ```bash
   # If credentials are leaked, attacker has unrestricted access
   aws s3 cp s3://sensitive-bucket/confidential.txt ./
   aws s3 cp malicious.txt s3://sensitive-bucket/
   aws s3 rm s3://sensitive-bucket/important-file.txt
   ```

2. **Insider Threat**:
   - No geographic restrictions allow access from anywhere
   - No time-based restrictions allow access outside business hours
   - No MFA requirements for sensitive operations

3. **Lateral Movement**:
   - If an EC2 instance or Lambda function is compromised, the attached role can access sensitive data without additional barriers

**Real-World Impact**:
This configuration allows:
- **Data exfiltration** from any location without detection
- **Data manipulation** or deletion without approval workflows
- **Compliance violations** in regulated environments requiring access controls
- **Audit trail gaps** without conditional logging requirements

**Common Risk Factors**:
- **Overly broad development policies** copied to production
- **Missing security reviews** during IAM policy creation
- **Lack of least-privilege implementation**
- **Insufficient understanding** of IAM condition capabilities

**Detection in the Wild**:
This pattern is commonly found in:
- Development and testing environments with relaxed security
- Quick fixes that bypass proper security controls
- Legacy policies created before security best practices were established
- Automated deployment pipelines without security validation

**Remediation Options**:

1. **IP Address Restrictions**:
   ```json
   {
     "Effect": "Allow",
     "Action": [
       "s3:GetObject",
       "s3:PutObject",
       "s3:DeleteObject"
     ],
     "Resource": "arn:aws:s3:::sensitive-bucket/*",
     "Condition": {
       "IpAddress": {
         "aws:SourceIp": [
           "203.0.113.0/24",
           "198.51.100.0/24"
         ]
       }
     }
   }
   ```

2. **MFA Requirements**:
   ```json
   {
     "Effect": "Allow",
     "Action": [
       "s3:PutObject",
       "s3:DeleteObject"
     ],
     "Resource": "arn:aws:s3:::sensitive-bucket/*",
     "Condition": {
       "Bool": {
         "aws:MultiFactorAuthPresent": "true"
       },
       "NumericLessThan": {
         "aws:MultiFactorAuthAge": "3600"
       }
     }
   }
   ```

3. **Time-Based Access**:
   ```json
   {
     "Effect": "Allow",
     "Action": [
       "s3:GetObject",
       "s3:PutObject"
     ],
     "Resource": "arn:aws:s3:::sensitive-bucket/*",
     "Condition": {
       "DateGreaterThan": {
         "aws:CurrentTime": "08:00:00Z"
       },
       "DateLessThan": {
         "aws:CurrentTime": "18:00:00Z"
       },
       "ForAllValues:StringEquals": {
         "aws:RequestedRegion": "us-east-1"
       }
     }
   }
   ```

4. **VPC Restrictions**:
   ```json
   {
     "Effect": "Allow",
     "Action": [
       "s3:GetObject",
       "s3:PutObject",
       "s3:DeleteObject"
     ],
     "Resource": "arn:aws:s3:::sensitive-bucket/*",
     "Condition": {
       "StringEquals": {
         "aws:SourceVpc": "vpc-12345678"
       }
     }
   }
   ```

5. **Secure Transport Enforcement**:
   ```json
   {
     "Effect": "Allow",
     "Action": [
       "s3:GetObject",
       "s3:PutObject",
       "s3:DeleteObject"
     ],
     "Resource": "arn:aws:s3:::sensitive-bucket/*",
     "Condition": {
       "Bool": {
         "aws:SecureTransport": "true"
       },
       "IpAddress": {
         "aws:SourceIp": "203.0.113.0/24"
       }
     }
   }
   ```

**Prevention Best Practices**:
- **Always add conditions** for sensitive actions, especially those involving data access or modification
- **Use IP restrictions** to limit access to known networks
- **Require MFA** for destructive or high-privilege actions
- **Implement time-based restrictions** for business-hours-only access
- **Enforce VPC endpoints** for internal service access
- **Regular policy reviews** to identify and remediate missing conditions
- **Automated scanning** in CI/CD pipelines to catch missing conditions early
- **Security training** for developers on IAM condition best practices

**Compliance Considerations**:
- **SOX compliance** may require additional access controls for financial data
- **HIPAA environments** need stronger restrictions for protected health information
- **PCI DSS** requires network segmentation and access controls for cardholder data
- **GDPR** may require geographic restrictions and audit trails for personal data

**Related Vulnerabilities**:
- Missing encryption requirements in conditions
- Overly broad resource specifications
- Lack of audit logging conditions
- Missing external ID requirements for cross-account access