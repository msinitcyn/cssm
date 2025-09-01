# Public S3 Bucket Configuration

This S3 bucket configuration demonstrates multiple public access vulnerabilities that commonly lead to data breaches.

**Risk Level**: Critical

**Security Issues**:
- Public ACL grants read access to everyone (`"acl": "public-read"`)
- Bucket policy allows public access with wildcard principal (`"Principal": "*"`)
- Public Access Block settings are disabled, allowing public configurations
- No server access logging enabled - no audit trail of access
- No server-side encryption configured - data stored in plaintext

**Expected Scanner Findings**:
- `S3_PUBLIC_ACL` - High severity public ACL detection
- `S3_PUBLIC_POLICY` - High severity public policy detection  
- `S3_NO_ACCESS_LOGGING` - Low severity missing access logging
- `S3_NO_ENCRYPTION` - High severity missing encryption

**Real-World Impact**:
This configuration allows:
- **Public data access** from anywhere on the internet without authentication
- **Data enumeration** through public listing capabilities
- **No audit trail** of who accessed what data when
- **Data exposure** in plaintext without encryption protection
- **Compliance violations** in regulated industries (HIPAA, PCI DSS, SOX)

**Attack Scenarios**:

1. **Direct Public Access**:
   ```bash
   # Anyone can access objects without credentials
   curl https://my-public-bucket.s3.amazonaws.com/sensitive-file.txt
   aws s3 cp s3://my-public-bucket/confidential.pdf ./
   ```

2. **Data Enumeration**:
   ```bash
   # List all objects in the bucket
   aws s3 ls s3://my-public-bucket --no-sign-request
   ```

3. **Bulk Data Extraction**:
   ```bash
   # Download entire bucket contents
   aws s3 sync s3://my-public-bucket ./ --no-sign-request
   ```

**Detection in the Wild**:
This pattern is commonly found in:
- Development buckets accidentally made public
- Static website hosting configurations with overly broad permissions
- Data sharing setups that bypass proper access controls
- Legacy configurations from before Public Access Block was available

**Common Causes**:
- **Accidental public ACL** settings during bucket creation
- **Copy-paste errors** from public documentation examples
- **Misunderstanding** of S3 permission model complexity
- **Lack of security review** in deployment pipelines
- **Emergency fixes** that bypass security controls

**Historical Context**:
This configuration mirrors real-world incidents including:
- **Capital One breach (2019)**: Misconfigured S3 buckets exposed 100M+ customer records
- **Equifax incident**: S3 buckets with public access contributed to massive data exposure
- **Various leaks**: Government agencies, healthcare providers, and Fortune 500 companies

**Remediation Steps**:

1. **Remove Public ACL**:
   ```json
   {
     "acl": "private"
   }
   ```

2. **Restrict Bucket Policy**:
   ```json
   {
     "policy": {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Effect": "Allow",
           "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
           "Action": "s3:GetObject",
           "Resource": "arn:aws:s3:::my-bucket/*",
           "Condition": {
             "IpAddress": {
               "aws:SourceIp": "203.0.113.0/24"
             }
           }
         }
       ]
     }
   }
   ```

3. **Enable Public Access Block**:
   ```json
   {
     "block_public_access": {
       "BlockPublicAcls": true,
       "IgnorePublicAcls": true,
       "BlockPublicPolicy": true,
       "RestrictPublicBuckets": true
     }
   }
   ```

4. **Enable Access Logging**:
   ```json
   {
     "server_access_logging": {
       "enabled": true,
       "target_bucket": "access-logs-bucket",
       "target_prefix": "my-public-bucket/"
     }
   }
   ```

5. **Enable Encryption**:
   ```json
   {
     "encryption": {
       "server_side_encryption": "aws:kms",
       "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
     }
   }
   ```

**Prevention Best Practices**:
- **Always enable Public Access Block** on new buckets unless specifically needed
- **Use bucket policies with conditions** instead of ACLs for access control
- **Implement least-privilege access** with specific principals and IP restrictions
- **Enable CloudTrail and S3 access logging** for all buckets
- **Encrypt all data at rest** using AWS KMS or SSE-S3
- **Regular security audits** using tools like this scanner
- **Infrastructure as Code** with security validation in CI/CD pipelines

**Compliance Considerations**:
- **GDPR**: Public access to personal data violates data protection principles
- **HIPAA**: PHI must be encrypted and access-controlled
- **PCI DSS**: Cardholder data requires strict access controls and encryption
- **SOX**: Financial data needs audit trails and access restrictions

**Related Vulnerabilities**:
- Missing MFA requirements for sensitive operations
- Overly broad cross-account access permissions
- Weak or missing CORS policies allowing unauthorized web access
- Public website hosting without proper access controls