# Database Exposed to Internet

**File**: `examples/sg/database_exposed.md`

This security group exposes database ports directly to the internet, violating fundamental security architecture principles.

**Risk Level**: Critical

**Security Issues**:
- MySQL port (3306) and PostgreSQL port (5432) open to 0.0.0.0/0
- Databases should never be directly accessible from internet
- No application-tier protection
- Direct data access if database credentials are compromised

**Expected Scanner Findings**:
- `SG_OPEN_PORT` for MySQL port 3306 open to internet
- `SG_OPEN_PORT` for PostgreSQL port 5432 open to internet

**Real-World Impact**:
Direct database exposure is one of the most critical misconfigurations, leading to immediate data breaches if credentials are compromised through any means.

**Attack Scenarios**:
- Direct database brute force attacks
- SQL injection attempts against database engines
- Database vulnerability exploitation (CVEs)
- Immediate data exfiltration if credentials obtained elsewhere

**Remediation**:
- Move databases to private subnets with no internet gateway
- Allow database access only from application tier security groups
- Use RDS Proxy for connection pooling and additional security
- Enable database encryption and audit logging