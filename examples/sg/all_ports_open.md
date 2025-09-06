# All Ports Open to Internet

**File**: `examples/sg/all_ports_open.md`

This security group allows all traffic from anywhere, representing the worst possible network security configuration.

**Risk Level**: Critical

**Security Issues**:
- All TCP ports (0-65535) open to 0.0.0.0/0
- All protocols (-1) open to 0.0.0.0/0  
- Complete absence of network-level security controls
- Every service on instances is directly exposed to internet

**Expected Scanner Findings**:
- `SG_OPEN_PORT` for all ports open to internet (multiple findings)

**Real-World Impact**:
This configuration essentially removes all network-level protection, making instances as vulnerable as if they were directly connected to the internet with no firewall.

**Attack Scenarios**:
- Any service running on any port is directly accessible
- Internal services (databases, caches, monitoring) exposed
- Administrative interfaces accessible from internet
- Complete network perimeter bypass

**Remediation**:
- Implement principle of least privilege - only open required ports
- Separate security groups by application tier (web, app, database)
- Use specific source IP ranges or security group references
- Regular security group audits and unused rule cleanup