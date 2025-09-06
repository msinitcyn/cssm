# SSH Open to World

**File**: `examples/sg/ssh_open_to_world.md`

This security group allows SSH access from anywhere on the internet, creating a major security vulnerability.

**Risk Level**: High

**Security Issues**:
- SSH port (22) open to 0.0.0.0/0 
- Direct remote access from any IP address
- Prime target for brute force attacks
- No network-level access control

**Expected Scanner Findings**:
- `SG_OPEN_PORT` for SSH port 22 open to internet

**Real-World Impact**:
SSH access from anywhere allows attackers to attempt brute force attacks against all instances using this security group. Even with strong passwords, this creates unnecessary exposure.

**Attack Scenarios**:
- Automated brute force attacks against SSH
- Credential stuffing attacks using leaked password databases  
- Zero-day SSH vulnerabilities provide immediate access
- Lateral movement once any instance is compromised

**Remediation**:
- Restrict SSH access to specific IP ranges (office IPs, VPN endpoints)
- Use bastion hosts/jump servers for remote access
- Implement SSH key-based authentication only
- Consider AWS Session Manager for shell access without direct SSH