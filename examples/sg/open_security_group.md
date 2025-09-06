# Open SSH and RDP Security Group

**File**: `examples/sg/open_security_group.md`

This security group exposes both SSH and RDP management ports to the entire internet, creating multiple attack vectors for remote access.

**Risk Level**: High

**Security Issues**:
- SSH port (22) open to 0.0.0.0/0 - Linux/Unix remote access exposed
- RDP port (3389) open to 0.0.0.0/0 - Windows remote access exposed
- Both primary remote management protocols accessible from anywhere
- No geographic or network restrictions on administrative access

**Expected Scanner Findings**:
- `SG_OPEN_PORT` for SSH port 22 open to internet
- `SG_OPEN_PORT` for RDP port 3389 open to internet

**Real-World Impact**:
This configuration exposes remote management interfaces for both Linux and Windows systems to global attack attempts. It's particularly dangerous because it combines both major operating system management protocols in one vulnerable configuration.

**Attack Scenarios**:

1. **SSH Brute Force Attacks (Port 22)**:
   ```bash
   # Automated attacks against Linux/Unix systems
   ssh root@target-ip
   ssh admin@target-ip
   ssh ubuntu@target-ip
   ```

2. **RDP Brute Force Attacks (Port 3389)**:
   - Automated RDP login attempts against Windows systems
   - BlueKeep and other RDP-specific vulnerability exploitation
   - Remote desktop session hijacking

3. **Credential Stuffing**:
   - Using leaked password databases against both SSH and RDP
   - Multi-protocol attack campaigns targeting the same infrastructure

4. **Zero-Day Exploitation**:
   - SSH vulnerabilities provide immediate Linux/Unix access
   - RDP vulnerabilities (historically common) provide Windows access

**Common Causes**:
- **Quick fixes** during troubleshooting that were never reverted
- **Copy-paste configurations** from insecure examples
- **Legacy systems** migrated to cloud without security review
- **Development environments** accidentally exposed to production networks

**Real-World Examples**:
This type of misconfiguration has contributed to:
- **WannaCry ransomware spread**: RDP exposure facilitated lateral movement
- **SSH botnet recruitment**: Compromised servers added to cryptocurrency mining networks
- **Data center breaches**: Management port exposure leading to infrastructure compromise

**Remediation Options**:

1. **Restrict to Known IPs**:
   ```json
   {
     "cidr_blocks": [
       "203.0.113.0/24",  // Office network
       "198.51.100.5/32"  // VPN endpoint
     ]
   }
   ```

2. **Use Bastion/Jump Hosts**:
   - Single hardened entry point for administrative access
   - Multi-factor authentication required
   - Session logging and monitoring

3. **AWS Session Manager**:
   - Shell access without exposing SSH/RDP ports
   - Built-in logging and session recording
   - IAM-based access control

4. **VPN-Only Access**:
   - Require VPN connection before allowing management access
   - Network-level authentication before reaching instances

**Prevention Best Practices**:
- **Never expose management ports** (22, 3389) to 0.0.0.0/0
- **Use infrastructure as code** to prevent accidental misconfigurations
- **Implement security group scanning** in CI/CD pipelines
- **Regular security audits** of all network access rules
- **Principle of least privilege** - only allow necessary access from specific sources

**Compliance Considerations**:
- **SOC 2**: Logical access controls require restricted administrative access
- **ISO 27001**: Network security management mandates controlled remote access
- **PCI DSS**: Cardholder data environment requires restricted administrative access
- **NIST**: Access control frameworks prohibit unrestricted management interfaces

**Monitoring and Detection**:
- Set up CloudWatch alarms for failed SSH/RDP attempts
- Monitor VPC Flow Logs for suspicious connection patterns
- Implement AWS GuardDuty for automated threat detection
- Use AWS Config rules to detect overly permissive security groups