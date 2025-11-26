## Backward Compatibility Summary

**Breaking Changes**:
- **Findings format**: New analyzers do not add `policy_name` and `policy_type` context fields
  - Old: `{"id": "...", "policy_name": "MyPolicy", "policy_type": "inline", ...}`
  - New: `{"id": "...", ...}` (orchestrator may add context in future if needed)
- This is acceptable - will handle compatibility later if needed

**Maintains 100% compatibility with**:
- IAM Policy file format (supported-features.md §3.1) - single object, dict, list, AWS CLI formats
- IAM Role file format (supported-features.md §3.2) - dict with role names as keys
- S3 Bucket file format (supported-features.md §3.3) - dict with bucket names as keys, ACL string conversion
- Security Group file format (supported-features.md §3.4) - single object format
- All field aliases (trust_policy_document, pab_config, block_public_access, ingress_permissions)
- All existing example files in examples/ directory
- All existing CLI commands and flags (except new --cloudformation)
- Vulnerability detection rules (same vulnerabilities detected)

**No breaking changes in**:
- Phase 3: New collectors support all existing file formats
- Phase 5: Orchestrator produces findings for same vulnerabilities
- Phase 6: Cleanup only removes internal classes, not external APIs

---

