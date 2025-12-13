# CloudFormation Support - Feature Definition

**Feature Branch**: `feature/cloudformation-support`
**Milestone**: 10
**Status**: PHASE 10 COMPLETE - Edge Case Test Coverage Complete

---

## ⚠️ API Precision Guidelines

**CRITICAL**: To avoid API mismatches between tests and implementations, follow these rules when writing or reading specs:

### Writing Tests From Specs
1. **Use EXACT method names** from specs - if spec says `get_by_id()`, don't use `get_resource()`
2. **Copy class names exactly** - including case and full paths
3. **Check existing code** - if spec references existing class, look at its actual API in the source file
4. **Ask for clarification** - if method name is ambiguous, request spec update

### Example of Good vs Bad Spec Writing
❌ **Bad**: "Test can retrieve bucket from collection"
✅ **Good**: "Test can retrieve bucket using `collection.get_by_id(logical_id)` method"

❌ **Bad**: "Returns a resource collection"
✅ **Good**: "Returns `ResourceCollection` (from `aws_scanner.engines.common.resource_definition`)"

### API Reference Location

**All core APIs are defined in**: `src/aws_scanner.engines/common/resource_definition.py`

Key classes to reference:
- `ResourceCollection` - Container for resources with methods: `add_resource()`, `get_by_id()`, `get_resources_by_type()`
- `ResourceDefinition` - Represents a single resource (has `logical_id`, `resource_type`, `properties`, `references`)
- `ResourceReference` - Represents a reference from one resource to another
- `ReferenceType` - Enum for reference types (INLINE, REF, etc.)

**Always check the source file for exact method signatures and field names before writing tests.**

---

## Feature Description

Enable CSSM to analyze AWS CloudFormation templates (YAML/JSON) for security misconfigurations.

### Current Limitation
CSSM can only scan individual AWS resource files. CloudFormation templates bundle multiple resources (IAM roles, S3 buckets, Security Groups) in a single file.

### Example Usage
```bash
# Scan single template
cssm --cloudformation file:infrastructure.yaml --output report.json

# Scan directory of templates
cssm --cloudformation dir:templates/ --output report.json
```

---

## Architecture Decisions

### Analyzer Separation of Concerns

**Decision**: Each analyzer focuses ONLY on its own resource type, without following references or analyzing related resources.

**Rationale**:
- Simpler, more maintainable analyzers
- Cleaner separation of concerns
- Better suited for CloudFormation's flat resource structure
- Orchestration layer handles resource relationships

**Analyzer Responsibilities**:

| Analyzer | Input | Analyzes | Does NOT Analyze |
|----------|-------|----------|------------------|
| IAM Role | `ResourceDefinition` (role) | Trust policy only (AssumeRolePolicyDocument) | Attached/inline policies |
| IAM Policy | `ResourceDefinition` (policy) | Policy document | - |
| S3 Bucket | `ResourceDefinition` (bucket) | Bucket configuration (PAB, ACL, CORS, etc.) | Bucket policies |
| Security Group | `ResourceDefinition` (SG) | Ingress/Egress rules | - |

**Orchestrator Responsibilities**:
- Iterate through `ResourceCollection`
- Route each resource to appropriate analyzer based on `resource_type`
- Aggregate all findings
- Format output

---

## Implementation Phases

See individual phase files for detailed implementation steps:

**Completed Phases:**
- ✅ [Phase 1: Integration Tests](01-phase-1.md)
- ✅ [Phase 2: CloudFormation Reader](02-phase-2.md)
- ✅ [Phase 3: Create New File Collectors Using ResourceCollection](03-phase-3.md)
- ✅ [Phase 4: Create New Analyzers Using ResourceDefinition](04-phase-4.md)
- ✅ [Phase 5: Create Universal Resource Orchestrator](05-phase-5.md)
- ✅ [Phase 6: Wire CloudFormation Scanner](06-phase-6.md)
- ✅ [Phase 7: Restore AWS API Scanning with Resource Collectors](07-phase-7.md)
- ✅ [Phase 8: Deprecation and Cleanup](08-phase-8.md)
- ✅ [Phase 9: Unify CloudFormation into General Collector Pattern](09-phase-9.md)
- ✅ [Phase 10: Edge Case Test Coverage](10-phase-10.md)

**References:**
- [Backward Compatibility Summary](99-backward-compatibility.md)

---

## Current Architecture (Phase 9)

### Unified Scanning Path

All scanning modes (CloudFormation, file-based, AWS API) now use a **single unified code path**:

```python
def run_scan(run_config: RunConfig):
    boto3_wrapper = Boto3Wrapper()
    collector = _get_collector(run_config, boto3_wrapper)  # Returns appropriate collector
    collection = collector.collect()                        # ResourceCollection
    findings = resource_orchestrator.analyze_resources(collection)
    results = format_results(findings)
    generate_report(run_config.report, results)
```

### Collector Pattern

Each scanning mode has its own collector that returns `ResourceCollection`:

**File-Based Collectors:**
- `ResourceFileCloudFormationCollector` - Parses CloudFormation templates (YAML/JSON)
- `ResourceFileIamPolicyCollector` - Parses IAM policy files
- `ResourceFileIamRoleCollector` - Parses IAM role files
- `ResourceFileS3Collector` - Parses S3 bucket configuration files
- `ResourceFileSgCollector` - Parses Security Group files

**AWS API Collectors:**
- `ResourceAwsIamPolicyCollector` - Fetches policies via AWS API
- `ResourceAwsIamRoleCollector` - Fetches roles via AWS API
- `ResourceAwsS3Collector` - Fetches bucket configurations via AWS API
- `ResourceAwsSecurityGroupCollector` - Fetches security groups via AWS API

### Benefits of Unified Architecture

1. **No Special Cases** - CloudFormation is "just another collector"
2. **Consistent Analysis** - All resources analyzed through same orchestrator
3. **Simplified Maintenance** - Single code path to maintain and test
4. **Easier Extensions** - New resource types follow same pattern
5. **Clean Separation** - Collectors handle data acquisition, analyzers handle security checks

### Statistics

- **193 tests passing** (192 unit tests + 1 integration test)
- **42 old files removed** in Phase 8 cleanup
- **9 collector classes** (5 file-based + 4 AWS API)
- **4 resource analyzers** (IAM Policy, IAM Role, S3, Security Group)
- **1 unified orchestrator** for all resource types
- **13 new edge case tests** added in Phase 10
- **Integration test validates** end-to-end CloudFormation scanning
