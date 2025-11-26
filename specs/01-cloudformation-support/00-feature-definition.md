# CloudFormation Support - Feature Definition

**Feature Branch**: `feature/cloudformation-support`
**Milestone**: 9
**Status**: IN PROGRESS
**Created**: 2025-09-29
**Updated**: 2025-10-26

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

- [Phase 1: Integration Tests](01-phase-1.md)
- [Phase 2: CloudFormation Reader](02-phase-2.md)
- [Phase 3: Create New File Collectors Using ResourceCollection](03-phase-3.md)
- [Phase 4: Create New Analyzers Using ResourceDefinition](04-phase-4.md)
- [Phase 5: Create Universal Resource Orchestrator](05-phase-5.md)
- [Phase 6: Wire Resource Orchestrator into All Scanners](06-phase-6.md)
- [Phase 7: Deprecation and Cleanup](07-phase-7.md)
- [Phase 8: Post-Implementation Review & Enhancements](08-phase-8.md)
- [Backward Compatibility Summary](99-backward-compatibility.md)
