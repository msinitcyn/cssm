# Development Workflow

## Test-Driven Development

All code changes follow TDD:

1. **Write tests** - Write failing tests for expected behavior
2. **Implement** - Write minimal code to make tests pass
3. **Refactor** - Improve code quality while keeping tests green

## Commit Strategy

**Tests always in separate commits:**

```bash
# First: commit tests
git commit -m "tests: <feature description>"

# Then: commit implementation
git commit -m "feat: <feature description>"
```

**Why separate commits:**
- Enables reverting implementation while keeping tests
- Makes code review clearer
- Allows reproducing failures independently

## Feature Specifications

Specs contain ONLY functionality information:
- What needs to be fixed/implemented
- Implementation stages (alternating test/implementation)
- Expected behavior (concise, specific)

**DO NOT include in specs:**
- Milestone information
- Version numbers or dates
- Sample command outputs (covered by tests)
- "Backward Compatibility" sections (assumed 100%)
- "Success Criteria" sections (assumed all tests pass)
- Redundant examples (covered by integration tests)

**Example structure:**
- Stage 1 (Tests): Write tests for CloudFormation BucketPolicy support
- Stage 2 (Implementation): Implement BucketPolicy scanner
- Stage 3 (Tests): Write tests for error handling
- Stage 4 (Implementation): Implement error handling

## Defaults

- 100% backward compatibility (unless breaking change documented with migration guide)
- All tests must pass
- Reference `specs/supported-features.md` for compatibility requirements
