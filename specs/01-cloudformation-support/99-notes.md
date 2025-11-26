## Notes

- Use TDD for each step: write test first, then implement
- Each checkbox is a separate commit
- Test checkboxes and implementation checkboxes are separate
- Always use exact method names from API Reference section above
- When in doubt about API, check existing code in `src/aws_scanner/engines/common/resource_definition.py`
- **CRITICAL**: Analyzers are simple and focused - they analyze only their own resource type
- **CRITICAL**: Orchestrator handles resource relationships and routing
- Validate changes against existing example files where applicable