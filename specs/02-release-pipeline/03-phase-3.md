# Phase 3: Quality Gates

**Status**: Not started

---

## Checklist

[ ] Add pre-release validation steps to workflow (before build):
  ```yaml
  - name: Run tests
    run: |
      source venv/bin/activate
      pytest tests/

  - name: Run linting
    run: |
      pip install ruff
      ruff check .
  ```
[ ] Add version increment validation:
  ```yaml
  - name: Validate version increment
    run: |
      LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
      LATEST_VERSION=${LATEST_TAG#v}
      NEW_VERSION="${{ steps.extract_version.outputs.version }}"

      if [ "$NEW_VERSION" == "$LATEST_VERSION" ]; then
        echo "Error: Version $NEW_VERSION already exists"
        exit 1
      fi
  ```
[ ] Add changelog generation from commits:
  ```yaml
  - name: Generate changelog
    run: |
      LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
      if [ -z "$LATEST_TAG" ]; then
        COMMITS=$(git log --pretty=format:"- %s (%h)")
      else
        COMMITS=$(git log ${LATEST_TAG}..HEAD --pretty=format:"- %s (%h)")
      fi
      echo "$COMMITS" > changelog.txt
  ```
[ ] Update release notes to include generated changelog
[ ] Add dependency caching (optional performance improvement)

---

## Quality Gate Criteria

Workflow fails if:
- Tests fail (pytest exit code != 0)
- Linting fails (ruff exit code != 0)
- TypeScript compilation fails
- Tag format invalid
- Tag version != package.json version
- Version already exists
