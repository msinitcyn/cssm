# Release Pipeline Automation - Feature Definition

**Feature Branch**: `feature/release-pipeline`
**Milestone**: 9
**Status**: NOT STARTED

---

## Goal

Automate extension releases: one tag push → published to marketplace in ~10 minutes.

---

## Architecture

**Monorepo approach**: Keep current structure with both scanner and extension in one repo.

**Artifacts published:**
- Scanner binaries (Linux, Windows, macOS) → GitHub Releases
- Extension `.vsix` (bundles Linux binary) → VS Code Marketplace + GitHub Releases

---

## Implementation Phases

### Phase 1: Basic Release Workflow (Linux only)
- Install `@vscode/vsce` in extension
- Create `.github/workflows/release-extension.yml`
- Build Linux scanner binary with PyInstaller
- Package extension with bundled binary
- Create GitHub release with artifacts

### Phase 2: Marketplace Publishing
- Generate VSCE_PAT token from Azure DevOps
- Add token to GitHub secrets
- Add marketplace publishing to workflow
- Test end-to-end release

### Phase 3: Quality Gates
- Add pre-release validation (pytest, ruff, version check)
- Auto-generate changelog from commits

### Phase 4: Multi-Platform Support (Optional)
- Build macOS and Windows binaries using GitHub Actions matrix
- Add platform-specific binaries to GitHub releases
- Optional: Bundle all platforms in .vsix with OS detection

---

## Technical Stack

### Tools
- `@vscode/vsce` - Package and publish extensions
- `pyinstaller` - Build standalone scanner binaries (already in use)
- GitHub Actions - CI/CD automation (already in use)

### Secrets
- `VSCE_PAT` - Personal Access Token for VS Code Marketplace publishing

### Versioning
- Manual: Developer updates `package.json` version, creates matching git tag
- Tag format: `v{MAJOR}.{MINOR}.{PATCH}` (e.g., `v0.2.0`)
- Pipeline validates tag matches package.json version

---

## Quality Gates

Pipeline must verify before publishing:
- ✅ All tests pass (pytest)
- ✅ Linting passes (ruff)
- ✅ Extension compiles (tsc)
- ✅ Tag version matches package.json
- ✅ Binaries build successfully

---

## Artifacts

Each release produces:

**GitHub Release Assets:**
- `aws-scanner-linux`
- `aws-scanner-windows.exe` (Phase 4)
- `aws-scanner-macos` (Phase 4)
- `aws-cssm-{version}.vsix`

**VS Code Marketplace:**
- `aws-cssm` extension (published automatically)

---

## Multi-Platform Builds

Use GitHub Actions matrix strategy with native OS runners:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest, macos-latest]
  fail-fast: false

runs-on: ${{ matrix.os }}
```

Each OS builds its own binary in parallel. PyInstaller cannot cross-compile.

---

## File Structure

```
.github/workflows/
  release-extension.yml    # NEW: Release automation workflow

vscode-extension/
  package.json             # Add vsce scripts + dependencies
  bin/
    aws-scanner-linux      # Bundled binary (created by workflow)
```

---

## References

- [VS Code Extension Publishing](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
- [vsce CLI](https://github.com/microsoft/vscode-vsce)
- [GitHub Actions Matrix Builds](https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs)
