# Release Pipeline Automation

## Goal

Automate extension releases: one tag push → published to marketplace in ~10 minutes.

---

## Architecture

**Monorepo approach**: Keep current structure with both scanner and extension in one repo.

**Artifacts published:**
- Scanner binaries (Linux, Windows, macOS) → GitHub Releases
- Extension `.vsix` (bundles Linux binary) → VS Code Marketplace + GitHub Releases

---

## Phases

**Phase 1** (Complete): Basic release workflow - Linux only
**Phase 2** (Next): Marketplace publishing
**Phase 3**: Quality gates (tests, linting, changelog)
**Phase 4**: Multi-platform support (Windows, macOS)

---

## Key Decisions

**Versioning**: Manual - update `package.json`, create git tag `v{MAJOR}.{MINOR}.{PATCH}`
**Trigger**: Git tag push (not every commit)
**Binary**: PyInstaller, Linux only for now
**Secrets**: `VSCE_PAT` token for marketplace publishing (Phase 2)

---

## Artifacts

- `aws-scanner-linux` - Standalone CLI binary
- `aws-cssm-{version}.vsix` - VS Code extension (bundles binary)
