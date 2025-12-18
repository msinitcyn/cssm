# Phase 1: Basic Release Workflow

**Status**: ✅ Complete

---

## Implementation Checklist

[x] Add `@vscode/vsce@^3.2.1` to `vscode-extension/package.json` devDependencies
[x] Add npm scripts: `"package": "vsce package"`, `"publish": "vsce publish"`
[x] Create `.github/workflows/release-extension.yml`
[x] Configure PyInstaller build (see issue below)
[x] Add version validation (tag format + package.json match)
[x] Add GitHub release creation with artifacts
[x] Verify locally

---

## Files Changed

- `.github/workflows/release-extension.yml` (new)
- `vscode-extension/package.json` (modified)
- `vscode-extension/pyinstaller_entry.py` (new - build entry point)

---

## PyInstaller Entry Point

**Why needed**: `src/aws_scanner/cli/main.py` uses relative imports (correct Python practice):
```python
from .cli_parser import get_args  # Pythonic, keep this
```

**Solution**: `vscode-extension/pyinstaller_entry.py` wrapper with absolute imports:
```python
from aws_scanner.cli.main import main
if __name__ == "__main__":
    main()
```

This keeps the scanner code clean and doesn't pollute it for packaging needs.

---

## Release Trigger

```bash
# Update version
vim vscode-extension/package.json  # Change version to X.Y.Z

# Commit, tag, push
git add vscode-extension/package.json
git commit -m "Bump version to X.Y.Z"
git tag vX.Y.Z
git push origin vX.Y.Z
```

Workflow creates GitHub Release with:
- `aws-scanner-linux` binary
- `aws-cssm-X.Y.Z.vsix` extension
