# Phase 4: Multi-Platform Support (Optional)

**Status**: Not started

---

## Goal

Build scanner binaries for Windows and macOS in addition to Linux.

---

## Checklist

[ ] Update workflow to use matrix strategy:
  ```yaml
  strategy:
    matrix:
      os: [ubuntu-latest, windows-latest, macos-latest]
    fail-fast: false

  runs-on: ${{ matrix.os }}
  ```
[ ] Add platform-specific binary naming:
  - Linux: `aws-scanner-linux`
  - Windows: `aws-scanner-windows.exe`
  - macOS: `aws-scanner-macos`
[ ] Update PyInstaller command for cross-platform builds
[ ] Upload all platform binaries to GitHub Release
[ ] Choose extension packaging approach:
  - **Option A**: Linux-only extension (current)
  - **Option B**: Platform-specific extensions (3 separate .vsix files)
  - **Option C**: Universal extension with all binaries bundled (~75 MB)

---

## Notes

- PyInstaller cannot cross-compile (must use native OS runners)
- macOS runners consume GitHub Actions minutes faster (10x multiplier)
- Windows path separator: backslash (handle in extension code if needed)
- macOS may require code signing for Gatekeeper
