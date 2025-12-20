# Feature: Scanner & Extension Reliability Fixes

**Feature ID**: 02
**Status**: Not started
**Milestone**: 9 - High Impact Foundation

---

## Overview

Fix critical reliability issues in scanner error handling and VSCode extension to ensure production readiness before release automation.

---

## Problems

1. Scanner crashes with unhelpful stack traces when wrong file format provided
2. Extension "Scan IAM Policy" returns no results for valid policy files
3. Extension lacks CloudFormation scanning support
4. Unknown if extension works with all example files

---

## Goals

- Graceful error messages instead of crashes
- Extension correctly handles all file formats in examples/
- CloudFormation scanning available in extension
- All example files validated with extension

---

## Phases

**Phase 1: Scanner Error Handling**
- Detect wrong file format early
- Return helpful error messages
- No stack traces for user errors

**Phase 2: Extension File Validation**
- Validate file format before scanning
- Clear error messages in extension UI
- Fix "no items found" issue

**Phase 3: CloudFormation Extension Support**
- Add "Scan CloudFormation" command
- Handle both YAML and JSON templates

**Phase 4: Example Validation**
- Test extension against all examples/
- Document which command works with which file type
- Fix any discovered issues

---

## Success Criteria

- [ ] Scanner returns helpful errors for format mismatches
- [ ] Extension shows clear error when wrong command used
- [ ] All file types in examples/ can be scanned via extension
- [ ] CloudFormation scanning works in extension
- [ ] No crashes or stack traces for user errors

---

## Backward Compatibility

Maintains compatibility with supported-features.md §3 (Input File Formats).
No changes to file formats or CLI interface.
