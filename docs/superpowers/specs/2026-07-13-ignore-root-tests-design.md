# Ignore Root Tests Directory

## Goal

Prevent Git from tracking the repository-root `tests` directory and everything
inside it.

## Design

Append `/tests/` to the root `.gitignore`. The leading slash anchors the rule to
the repository root, and the trailing slash applies it to the directory and all
descendants. Nested directories such as `src/tests/` remain unaffected.

No other ignore patterns or files will change.

## Verification

- `git check-ignore -v --no-index tests/example.txt` identifies `/tests/`.
- `git check-ignore -q --no-index src/tests/example.txt` returns nonzero.
- The existing untracked `SCAN_REPORT.md` remains outside the commit.
