# Ignore Root Tests Directory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ignore the repository-root `tests` directory and every descendant without ignoring nested directories named `tests` elsewhere.

**Architecture:** Add one root-anchored directory pattern to the existing root `.gitignore`. Verify behavior directly with `git check-ignore`; no application code or test framework is involved.

**Tech Stack:** Git ignore patterns, PowerShell, GitHub CLI

---

### Task 1: Ignore the root tests directory

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Verify the root test path is not already ignored by the requested rule**

Run:

```powershell
git check-ignore -v --no-index tests/example.txt
```

Expected: nonzero exit status with no `/tests/` match.

- [ ] **Step 2: Add the minimal ignore pattern**

Append this exact line to `.gitignore`:

```gitignore
/tests/
```

- [ ] **Step 3: Verify root descendants are ignored**

Run:

```powershell
git check-ignore -v --no-index tests/example.txt
```

Expected: exit status 0 and output identifying `.gitignore` pattern `/tests/`.

- [ ] **Step 4: Verify nested test directories remain unignored**

Run:

```powershell
git check-ignore -q --no-index src/tests/example.txt
```

Expected: nonzero exit status.

- [ ] **Step 5: Verify and commit only `.gitignore`**

Run:

```powershell
git diff --check
git diff -- .gitignore
git add -- .gitignore
git commit -m "ignore root tests directory"
```

Expected: one commit modifying only `.gitignore` with one inserted line.

- [ ] **Step 6: Push and verify the existing draft PR**

Run:

```powershell
git push
gh pr view 1 --repo huigangz/scan-agent-skills --json state,isDraft,headRefName,baseRefName,url
```

Expected: PR #1 remains open as a draft from `agent/remove-tests` to `main`.
