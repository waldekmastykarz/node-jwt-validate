---
name: bump-version
description: This skill should be used when the user asks to "bump the version", "release a new version", "increment version", "update version number", "prepare a release", or mentions anything related to version management and semantic versioning.
---

# Bump Version

This skill manages semantic versioning for the project by analyzing changes since the last release and proposing an appropriate version bump.

## When to Use

Activate when the user requests a version bump or release preparation. The workflow analyzes git history to determine the appropriate SemVer increment (major, minor, or patch).

## SemVer Classification

### Major (X.0.0)
Breaking changes that require user action:
- Removed or renamed public APIs
- Changed behavior of existing features
- Breaking config file format changes

### Minor (0.X.0)
New features that are backward-compatible:
- New exported functions, classes, or types
- New configuration options
- Performance improvements
- Non-breaking dependency updates with new capabilities

### Patch (0.0.X)
Bug fixes and minor improvements:
- Bug fixes
- Security patches
- Documentation updates
- Typo fixes
- Dependency updates for security/bugs

## Workflow

**STOP — Complete all steps in order. Do not skip Step 5 (user confirmation).**

### Step 1: Find the Latest Version Tag

```bash
git describe --tags --abbrev=0
```

This returns the most recent version tag (e.g., `v0.5.2`).

### Step 2: Get Changes Since Last Tag

```bash
git log <tag>..HEAD --oneline
```

Replace `<tag>` with the result from Step 1.

### Step 3: Get Detailed Diff Summary

```bash
git diff <tag>..HEAD --stat
```

This shows which files changed and how many lines were modified.

### Step 4: Classify Changes

Analyze the commit messages and changed files:

1. Review each commit message for keywords:
   - Breaking: "BREAKING", "remove", "rename API", "migrate"
   - Features: "feat", "add", "new", "implement"
   - Fixes: "fix", "bug", "patch", "security"

2. Review changed files:
   - src/TokenValidator.ts — Core validation logic (behavior changes = major, fixes = patch)
   - src/TokenCacheWrapper.ts — Cache logic (behavior changes = major, fixes = patch)
   - src/utils.ts — Utility functions
   - src/index.ts — Public API surface (exports changed = major)
   - package.json dependency changes require analysis

3. Determine the highest applicable SemVer level:
   - Any breaking change → major
   - Any new feature (no breaking) → minor
   - Only fixes/docs → patch

### Step 5: Present Changes and Propose Version (REQUIRED)

**STOP — Present findings to user and wait for confirmation before proceeding.**

Format the proposal as follows:

```
## Changes since <current-version>

**Commits:**
- <commit message 1>
- <commit message 2>
- ...

**Files changed:** <count>

**Classification:** <major|minor|patch>

**Proposed version:** <current> → <new>

Confirm to proceed with `npm version <increment>`?
```

### Step 6: Execute Version Bump (After Confirmation Only)

Once the user confirms, run:

```bash
npm version <major|minor|patch>
```

This command:
- Updates package.json version
- Creates a git commit
- Creates a git tag

### Step 7: Push Changes and Tag

```bash
git push && git push --tags
```

This pushes both the commit and the new version tag to the remote.

## Checklist

Before executing version bump:
- [ ] Found latest version tag
- [ ] Retrieved all commits since tag
- [ ] Analyzed changes for SemVer classification
- [ ] Presented summary to user
- [ ] Received explicit confirmation
- [ ] Ran `npm version <increment>`
- [ ] Pushed commit and tag to remote
