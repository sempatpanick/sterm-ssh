# Contributing to STerm SSH

## Local Setup

Enable the repository commit-message hook so commit policy checks run locally before pushing:

```bash
git config core.hooksPath .githooks
```

## Commit & Pull Request Attribution Policy

- **No AI or coding agent may be listed as an author or co-author** on any commit or pull request.
- Do **not** include `Co-authored-by:`, `Assisted-by:`, or `Generated-by:` trailers referencing any AI/agent (Claude, Gemini, Antigravity, Codex, Copilot, Cursor, etc.), nor AI attribution footers such as `Generated with ...`.
- This rule applies to **all agents and contributors** and is automatically enforced by:
  - `.githooks/commit-msg` (local hook)
  - `.github/workflows/no-agent-coauthor.yml` (GitHub Actions on every push & PR)

## Code Quality Checks

Run before opening a pull request:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
