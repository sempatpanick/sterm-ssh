# GitHub Copilot Instructions — STerm SSH

Follow all rules in [AGENTS.md](../AGENTS.md).

## Commit & Pull Request Co-Author Policy (Mandatory)

- **NEVER** add `Co-authored-by:` (or any similar trailer) referencing GitHub Copilot or any other AI/coding agent in commit messages or pull requests.
- **NEVER** include AI-generated attribution footers in commit messages or PR descriptions.
- Enforced automatically by `.githooks/commit-msg` and `.github/workflows/no-agent-coauthor.yml`.
