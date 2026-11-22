# Claude Code Project Rules — STerm SSH

Follow all rules in [AGENTS.md](./AGENTS.md).

## Commit & Pull Request Co-Author Policy (Mandatory)

- **NEVER** add `Co-Authored-By:` or any AI/agent co-author trailer (including Claude, Anthropic, `noreply@anthropic.com`, or any other agent/model) to any commit message or PR.
- **NEVER** append `🤖 Generated with [Claude Code]` or similar attribution footers to commits or PR descriptions.
- Keep commit author/committer set strictly to the human contributor's Git config.
- Enforced automatically by `.githooks/commit-msg` and `.github/workflows/no-agent-coauthor.yml`.
