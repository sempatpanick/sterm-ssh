# Gemini / Antigravity Project Rules — STerm SSH

Follow all rules in [AGENTS.md](./AGENTS.md).

## Commit & Pull Request Co-Author Policy (Mandatory)

- **NEVER** include any `Co-authored-by:` / `Co-Authored-By:`, `Assisted-by:`, or `Generated-by:` trailer referencing any AI model, agent, or bot in any git commit message or PR description.
- **NEVER** include `Generated with ...` / AI attribution footers in commits or pull requests.
- Keep commits authored solely by the human user's configured Git identity.
- This rule applies to **all agents** and is enforced by `.githooks/commit-msg` and `.github/workflows/no-agent-coauthor.yml`.
