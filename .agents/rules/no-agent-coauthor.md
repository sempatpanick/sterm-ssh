# No Agent Co-Author Rule (Applies to All Agents)

- **NEVER** add any AI, LLM, or coding agent as a co-author on any commit or pull request (`Co-authored-by:`, `Co-Authored-By:`, `Assisted-by:`, `Generated-by:`).
- **NEVER** add AI-generated attribution footers (e.g. `Generated with ...`) to commit messages or PR bodies.
- This rule applies to all agents and is enforced locally by `.githooks/commit-msg` and in CI by `.github/workflows/no-agent-coauthor.yml`.
