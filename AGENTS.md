# Agent Rules — STerm SSH

These rules apply unconditionally to **all AI / coding agents** working in this repository (including Antigravity, Gemini, Claude Code, OpenAI Codex, GitHub Copilot, Cursor, Windsurf, Aider, Cline, Devin, and any other automated assistant).

## Mandatory Git Commit & Pull Request Attribution Rule

1. **NEVER add any AI or coding agent as a co-author** on any git commit, merge commit, squash commit, or pull request.
2. **Forbidden commit trailers & footers** (strictly prohibited):
   - No `Co-authored-by:` / `Co-Authored-By:` line referencing any AI model, coding agent, assistant, or bot (e.g., Claude, Gemini, Antigravity, Codex, OpenAI, Copilot, Cursor, Windsurf, Aider, Cline, Devin, `[bot]`, `noreply@anthropic.com`, `noreply@openai.com`, `noreply@google.com`, `copilot@github.com`, etc.).
   - No `Assisted-by:` or `Generated-by:` trailers referencing an AI/agent.
   - No boilerplate attribution footers such as `Generated with ...` or `🤖 Generated with ...` in commit messages or PR descriptions.
3. **Commit author & committer identity** must always remain the human repository contributor's configured Git identity — never override `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, or `GIT_COMMITTER_EMAIL` with an agent identity.
4. **Enforcement**:
   - Local commits are checked by `.githooks/commit-msg` (enabled via `git config core.hooksPath .githooks`).
   - All pushes and pull requests are enforced in CI by `.github/workflows/no-agent-coauthor.yml`.

## Repository Standards

- Pure-Rust workspace (`crates/sterm-gpui`, `crates/core-*`, `server/sync-server`). Do not reintroduce Node.js, React, or Tauri dependencies.
- Keep `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` passing before committing or opening a PR.
