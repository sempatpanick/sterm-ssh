#!/usr/bin/env sh
# Enforces that no commit message, commit identity, or PR description
# attributes any AI model, coding agent, or bot as a co-author.
set -eu

AGENT_PATTERN='(claude|anthropic|gemini|antigravity|codex|openai|chatgpt|\bgpt(-?[0-9])?\b|copilot|cursor(agent)?|windsurf|codeium|devin|aider|cline|\broo\b|\bamp\b|droid|factory\.ai|amazon[[:space:]]+q|\bcody\b|junie|tabnine|qwen|deepseek|mistral|llama|sonnet|opus|haiku|\[bot\]|noreply@anthropic\.com|noreply@openai\.com|noreply@google\.com|copilot@github\.com|\bai[[:space:]-]+(agent|assistant|bot)\b|\bcoding[[:space:]-]+agent\b|\bagent\b)'
TRAILER_PREFIX='^[[:space:]]*(co-authored-by|assisted-by|generated-by|helped-by|authored-by)[[:space:]]*:'
FOOTER_PATTERN='^[[:space:]]*(🤖[[:space:]]*)?(generated|created|authored|written)[[:space:]]+(with|by)[[:space:]].*(claude|anthropic|gemini|antigravity|codex|openai|chatgpt|copilot|cursor|windsurf|codeium|devin|aider|cline|roo|amp|droid|factory|amazon[[:space:]]+q|cody|junie|tabnine|qwen|deepseek|ai|agent)'

check_text() {
  label="$1"
  file="$2"
  failed=0

  # 1. Check Co-authored-by / Assisted-by / Generated-by trailers referencing any agent
  matches=$(grep -inE "$TRAILER_PREFIX" "$file" | grep -iE "$AGENT_PATTERN" || true)
  if [ -n "$matches" ]; then
    printf 'ERROR: Agent co-author trailer prohibited in %s:\n%s\n' "$label" "$matches" >&2
    failed=1
  fi

  # 2. Check boilerplate AI generation footers (e.g. "Generated with [Claude Code]")
  footers=$(grep -inE "$FOOTER_PATTERN" "$file" || true)
  if [ -n "$footers" ]; then
    printf 'ERROR: AI/agent attribution footer prohibited in %s:\n%s\n' "$label" "$footers" >&2
    failed=1
  fi

  return "$failed"
}

check_identity() {
  label="$1"
  identity="$2"
  if printf '%s\n' "$identity" | grep -qiE "$AGENT_PATTERN"; then
    printf 'ERROR: Agent author/committer identity prohibited in %s: %s\n' "$label" "$identity" >&2
    return 1
  fi
  return 0
}

mode="${1:-}"
case "$mode" in
  --file)
    label="${2:?missing label}"
    file="${3:?missing file}"
    check_text "$label" "$file"
    ;;
  --identity)
    label="${2:?missing label}"
    identity="${3:-}"
    check_identity "$label" "$identity"
    ;;
  *)
    printf 'Usage: %s --file <label> <path> | --identity <label> <name-and-email>\n' "$0" >&2
    exit 2
    ;;
esac
