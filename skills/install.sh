#!/bin/sh
# depguard agent skill installer (served at <api>/agent/install.sh).
#   curl -fsSL https://<api>/agent/install.sh | sh
#   curl -fsSL https://<api>/agent/install.sh | DEPGUARD_API_KEY=dg_... sh   # also connects Claude Code's MCP
set -eu
API="${DEPGUARD_API_URL:-__API_URL__}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL "$API/agent/SKILL.md" -o "$tmp"
head -2 "$tmp" | grep -q '^name: depguard' || { echo "depguard: unexpected SKILL.md from $API" >&2; exit 1; }
done=""
for dir in "$HOME/.claude/skills" "$HOME/.codex/skills"; do
  agent="$(dirname "$dir")"
  if [ -d "$agent" ] || { [ "$agent" = "$HOME/.claude" ] && command -v claude >/dev/null 2>&1; }; then
    mkdir -p "$dir/depguard" && cp "$tmp" "$dir/depguard/SKILL.md" && done="$done $dir/depguard"
  fi
done
[ -n "$done" ] && echo "depguard: skill installed in$done" || echo "depguard: no Claude Code or Codex found; save $API/agent/SKILL.md as your agent's rules"
if [ -n "${DEPGUARD_API_KEY:-}" ] && command -v claude >/dev/null 2>&1; then
  claude mcp remove -s user depguard >/dev/null 2>&1 || true
  claude mcp add -s user --transport http depguard "$API/mcp" --header "Authorization: Bearer $DEPGUARD_API_KEY" >/dev/null
  echo "depguard: MCP server added to Claude Code"
else
  echo "depguard: connect the MCP server too: install the depguard CLI and run 'depguard setup agents', or see Setup → AI agents"
fi
