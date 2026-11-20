#!/usr/bin/env bash
set -euo pipefail

# AREA (Anti-Reverse Engineering Anything) — Cross-Agent AI Skill Installer
# Supports: Codex, Antigravity, Claude Code, Gemini CLI, OpenCode, or local workspace install.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="${SCRIPT_DIR}/skills/area"

if [ ! -f "${SKILL_SRC}/SKILL.md" ]; then
  echo "Error: Could not find ${SKILL_SRC}/SKILL.md" >&2
  exit 1
fi

install_to() {
  local dest="$1"
  local label="$2"
  mkdir -p "$(dirname "${dest}")"
  rm -rf "${dest}"
  cp -R "${SKILL_SRC}" "${dest}"
  chmod +x "${dest}/scripts/area_audit.py"
  echo "  [OK] Installed AREA skill for ${label} -> ${dest}"
}

usage() {
  cat <<'EOF'
AREA (Anti-Reverse Engineering Anything) — AI Skill Installer

Usage:
  ./install.sh                  Install globally for Codex, Antigravity, and Claude Code (default)
  ./install.sh --all            Install globally for Codex, Antigravity, Claude Code, Gemini CLI, and OpenCode
  ./install.sh --codex          Install globally for Codex (~/.agents/skills/area)
  ./install.sh --antigravity    Install globally for Antigravity (~/.gemini/config/skills/area)
  ./install.sh --claude         Install globally for Claude Code (~/.claude/skills/area)
  ./install.sh --gemini         Install globally for Gemini CLI (~/.gemini/skills/area)
  ./install.sh --opencode       Install globally for OpenCode (~/.config/opencode/skills/area)
  ./install.sh --local <dir>    Install into a project workspace (.agents/skills/area & .claude/skills/area)
EOF
}

if [ $# -eq 0 ]; then
  echo "Installing AREA (Anti-Reverse Engineering Anything) globally..."
  install_to "${HOME}/.agents/skills/area" "Codex"
  install_to "${HOME}/.gemini/config/skills/area" "Antigravity"
  install_to "${HOME}/.claude/skills/area" "Claude Code"
  echo ""
  echo "Done! Ask Codex, Antigravity, or Claude Code to run an AREA binary obfuscation audit."
  exit 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --all)
      install_to "${HOME}/.agents/skills/area" "Codex"
      install_to "${HOME}/.gemini/config/skills/area" "Antigravity"
      install_to "${HOME}/.claude/skills/area" "Claude Code"
      install_to "${HOME}/.gemini/skills/area" "Gemini CLI"
      install_to "${HOME}/.config/opencode/skills/area" "OpenCode"
      ;;
    --codex)
      install_to "${HOME}/.agents/skills/area" "Codex"
      ;;
    --antigravity)
      install_to "${HOME}/.gemini/config/skills/area" "Antigravity"
      ;;
    --claude)
      install_to "${HOME}/.claude/skills/area" "Claude Code"
      ;;
    --gemini)
      install_to "${HOME}/.gemini/skills/area" "Gemini CLI"
      ;;
    --opencode)
      install_to "${HOME}/.config/opencode/skills/area" "OpenCode"
      ;;
    --local)
      shift
      if [ $# -eq 0 ]; then
        echo "Error: --local requires a project directory path." >&2
        exit 1
      fi
      proj="$1"
      install_to "${proj}/.agents/skills/area" "Workspace (.agents/skills)"
      install_to "${proj}/.claude/skills/area" "Workspace (.claude/skills)"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done
