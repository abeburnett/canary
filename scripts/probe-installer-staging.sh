#!/bin/sh
# Probe for the front-door program (docs/program-2026-09-30-front-door.md):
# do the native installers write into a staging folder when told to, and
# leave the real skill and plugin folders alone? Run it yourself in a
# terminal; SkillCanary's hook blocks agents from running installers.
#
# It installs into a throwaway folder only, and prints where files landed.
set -u
T=$(mktemp -d /tmp/canary-staging-probe.XXXXXX)
echo "staging folder: $T"

count() { find "$1" 2>/dev/null | wc -l | tr -d ' '; }
REAL_SKILLS_BEFORE=$(count "$HOME/.claude/skills")
REAL_AGENTS_BEFORE=$(count "$HOME/.agents/skills")
REAL_PLUGINS_BEFORE=$(count "$HOME/.claude/plugins")

echo
echo "== 1. npx skills add, with HOME pointed at the staging folder"
HOME="$T/home" npx -y skills add mattpocock/skills -g -y -a claude-code --copy > "$T/npx.log" 2>&1
echo "exit $?  (log: $T/npx.log)"
echo "skill folders that landed in the staging home:"
find "$T/home" -name SKILL.md 2>/dev/null | sed "s|$T/home|  STAGING-HOME|" | head -10

echo
echo "== 2. claude plugin install, with CLAUDE_CONFIG_DIR pointed at the staging folder"
CLAUDE_CONFIG_DIR="$T/claude" claude plugin marketplace add anthropics/claude-plugins-official > "$T/mkt.log" 2>&1
echo "marketplace add exit $?  (log: $T/mkt.log)"
CLAUDE_CONFIG_DIR="$T/claude" claude plugin install code-simplifier@claude-plugins-official > "$T/plugin.log" 2>&1
echo "plugin install exit $?  (log: $T/plugin.log)"
echo "plugin files that landed in the staging config folder:"
find "$T/claude" -path '*code-simplifier*' -type f 2>/dev/null | sed "s|$T/claude|  STAGING-CONFIG|" | head -10

echo
echo "== 3. the real folders must be unchanged"
echo "~/.claude/skills entries:  before $REAL_SKILLS_BEFORE, after $(count "$HOME/.claude/skills")"
echo "~/.agents/skills entries:  before $REAL_AGENTS_BEFORE, after $(count "$HOME/.agents/skills")"
echo "~/.claude/plugins entries: before $REAL_PLUGINS_BEFORE, after $(count "$HOME/.claude/plugins")"
echo
echo "Paste everything above back into the session. Remove the staging folder with: rm -rf $T"
