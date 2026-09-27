"""Behavioural tests for `canary hook` (docs/architecture.md, decision rules).

They run the real command with a throwaway HOME, the way each host runs it,
and assert the host-specific deny contract: Claude Code blocks on exit 2,
Codex on deny JSON with exit 0 (JSON with exit 2 would run the command).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

from canary import gate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = os.path.join(ROOT, "bin", "canary")


class Home:
    def __init__(self):
        self.path = os.path.realpath(tempfile.mkdtemp(prefix="canary-home-"))
        self.project = os.path.join(self.path, "work", "app")
        for d in (".claude/skills/notes", ".agents/skills", ".codex", "work/app/src"):
            os.makedirs(os.path.join(self.path, d), exist_ok=True)

    def hook(self, host, tool, tool_input, raw=None):
        payload = raw if raw is not None else json.dumps({
            "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": tool_input, "cwd": self.project})
        env = {"HOME": self.path, "PATH": os.environ.get("PATH", "")}
        proc = subprocess.run([sys.executable, CANARY, "hook", "--host", host],
                              input=payload, capture_output=True, text=True, env=env,
                              timeout=60)
        return proc

    def denied(self, host, tool, tool_input, raw=None):
        proc = self.hook(host, tool, tool_input, raw)
        if host == "claude":
            blocked = proc.returncode == 2 and proc.stderr.strip()
        else:
            blocked = (proc.returncode == 0 and proc.stdout != ""
                       and json.loads(proc.stdout)["hookSpecificOutput"]
                       ["permissionDecision"] == "deny")
        allowed = proc.returncode == 0 and proc.stdout == "" and proc.stderr == ""

        if not (blocked or allowed):
            raise AssertionError(f"neither a clean allow nor a deny: {proc!r}")
        return bool(blocked)


class WritesIntoSkillFoldersAreDenied(unittest.TestCase):
    def test_file_tools_and_simple_shell(self):
        h = Home()
        skill = os.path.join(h.path, ".claude", "skills", "notes", "SKILL.md")
        cases = [
            ("claude", "Write", {"file_path": skill, "content": "x"}, True),
            ("claude", "Edit", {"file_path": "~/.claude/skills/notes/SKILL.md",
                                "old_string": "a", "new_string": "b"}, True),
            ("claude", "Write", {"file_path": os.path.join(h.project, "src", "a.py"),
                                 "content": "x"}, False),
            ("claude", "Read", {"file_path": skill}, False),
            ("claude", "Bash", {"command": "touch ~/.agents/skills/evil/SKILL.md"}, True),
            ("codex", "Bash", {"command": "mkdir ~/.agents/skills/evil"}, True),
            ("codex", "apply_patch", {"command": "*** Begin Patch\n*** Add File: "
                                      + os.path.join(h.path, ".agents/skills/e/SKILL.md")
                                      + "\n+x\n*** End Patch"}, True),
            ("codex", "Bash", {"command": "ls src"}, False),
        ]
        for host, tool, tool_input, deny in cases:
            with self.subTest(host=host, tool=tool, tool_input=tool_input):
                self.assertEqual(h.denied(host, tool, tool_input), deny)


class InstallersRedirectToCanaryAdd(unittest.TestCase):
    def test_installer_commands_are_denied_with_the_way_in(self):
        h = Home()
        for command in ("npx skills add someone/repo", "npx -y skills@latest install x",
                        "pnpm dlx skills add x", "claude plugin install foo@bar",
                        "claude plugin marketplace add someone/market",
                        "cd /tmp && bunx skills update"):
            for host in ("claude", "codex"):
                with self.subTest(host=host, command=command):
                    proc = h.hook(host, "Bash", {"command": command})
                    self.assertTrue(h.denied(host, "Bash", {"command": command}))
                    self.assertIn("canary add", proc.stdout + proc.stderr)


class CommandsItCannotMapAreScreenedAsText(unittest.TestCase):
    def test_compound_commands(self):
        h = Home()
        for host in ("claude", "codex"):
            with self.subTest(host=host):
                self.assertFalse(h.denied(host, "Bash", {"command": "cd src && npm test"}))
                self.assertFalse(h.denied(host, "Bash", {"command": "echo $PATH | wc -c"}))
                self.assertTrue(h.denied(host, "Bash", {
                    "command": "cd ~/.claude/skills && echo x > notes/SKILL.md"}))
                self.assertTrue(h.denied(host, "Bash", {
                    "command": 'D="$HOME/.agents/skills"; mkdir -p "$D/x"'}))
                self.assertTrue(h.denied(host, "mcp__fs__write_file", {
                    "path": os.path.join(h.path, ".claude/skills/x/SKILL.md")}))
                self.assertFalse(h.denied(host, "mcp__fs__write_file", {
                    "path": os.path.join(h.project, "notes.md")}))


class TheHookNeverFailsOpen(unittest.TestCase):
    def test_garbage_and_missing_fields_deny(self):
        h = Home()
        for raw in ("", "not json", "[]", json.dumps({"hook_event_name": "PreToolUse"}),
                    json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                "tool_input": {"command": "ls"}, "cwd": "relative"})):
            for host in ("claude", "codex"):
                with self.subTest(host=host, raw=raw[:30]):
                    self.assertTrue(h.denied(host, None, None, raw=raw))

    def test_an_internal_error_still_denies(self):
        call = gate.ToolCall("Write", None, [], ["/x"], "/", True, "")
        with unittest.mock.patch.object(gate, "_protected_hit", side_effect=RuntimeError):
            reason = gate.decide(call, ["/y"], home="/h")
        self.assertIsNotNone(reason)


class TheQuarantineIsNotReadable(unittest.TestCase):
    def test_reads_of_quarantined_packages_are_denied(self):
        h = Home()
        q = os.path.join(h.path, "Library/Application Support/Canary/quarantine/r1/package/SKILL.md")
        self.assertTrue(h.denied("claude", "Read", {"file_path": q}))
        self.assertTrue(h.denied("codex", "Bash", {"command": "cat '" + q + "'"}))

if __name__ == "__main__":
    unittest.main()
