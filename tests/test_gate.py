"""Behavioural tests for `canary hook` (docs/architecture.md, decision rules).

They run the real command with a throwaway HOME, the way each host runs it,
and assert the host-specific deny contract: Claude Code blocks on exit 2,
Codex on deny JSON with exit 0 (JSON with exit 2 would run the command).
The per-call allow and deny cases live in tests/test_corpus.py (HOOK_CASES);
these tests cover what the corpus cannot: the deny contract itself, the
messages, and failing closed.
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
        with open(os.path.join(self.path, ".claude/skills/notes/SKILL.md"), "w") as fh:
            fh.write("---\nname: notes\ndescription: Notes.\n---\nBody.\n")

    def hook(self, host, tool, tool_input, raw=None, env=None):
        payload = raw if raw is not None else json.dumps({
            "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": tool_input, "cwd": self.project})
        env = {"HOME": self.path, "PATH": os.environ.get("PATH", ""), **(env or {})}
        return subprocess.run([sys.executable, CANARY, "hook", "--host", host],
                              input=payload, capture_output=True, text=True, env=env,
                              timeout=60)

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


class InstallsGoThroughTheDoor(unittest.TestCase):
    def test_claude_code_runs_a_plain_installer_through_canary_install(self):
        h = Home()
        proc = h.hook("claude", "Bash", {"command": "npx skills add someone/repo -g",
                                         "description": "Install", "run_in_background": True})
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("permissionDecision", out)  # the person's own settings decide
        self.assertEqual(out["updatedInput"], {
            "command": "/usr/bin/python3 -I -B '/Library/Application Support/SkillCanary/bin/"
                       "canary' install -- npx skills add someone/repo -g",
            "description": "Install", "timeout": 600000})

    def test_codex_is_told_the_canary_install_command(self):
        h = Home()
        proc = h.hook("codex", "Bash", {"command": "npx skills add someone/repo"})
        self.assertTrue(h.denied("codex", "Bash", {"command": "npx skills add someone/repo"}))
        self.assertIn("canary install -- npx skills add someone/repo", proc.stdout)

    def test_an_installer_inside_a_longer_command_is_still_denied(self):
        h = Home()
        for host in ("claude", "codex"):
            with self.subTest(host=host):
                command = {"command": "cd /tmp && npx skills add someone/repo"}
                self.assertTrue(h.denied(host, "Bash", command))
                self.assertIn("canary install --", h.hook(host, "Bash", command).stdout)

    def test_a_new_skill_from_a_file_tool_is_sent_to_canary_add(self):
        h = Home()
        new = os.path.join(h.path, ".claude", "skills", "brand-new", "SKILL.md")
        proc = h.hook("claude", "Write", {"file_path": new, "content": "x"})
        self.assertEqual(proc.returncode, 2)
        self.assertIn("canary add", proc.stderr)
        self.assertIn("Editing a skill that is already installed is allowed", proc.stderr)
        self.assertFalse(h.denied("claude", "Write", {
            "file_path": os.path.join(h.path, ".claude", "skills", "notes", "SKILL.md"),
            "content": "edited"}))


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
        call = gate.ToolCall("Write", None, [], ["/x/.claude/skills/new/SKILL.md"], "/")
        with unittest.mock.patch.object(gate, "_creates_skill", side_effect=RuntimeError):
            reason = gate.decide(call, "/h", [])
        self.assertEqual(reason, gate.UNREADABLE)


class TheQuarantineIsNotReadable(unittest.TestCase):
    def test_file_tool_reads_of_quarantined_packages_are_denied(self):
        h = Home()
        q = os.path.join(h.path, "Library/Application Support/Canary/quarantine/r1/package/SKILL.md")
        self.assertTrue(h.denied("claude", "Read", {"file_path": q}))
        self.assertFalse(h.denied("claude", "Read", {
            "file_path": os.path.join(h.path, ".claude", "skills", "notes", "SKILL.md")}))


if __name__ == "__main__":
    unittest.main()
