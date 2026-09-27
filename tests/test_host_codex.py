"""Codex's public hook boundary, using captured 0.157.1 payload shapes.

Three risk groups: denial remains valid on errors; tool paths cannot disappear
through normalization; discovery/install planning preserves protected state.
Shared dataclasses are supplied locally until the gate module lands.
"""
import json
import unittest
from unittest.mock import patch

from canary.hosts import codex


class DenialProtocol(unittest.TestCase):
    def test_deny_stays_valid_even_when_reason_or_serializer_fails(self):
        class BrokenReason:
            def __str__(self):
                raise RuntimeError("must not stringify arbitrary objects")

        for reason in ['Use canary add "demo"\nthen retry', '', None, BrokenReason()]:
            with self.subTest(reason_type=type(reason).__name__):
                stdout, code = codex.deny(reason)
                self.assertEqual(code, 0, "Codex ignores stdout deny JSON at exit 2")
                decision = json.loads(stdout)["hookSpecificOutput"]
                self.assertEqual(decision["hookEventName"], "PreToolUse")
                self.assertEqual(decision["permissionDecision"], "deny")
                self.assertTrue(decision["permissionDecisionReason"].strip())
        for failure in [RuntimeError("serialization"), KeyboardInterrupt()]:
            with self.subTest(failure=type(failure).__name__), patch.object(json, "dumps", side_effect=failure):
                stdout, code = codex.deny("blocked")
            self.assertEqual(code, 0)
            self.assertIn("canary add", json.loads(stdout)["hookSpecificOutput"]["permissionDecisionReason"])


# Test-only seam: do not create or modify Claude's canary/gate.py.
import importlib.util
import os
import sys
import tempfile
import types
from dataclasses import dataclass
from pathlib import Path

@dataclass
class ToolCall:
    tool_name: str
    command: str
    paths_read: list
    paths_written: list
    cwd: str

@dataclass
class PlannedFile:
    path: str
    content: str
    mode: int
    action: str

standin = types.ModuleType("canary.gate")
standin.ToolCall = ToolCall
standin.PlannedFile = PlannedFile


class HostBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / 'home'
        self.cwd = self.root / 'repo' / 'child'
        self.home.mkdir()
        self.cwd.mkdir(parents=True)
        (self.root / 'repo' / '.git').mkdir()
        self.env = patch.dict(os.environ, {'HOME': str(self.home), 'CODEX_HOME': str(self.home / '.codex')})
        self.env.start()
        self.addCleanup(self.env.stop)
        if importlib.util.find_spec('canary.gate') is None:
            seam = patch.dict(sys.modules, {'canary.gate': standin})
            seam.start()
            self.addCleanup(seam.stop)

    def payload(self, tool, tool_input):
        # Captured envelope from shell-deny / patch-deny / mcp-deny-approved.
        return dict(session_id='session', turn_id='turn', transcript_path=None,
                    cwd=str(self.cwd), hook_event_name='PreToolUse', model='gpt-6-astra',
                    permission_mode='bypassPermissions', tool_name=tool,
                    tool_input=tool_input, tool_use_id='exec-probe')

    def test_captured_tool_shapes_preserve_paths_and_reject_unknown_shapes(self):
        skill = str(self.home / '.agents' / 'skills' / 'demo' / 'SKILL.md')
        shell = codex.parse_pre_tool_use(self.payload('Bash', {'command': '/usr/bin/touch ' + skill}))
        self.assertIn(skill, shell.paths_written)
        self.assertEqual(shell.command, '/usr/bin/touch ' + skill)
        target = str(self.home / '.codex' / 'hooks.json')
        patch_text = '*** Begin Patch\n*** Add File: ' + target + '\n+{}\n*** End Patch'
        change = codex.parse_pre_tool_use(self.payload('apply_patch', {'command': patch_text}))
        self.assertIn(target, change.paths_written)
        moved = codex.parse_pre_tool_use(self.payload('apply_patch', {'command':
            '*** Begin Patch\n*** Update File: old.md\n*** Move to: new.md\n@@\n-old\n+new\n*** End Patch'}))
        self.assertIn(str(self.cwd / 'old.md'), moved.paths_read)
        self.assertIn(str(self.cwd / 'old.md'), moved.paths_written)
        self.assertIn(str(self.cwd / 'new.md'), moved.paths_written)
        redirect = codex.parse_pre_tool_use(self.payload('Bash', {'command': 'printf ok > "' + target + '"'}))
        self.assertIn(target, redirect.paths_written)
        # MCP arguments are not shell commands; unknown tool semantics must deny.
        unknown = [None, {}, self.payload('Bash', {}), self.payload('Bash', {'command': []}),
                   self.payload('mcp__probe__echo', {'message': 'MCP_SENTINEL'}),
                   self.payload('write_stdin', {'chars': 'touch x'}),
                   self.payload('apply_patch', {'command': 'not a patch'})]
        for payload in unknown:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                codex.parse_pre_tool_use(payload)

    def test_local_roots_and_plan_preserve_existing_administrator_state(self):
        linked = self.root / 'external-skills'
        linked.mkdir()
        skills = self.home / '.agents' / 'skills'
        skills.mkdir(parents=True)
        (skills / 'linked').symlink_to(linked, target_is_directory=True)
        roots = codex.discovery_roots(str(self.home), str(self.cwd))
        for expected in [skills, linked, self.home / '.codex' / 'skills',
                         self.home / '.codex' / 'plugins' / 'cache',
                         self.root / 'repo' / '.agents' / 'skills',
                         self.cwd / '.agents' / 'skills', self.cwd / 'AGENTS.md']:
            self.assertIn(str(expected.resolve()), roots)
        self.assertNotIn(str(self.root / '.agents' / 'skills'), roots)
        self.assertEqual(len(roots), len(set(roots)))
        self.assertIn(str(self.home / '.codex'), codex.config_files(str(self.home)),
                      'A not-yet-created named profile must remain protected')
        self.assertIn(str(self.home / '.codex' / 'hooks.json'), codex.config_files(str(self.home)))
        self.assertIn(str(Path('/etc/codex/requirements.toml').resolve()), codex.config_files(str(self.home)))
        binary = str(self.root / "Canary's folder" / 'canary')
        # The filesystem is the external boundary: no /etc writes in tests.
        with patch('os.lstat', side_effect=FileNotFoundError):
            plan = codex.managed_install_plan(binary)
        self.assertEqual(len(plan), 1)
        self.assertEqual((plan[0].path, plan[0].mode, plan[0].action),
                         ('/etc/codex/requirements.toml', 0o644, 'create'))
        self.assertIn('[[hooks.PreToolUse.hooks]]', plan[0].content)
        self.assertIn('hooks = true', plan[0].content)
        self.assertNotIn('allow_managed_hooks_only', plan[0].content)
        with patch('os.lstat', return_value=object()):
            existing = codex.managed_install_plan(binary)
        self.assertEqual(existing[0].action, 'manual')
        self.assertEqual(existing[0].content, plan[0].content)
        with self.assertRaises(ValueError):
            codex.managed_install_plan('relative/canary')
