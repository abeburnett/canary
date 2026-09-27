"""Behavioural tests for `canary setup` and `canary doctor`.

The privileged script is run for real, as the current user, with a temporary
folder standing in for `/` and the current user standing in for root; nothing
touches this Mac's real policy folders.
"""

import json
import os
import subprocess
import tempfile
import unittest

from canary import setup

ME = f"{os.getuid()}:{os.getgid()}"


class Mac:
    def __init__(self):
        self.prefix = os.path.realpath(tempfile.mkdtemp(prefix="canary-root-"))
        self.home = os.path.join(self.prefix, "Users", "person")
        for d in (".claude/skills", ".agents/skills"):
            os.makedirs(os.path.join(self.home, d))
        self.scripts = []

    def run_script(self, text):
        self.scripts.append(text)
        return subprocess.run(["/bin/sh", "-c", text], capture_output=True,
                              timeout=120).returncode == 0

    def setup(self, level, runner=None):
        return setup.setup(level, home=self.home, prefix=self.prefix,
                           runner=runner or self.run_script, owner=ME, person=ME)

    def doctor(self):
        return setup.doctor(self.home, self.prefix, expected_uid=os.getuid())

    def at(self, path):
        return os.path.join(self.prefix, path.lstrip("/"))


DROP_IN = "/Library/Application Support/ClaudeCode/managed-settings.d/canary.json"
CODEX = "/etc/codex/requirements.toml"


class GuardInstallsBothHooks(unittest.TestCase):
    def test_guard_then_doctor_finds_no_gaps(self):
        mac = Mac()
        out, code = mac.setup("guard")
        self.assertEqual((out["outcome"], code), ("done", 0))
        with open(mac.at(DROP_IN)) as fh:
            settings = json.load(fh)
        command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertEqual(command, setup.hook_command(mac.prefix, "claude"))
        self.assertTrue(command.startswith("/usr/bin/python3 -I "))
        self.assertNotIn("allowManagedHooksOnly", json.dumps(settings))
        with open(mac.at(CODEX)) as fh:
            self.assertIn(setup.hook_command(mac.prefix, "codex"), fh.read())
        level, gaps, claim = mac.doctor()
        self.assertEqual((level, gaps), ("guard", []))
        self.assertEqual(claim, setup.CLAIMS["guard"])
        proc = subprocess.run(setup.hook_command(mac.prefix, "claude").split(),
                              input="not json", capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)

    def test_scan_asks_for_no_password(self):
        mac = Mac()
        out, code = mac.setup("scan", runner=lambda text: self.fail("asked for a password"))
        self.assertEqual((out["outcome"], code), ("done", 0))
        self.assertFalse(os.path.exists(mac.at(setup.LIB)))


class ThePrivilegedScriptChecksItsPayload(unittest.TestCase):
    def test_a_changed_payload_installs_nothing(self):
        mac = Mac()
        text = setup.script(setup.plan("guard", mac.home, mac.prefix), mac.prefix, ME, ME)
        b64 = text.split("printf %s ", 1)[1].split(" |", 1)[0]
        tampered = text.replace(b64, b64[:-8] + ("A" * 8 if not b64.endswith("A" * 8) else "B" * 8), 1)
        self.assertFalse(mac.run_script(tampered))
        self.assertFalse(os.path.exists(mac.at(setup.LIB)))
        self.assertFalse(os.path.exists(mac.at(DROP_IN)))


class AdministratorFilesAreNeverOverwritten(unittest.TestCase):
    def test_existing_codex_requirements_become_a_manual_step(self):
        mac = Mac()
        os.makedirs(os.path.dirname(mac.at(CODEX)))
        with open(mac.at(CODEX), "w") as fh:
            fh.write("# the administrator's policy\n")
        out, _ = mac.setup("guard")
        with open(mac.at(CODEX)) as fh:
            self.assertEqual(fh.read(), "# the administrator's policy\n")
        self.assertEqual([m["path"] for m in out["manual"]], [mac.at(CODEX)])
        level, gaps, claim = mac.doctor()
        self.assertTrue(any("Codex" in g for g in gaps))
        self.assertNotEqual(claim, setup.CLAIMS["guard"])

    def test_going_back_to_scan_keeps_files_someone_else_changed(self):
        mac = Mac()
        mac.setup("lockdown")
        with open(mac.at(DROP_IN), "a") as fh:
            fh.write("\n")
        mac.setup("scan")
        self.assertTrue(os.path.exists(mac.at(DROP_IN)))
        self.assertFalse(os.path.exists(mac.at(CODEX)))
        self.assertFalse(os.path.exists(mac.at(setup.LIB)))
        self.assertEqual(mac.doctor()[0], "scan")


class DoctorReportsWhatIsWeak(unittest.TestCase):
    def test_a_writable_install_is_a_gap(self):
        mac = Mac()
        mac.setup("guard")
        path = os.path.join(mac.at(setup.LIB), "canary", "gate.py")
        os.chmod(path, 0o666)
        level, gaps, _ = mac.doctor()
        self.assertTrue(any("installed files" in g for g in gaps))

    def test_lockdown_roots_must_be_locked(self):
        mac = Mac()
        inside = os.path.join(mac.home, ".claude", "skills", "notes.md")
        with open(inside, "w") as fh:
            fh.write("x")
        os.chmod(inside, 0o666)
        mac.setup("lockdown")
        self.assertEqual(os.stat(inside).st_mode & 0o022, 0)
        self.assertEqual(mac.doctor()[1], [])
        os.chmod(os.path.join(mac.home, ".agents", "skills"), 0o777)
        self.assertTrue(any(".agents/skills" in g for g in mac.doctor()[1]))


if __name__ == "__main__":
    unittest.main()
