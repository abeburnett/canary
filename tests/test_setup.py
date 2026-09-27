"""Behavioural tests for `canary setup` and `canary doctor`.

The privileged script is run for real, as the current user, with a temporary
folder standing in for `/` and the current user standing in for root; nothing
touches this Mac's real policy folders.
"""

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

from canary import setup

MACOS = unittest.skipUnless(sys.platform == "darwin", "setup runs macOS tools (base64 -D, /Library)")
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


@MACOS
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
        proc = subprocess.run(shlex.split(setup.hook_command(mac.prefix, "claude")),
                              input="not json", capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)

    def test_scan_asks_for_no_password(self):
        mac = Mac()
        out, code = mac.setup("scan", runner=lambda text: self.fail("asked for a password"))
        self.assertEqual((out["outcome"], code), ("done", 0))
        self.assertFalse(os.path.exists(mac.at(setup.LIB)))


@MACOS
class ThePrivilegedScriptChecksItsPayload(unittest.TestCase):
    def test_a_changed_payload_installs_nothing(self):
        mac = Mac()
        text = setup.script(setup.plan("guard", mac.home, mac.prefix), mac.prefix, ME, ME)
        b64 = text.split("printf %s ", 1)[1].split(" |", 1)[0]
        tampered = text.replace(b64, b64[:-8] + ("A" * 8 if not b64.endswith("A" * 8) else "B" * 8), 1)
        self.assertFalse(mac.run_script(tampered))
        self.assertFalse(os.path.exists(mac.at(setup.LIB)))
        self.assertFalse(os.path.exists(mac.at(DROP_IN)))


@MACOS
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
        self.assertNotIn("Nothing is enforced", claim)

    def test_going_back_to_scan_keeps_files_someone_else_changed(self):
        mac = Mac()
        mac.setup("lockdown")
        with open(mac.at(DROP_IN), "a") as fh:
            fh.write("\n")
        mac.setup("scan")
        self.assertTrue(os.path.exists(mac.at(DROP_IN)))
        self.assertFalse(os.path.exists(mac.at(CODEX)))
        self.assertTrue(os.path.exists(mac.at(setup.LIB + "/bin/canary")))
        self.assertEqual(mac.doctor()[0], "scan")


@MACOS
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




@MACOS
class SetupTeachesAgentsAboutSkillCanary(unittest.TestCase):
    """0.1.1: setup installs the SkillCanary skill so "use Canary to install"
    works in Claude Code and Codex without a plugin."""

    def skill_paths(self, mac):
        return [os.path.join(mac.home, root, "canary", "SKILL.md")
                for root in (".claude/skills", ".agents/skills")]

    def test_each_level_installs_the_skill_in_both_hosts(self):
        from canary import frontdoor
        for level in ("scan", "guard", "lockdown"):
            with self.subTest(level):
                mac = Mac()
                out, code = mac.setup(level)
                self.assertEqual(code, 0)
                for path in self.skill_paths(mac):
                    with open(path) as fh:
                        self.assertEqual(fh.read(), frontdoor.installed_text())
                if level == "lockdown":
                    self.assertEqual(mac.doctor()[1], [])

    def test_a_canary_skill_someone_else_put_there_is_left_alone(self):
        mac = Mac()
        theirs = self.skill_paths(mac)[0]
        os.makedirs(os.path.dirname(theirs))
        with open(theirs, "w") as fh:
            fh.write("---\nname: canary\ndescription: someone else's\n---\n")
        mac.setup("guard")
        with open(theirs) as fh:
            self.assertIn("someone else's", fh.read())
        self.assertTrue(os.path.exists(self.skill_paths(mac)[1]))

    def test_the_shipped_skill_file_is_the_one_setup_installs(self):
        from canary import frontdoor
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "skills", "canary", "SKILL.md")) as fh:
            self.assertEqual(fh.read(), frontdoor.SKILL_TEXT)

    def test_the_privileged_step_never_writes_the_skill(self):
        mac = Mac()
        mac.setup("lockdown")
        self.assertTrue(mac.scripts)
        for text in mac.scripts:
            self.assertNotIn("SKILL.md", text)

    def test_a_folder_swapped_for_a_link_during_setup_is_not_followed(self):
        for level in ("guard", "lockdown"):
            with self.subTest(level):
                mac = Mac()
                outside = os.path.join(mac.prefix, "outside")
                os.makedirs(outside)
                victim = os.path.join(outside, "SKILL.md")
                with open(victim, "w") as fh:
                    fh.write("KEEP\n")
                folder = os.path.join(mac.home, ".claude", "skills", "canary")

                def swap_then_run(text):
                    if not os.path.lexists(folder):
                        os.symlink(outside, folder)
                    return mac.run_script(text)

                if level == "lockdown":
                    # At Lockdown the skill is written before the privileged
                    # step; swap before setup starts instead.
                    os.symlink(outside, folder)
                    mac.setup(level)
                else:
                    mac.setup(level, runner=swap_then_run)
                with open(victim) as fh:
                    self.assertEqual(fh.read(), "KEEP\n")

    def test_a_linked_skill_file_is_not_followed(self):
        mac = Mac()
        outside = os.path.join(mac.prefix, "outside.md")
        from canary import frontdoor
        with open(outside, "w") as fh:
            fh.write("KEEP" + frontdoor.MARKER)
        folder = os.path.join(mac.home, ".claude", "skills", "canary")
        os.makedirs(folder)
        os.symlink(outside, os.path.join(folder, "SKILL.md"))
        mac.setup("guard")
        with open(outside) as fh:
            self.assertEqual(fh.read(), "KEEP" + frontdoor.MARKER)



@MACOS
class InstallsWhereNoUserCanReplaceIt(unittest.TestCase):
    """0.1.1: /usr/local/lib is often owned by the person (old Homebrew), so
    anything running as them could swap the whole install. The program now
    lives in /Library/Application Support/SkillCanary, whose parents macOS
    keeps root-owned, and 0.1.0 installs move there."""

    def test_the_install_lives_under_library_application_support(self):
        self.assertEqual(setup.LIB, "Library/Application Support/SkillCanary")

    def test_a_0_1_0_guard_install_moves_and_its_policy_files_follow(self):
        import hashlib
        mac = Mac()
        old = mac.at("usr/local/lib/skillcanary")
        os.makedirs(os.path.join(old, "bin"))
        drop_in = mac.at(DROP_IN)
        os.makedirs(os.path.dirname(drop_in))
        from canary.hosts import claude as claude_host
        old_text = claude_host.managed_install_plan(os.path.join(old, "bin", "canary"))[0].content
        with open(drop_in, "w") as fh:
            fh.write(old_text)
        with open(os.path.join(old, "state.json"), "w") as fh:
            json.dump({"level": "guard", "locked": [],
                       "created": {drop_in: hashlib.sha256(old_text.encode()).hexdigest()}}, fh)
        out, code = mac.setup("guard")
        self.assertEqual((out["outcome"], out["manual"]), ("done", []))
        with open(drop_in) as fh:
            self.assertIn(setup.hook_command(mac.prefix, "claude"), fh.read().replace('\\"', '"'))
        # Root never deletes inside a folder the person controls; the old
        # copy is left unused, and nothing points at it any more.
        self.assertEqual(os.path.realpath(mac.at(setup.LINK)),
                         os.path.realpath(mac.at(setup.LIB + "/bin/canary")))
        self.assertEqual(mac.doctor()[:2], ("guard", []))



@MACOS
class OldStateIsAHintNotPermission(unittest.TestCase):
    """0.1.1 round 2: 0.1.0's state.json can sit in a folder the person
    controls, so nothing in it may authorize a root operation."""

    def forge(self, mac, state):
        old = mac.at("usr/local/lib/skillcanary")
        os.makedirs(old, exist_ok=True)
        with open(os.path.join(old, "state.json"), "w") as fh:
            json.dump(state, fh)

    def victim(self, mac, name="important.conf", mode=0o600):
        path = mac.at("etc/" + name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write("KEEP\n")
        os.chmod(path, mode)
        return path

    def test_forged_created_entries_are_never_deleted(self):
        import hashlib
        mac = Mac()
        victim = self.victim(mac)
        self.forge(mac, {"level": "guard", "locked": [], "created": {
            victim: hashlib.sha256(b"KEEP\n").hexdigest(), mac.at("etc/unreadable"): None}})
        mac.setup("scan")
        self.assertTrue(os.path.exists(victim))
        for text in mac.scripts:
            self.assertNotIn(victim, text)

    def test_forged_locked_folders_are_never_touched(self):
        mac = Mac()
        private = mac.at("private-folder")
        os.makedirs(private)
        os.chmod(private, 0o700)
        self.forge(mac, {"level": "lockdown", "created": {}, "locked": [private]})
        mac.setup("guard")
        for text in mac.scripts:
            self.assertNotIn(private, text)
        self.assertEqual(os.stat(private).st_mode & 0o777, 0o700)

    def test_a_forged_hash_cannot_claim_an_administrators_policy(self):
        import hashlib
        mac = Mac()
        policy = mac.at(CODEX)
        os.makedirs(os.path.dirname(policy))
        with open(policy, "w") as fh:
            fh.write("# the administrator's policy\n")
        self.forge(mac, {"level": "guard", "locked": [], "created": {
            policy: hashlib.sha256(b"# the administrator's policy\n").hexdigest()}})
        out, _ = mac.setup("guard")
        with open(policy) as fh:
            self.assertEqual(fh.read(), "# the administrator's policy\n")
        self.assertEqual([m["path"] for m in out["manual"]], [policy])


@MACOS
class LockdownNeverFollowsLinks(unittest.TestCase):
    def test_a_linked_skills_root_is_not_locked_and_doctor_says_so(self):
        mac = Mac()
        private = mac.at("private-folder")
        os.makedirs(private)
        os.chmod(private, 0o700)
        root = os.path.join(mac.home, ".claude", "skills")
        os.rmdir(root)
        os.symlink(private, root)
        mac.setup("lockdown")
        self.assertEqual(os.stat(private).st_mode & 0o777, 0o700)
        self.assertTrue(any(".claude/skills" in g for g in mac.doctor()[1]))

    def test_a_link_above_the_skills_root_is_refused_too(self):
        mac = Mac()
        elsewhere = mac.at("elsewhere")
        os.makedirs(os.path.join(elsewhere, "skills"))
        os.chmod(elsewhere, 0o700)
        claude = os.path.join(mac.home, ".claude")
        os.rmdir(os.path.join(claude, "skills"))
        os.rmdir(claude)
        os.symlink(elsewhere, claude)
        mac.setup("lockdown")
        self.assertEqual(os.stat(os.path.join(elsewhere, "skills")).st_mode & 0o022,
                         os.stat(os.path.join(elsewhere, "skills")).st_mode & 0o022)
        self.assertFalse(os.path.exists(os.path.join(elsewhere, "skills", "canary")))
        self.assertTrue(any(".claude" in g for g in mac.doctor()[1]))



@MACOS
class NeverTouchesWhatItCannotSeeOrOwn(unittest.TestCase):
    """0.1.1 round 3: an unreadable policy is not a missing one, and a file
    with more than one name is never re-owned or re-permissioned."""

    def test_an_unreadable_policy_is_a_manual_step(self):
        mac = Mac()
        policy = mac.at(CODEX)
        os.makedirs(os.path.dirname(policy))
        with open(policy, "w") as fh:
            fh.write("# the administrator's policy\n")
        os.chmod(policy, 0o000)
        try:
            out, _ = mac.setup("guard")
            self.assertEqual([m["path"] for m in out["manual"]], [policy])
        finally:
            os.chmod(policy, 0o600)
        with open(policy) as fh:
            self.assertEqual(fh.read(), "# the administrator's policy\n")

    def test_hard_linked_files_are_left_alone_and_reported(self):
        mac = Mac()
        outside = mac.at("etc/outside.conf")
        os.makedirs(os.path.dirname(outside))
        with open(outside, "w") as fh:
            fh.write("x")
        os.chmod(outside, 0o666)
        os.link(outside, os.path.join(mac.home, ".claude", "skills", "linked.md"))
        mac.setup("lockdown")
        self.assertEqual(os.stat(outside).st_mode & 0o777, 0o666)
        self.assertTrue(any("more than one name" in g for g in mac.doctor()[1]))
        mac.setup("scan")
        self.assertEqual(os.stat(outside).st_mode & 0o777, 0o666)


if __name__ == "__main__":
    unittest.main()
