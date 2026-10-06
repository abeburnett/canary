"""Behavioural tests for `canary setup` and `canary doctor`.

The privileged script is run for real, as the current user, with a temporary
folder standing in for `/` and the current user standing in for root; nothing
touches this Mac's real policy folders.
"""

import contextlib
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

from canary import add, cli, setup

MACOS = unittest.skipUnless(sys.platform == "darwin", "setup runs macOS tools (base64 -D, /Library)")
ME = f"{os.getuid()}:{os.getgid()}"



def setUpModule():
    """A test that reaches the real launchctl fails rather than loading a
    launch agent on the machine running the tests."""
    def refuse(args):
        raise AssertionError(f"a test reached the real launchctl: {args}")
    patch = unittest.mock.patch.object(setup, "launchctl", refuse)
    patch.start()
    unittest.addModuleCleanup(patch.stop)

class Mac:
    def __init__(self):
        self.prefix = os.path.realpath(tempfile.mkdtemp(prefix="canary-root-"))
        self.home = os.path.join(self.prefix, "Users", "person")
        for d in (".claude/skills", ".agents/skills"):
            os.makedirs(os.path.join(self.home, d))
        self.scripts = []
        self.launches, self.loaded = [], False

    def launch(self, args):
        """A stand-in for launchctl: tests never load a real launch agent."""
        self.launches.append(list(args))
        if args[0] == "bootstrap":
            self.loaded = True
        elif args[0] == "bootout":
            self.loaded = False
        elif args[0] == "print":
            return 0 if self.loaded else 113
        return 0

    def run_script(self, text):
        self.scripts.append(text)
        return subprocess.run(["/bin/sh", "-c", text], capture_output=True,
                              timeout=120).returncode == 0

    def setup(self, level, runner=None):
        return setup.setup(level, home=self.home, prefix=self.prefix,
                           runner=runner or self.run_script, owner=ME, person=ME,
                           launcher=self.launch)

    def doctor(self):
        return setup.doctor(self.home, self.prefix, expected_uid=os.getuid(),
                            launcher=self.launch)

    def at(self, path):
        return os.path.join(self.prefix, path.lstrip("/"))

    def at_old_lockdown(self):
        """This Mac as SkillCanary 0.1.x left it at Lockdown: installed, with
        the root-owned state recording the level."""
        out, _ = self.setup("guard")
        assert out["outcome"] == "done", out
        state_path = os.path.join(self.at(setup.LIB), "state.json")
        with open(state_path) as fh:
            state = json.load(fh)
        state["level"] = "lockdown"
        state["locked"] = setup.lock_roots(self.home)
        with open(state_path, "w") as fh:
            json.dump(state, fh)
        self.scripts.clear()


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

    def test_guard_starts_the_watcher_and_scan_removes_it(self):
        from canary import watcher
        mac = Mac()
        seen = os.path.join(mac.home, "Library", "Application Support", "Canary", watcher.SEEN)
        os.makedirs(os.path.dirname(seen))
        with open(seen, "w") as fh:
            fh.write("{}")  # left from an earlier watcher
        mac.setup("guard")
        self.assertFalse(os.path.exists(seen))  # setup is a fresh first look
        plist = watcher.plist_path(mac.home)
        with open(plist) as fh:
            text = fh.read()
        self.assertIn("<string>watch</string>", text)
        self.assertIn(f"<string>{mac.at(setup.LIB)}/bin/canary</string>", text)
        self.assertEqual(mac.launches[-1], ["bootstrap", f"gui/{os.getuid()}", plist])
        self.assertEqual(mac.doctor()[1], [])
        with open(plist, "w") as fh:
            fh.write(text.replace("<string>watch</string>", "<string>list</string>"))
        self.assertTrue(any("watcher" in g and "changed" in g for g in mac.doctor()[1]))
        mac.setup("guard")
        mac.loaded = False  # stopped behind SkillCanary's back
        self.assertTrue(any("watcher is not running" in g for g in mac.doctor()[1]))
        mac.setup("scan")
        self.assertFalse(os.path.exists(plist))
        self.assertEqual(mac.launches[-1][0], "bootout")

    def test_guard_adds_the_guest_list_hook_in_both_hosts(self):
        mac = Mac()
        mac.setup("guard")
        with open(mac.at(DROP_IN)) as fh:
            session = json.load(fh)["hooks"]["SessionStart"][0]["hooks"][0]["command"]
        self.assertTrue(session.endswith("session-start --host claude"))
        self.assertTrue(session.startswith("/usr/bin/python3 -I "))
        with open(mac.at(CODEX)) as fh:
            codex = fh.read()
        self.assertIn("[[hooks.SessionStart]]", codex)
        self.assertIn("session-start --host codex", codex)

    def test_setup_takes_the_guest_lists_first_look(self):
        from canary import guestlist
        mac = Mac()
        folder = os.path.join(mac.home, ".agents", "skills", "mine")
        os.makedirs(folder)
        with open(os.path.join(folder, "SKILL.md"), "w") as fh:
            fh.write("---\nname: mine\ndescription: x\n---\nBody.\n")
        mac.setup("scan")
        self.assertTrue(os.path.exists(os.path.join(
            mac.home, "Library", "Application Support", "Canary", "ledger.jsonl")))
        later = os.path.join(mac.home, ".agents", "skills", "later")
        os.makedirs(later)
        with open(os.path.join(later, "SKILL.md"), "w") as fh:
            fh.write("---\nname: later\ndescription: x\n---\nBody.\n")
        report = guestlist.scan(mac.home)
        statuses = {s["name"]: s["status"] for s in report["skills"]}
        self.assertEqual((statuses["mine"], statuses["later"]), ("yours", "unchecked"))

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
        mac.setup("guard")
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

    def test_guard_does_not_report_lockdown_gaps(self):
        # The owner's 2026-09-30 doctor run reported a hard link in a skills
        # folder: a gap only Lockdown's locking cared about.
        mac = Mac()
        outside = mac.at("etc/outside.conf")
        os.makedirs(os.path.dirname(outside))
        with open(outside, "w") as fh:
            fh.write("x")
        os.link(outside, os.path.join(mac.home, ".agents", "skills", "linked.bin"))
        mac.setup("guard")
        self.assertEqual(mac.doctor()[1], [])




@MACOS
class SetupTeachesAgentsAboutSkillCanary(unittest.TestCase):
    """0.1.1: setup installs the SkillCanary skill so "use Canary to install"
    works in Claude Code and Codex without a plugin."""

    def skill_paths(self, mac):
        return [os.path.join(mac.home, root, "canary", "SKILL.md")
                for root in (".claude/skills", ".agents/skills")]

    def test_each_level_installs_the_skill_in_both_hosts(self):
        from canary import frontdoor
        for level in ("scan", "guard"):
            with self.subTest(level):
                mac = Mac()
                out, code = mac.setup(level)
                self.assertEqual(code, 0)
                for path in self.skill_paths(mac):
                    with open(path) as fh:
                        self.assertEqual(fh.read(), frontdoor.installed_text())

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

    def test_the_skill_tells_agents_to_relay_the_plain_judgment_and_keep_explain_for_the_person(self):
        from canary import frontdoor
        text = " ".join(frontdoor.SKILL_TEXT.split())
        for phrase in (
                "relay the headline first, then the reasons and the steps",
                "explain (for the person only: never run canary explain or --excerpts yourself; "
                "give the person the command to run in their own terminal)",
                "canary doctor --prune"):
            self.assertIn(phrase, text)

    def test_the_privileged_step_never_writes_the_skill(self):
        mac = Mac()
        mac.setup("guard")
        self.assertTrue(mac.scripts)
        for text in mac.scripts:
            self.assertNotIn("SKILL.md", text)

    def test_a_folder_swapped_for_a_link_during_setup_is_not_followed(self):
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

        mac.setup("guard", runner=swap_then_run)
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


class LockdownIsGone(unittest.TestCase):
    """Front door, slice A2 (owner decision 2026-09-30): Lockdown is removed,
    and a Mac still at Lockdown gets its skill folders back."""

    def test_lockdown_can_no_longer_be_chosen(self):
        self.assertEqual(setup.LEVELS, ("scan", "guard"))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run([sys.executable, os.path.join(root, "bin", "canary"), "setup",
                               "--level", "lockdown"], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("guard", proc.stderr)

    @MACOS
    def test_doctor_tells_a_mac_still_at_lockdown_how_to_leave_it(self):
        mac = Mac()
        mac.at_old_lockdown()
        level, gaps, _ = mac.doctor()
        self.assertTrue(any("canary setup --level guard" in g for g in gaps))

    @MACOS
    def test_setup_returns_the_skill_folders_and_records_guard(self):
        mac = Mac()
        mac.at_old_lockdown()
        out, code = mac.setup("guard")
        self.assertEqual((out["outcome"], code), ("done", 0))
        self.assertTrue(any("_roots unlock" in t for t in mac.scripts))
        self.assertFalse(any("_roots lock" in t for t in mac.scripts))
        self.assertEqual(mac.doctor()[:2], ("guard", []))

    def chowned_inodes(self, home, roots):
        """Run the root step's unlock and record the inode of everything it
        re-owns. In a test the owner and the person are the same account, so
        ownership itself cannot show what was touched."""
        import unittest.mock
        touched = set()
        real_fchown, real_chown = os.fchown, os.chown

        def fchown(fd, uid, gid):
            touched.add(os.fstat(fd).st_ino)
            return real_fchown(fd, uid, gid)

        def chown(name, uid, gid, dir_fd=None, follow_symlinks=True):
            touched.add(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_ino)
            return real_chown(name, uid, gid, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

        with unittest.mock.patch.object(os, "fchown", fchown), \
                unittest.mock.patch.object(os, "chown", chown):
            setup.change_roots("unlock", ME, ME, home, roots)
        return touched

    def test_unlock_reowns_the_folder_but_not_a_linked_one_or_a_hard_link(self):
        base = os.path.realpath(tempfile.mkdtemp(prefix="canary-unlock-"))
        home = os.path.join(base, "home")
        real_root = os.path.join(home, ".agents", "skills")
        os.makedirs(os.path.join(real_root, "notes"))
        with open(os.path.join(real_root, "notes", "SKILL.md"), "w") as fh:
            fh.write("x")
        private = os.path.join(base, "private")
        os.makedirs(private)
        linked_root = os.path.join(home, ".claude", "skills")
        os.makedirs(os.path.dirname(linked_root))
        os.symlink(private, linked_root)
        outside = os.path.join(base, "outside.conf")
        with open(outside, "w") as fh:
            fh.write("x")
        os.link(outside, os.path.join(real_root, "notes", "linked.conf"))
        touched = self.chowned_inodes(home, [real_root, linked_root])
        self.assertIn(os.stat(real_root).st_ino, touched)
        self.assertIn(os.stat(os.path.join(real_root, "notes", "SKILL.md")).st_ino, touched)
        self.assertNotIn(os.stat(private).st_ino, touched)
        self.assertNotIn(os.stat(outside).st_ino, touched)

    def test_the_root_step_can_no_longer_lock(self):
        home = os.path.realpath(tempfile.mkdtemp(prefix="canary-lock-"))
        with self.assertRaises(ValueError):
            setup.change_roots("lock", ME, ME, home, setup.lock_roots(home))

    @MACOS
    def test_going_to_scan_without_the_helper_keeps_lockdown_recorded(self):
        mac = Mac()
        mac.at_old_lockdown()
        os.chmod(mac.at(setup.LIB + "/bin"), 0o755)
        os.unlink(mac.at(setup.LIB + "/bin/canary"))
        out, code = mac.setup("scan")
        self.assertEqual((out["outcome"], code), ("not_changed", 10))
        self.assertEqual(setup.read_state(mac.prefix)["level"], "lockdown")

    # Spark 1.3 Contributor's review of slice A2 (2026-10-01).
    @MACOS
    def test_a_lockdown_level_in_the_old_user_folder_unlocks_nothing(self):
        mac = Mac()
        old = mac.at("usr/local/lib/skillcanary")
        os.makedirs(old)
        with open(os.path.join(old, "state.json"), "w") as fh:
            json.dump({"level": "lockdown", "created": {}, "locked": []}, fh)
        self.assertEqual(setup.plan("guard", mac.home, mac.prefix)["unlock"], [])
        mac.setup("guard")
        self.assertFalse(any("_roots" in t for t in mac.scripts))

    def test_setup_takes_the_home_folder_from_the_account_not_the_environment(self):
        import pwd
        import unittest.mock
        seen = {}

        def chooser():
            return None
        with unittest.mock.patch.dict(os.environ, {"HOME": "/Users/someone-else"}), \
                unittest.mock.patch.object(setup, "plan", side_effect=lambda level, home, prefix:
                                           seen.setdefault("home", home) and {}):
            try:
                setup.setup("guard", runner=lambda text: False, chooser=chooser)
            except Exception:
                pass
        self.assertEqual(seen.get("home"), pwd.getpwuid(os.getuid()).pw_dir)

    def test_the_root_step_only_unlocks_the_two_known_folders(self):
        base = os.path.realpath(tempfile.mkdtemp(prefix="canary-unlock-"))
        home = os.path.join(base, "home")
        victim = os.path.join(base, "victim")
        os.makedirs(victim)
        with self.assertRaises(ValueError):
            setup.change_roots("unlock", ME, ME, home, [victim])

    def test_the_root_step_refuses_to_run_as_anyone_but_root(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if os.geteuid() == 0:
            self.skipTest("runs as root")
        proc = subprocess.run([sys.executable, os.path.join(root, "bin", "canary"), "_roots",
                               "unlock", "root:wheel", ME, "/nonexistent-home",
                               "/nonexistent-home/.claude/skills"],
                              capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0)

    @MACOS
    def test_a_failed_unlock_does_not_record_guard(self):
        mac = Mac()
        mac.at_old_lockdown()
        broken = lambda text: mac.run_script(text.replace(" _roots unlock ", " _roots no-such-verb "))
        out, code = mac.setup("guard", runner=broken)
        self.assertEqual((out["outcome"], code), ("not_changed", 10))
        self.assertEqual(setup.read_state(mac.prefix)["level"], "lockdown")

    @MACOS
    def test_doctor_reports_a_skills_folder_still_owned_by_root(self):
        import unittest.mock
        mac = Mac()
        mac.setup("guard")
        root = os.path.join(mac.home, ".agents", "skills")
        real_stat = os.stat
        fake_root = os.getuid() + 1

        def stat(path, *a, **k):
            st = real_stat(path, *a, **k)
            if os.path.realpath(path) == os.path.realpath(root):
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, fake_root,
                                       st.st_gid, st.st_size, st.st_atime, st.st_mtime, st.st_ctime))
            return st
        with unittest.mock.patch.object(os, "stat", stat):
            gaps = setup.doctor(mac.home, mac.prefix, expected_uid=os.getuid(), root_uid=fake_root,
                                launcher=mac.launch)[1]
        self.assertTrue(any(".agents/skills" in g and "root" in g for g in gaps), gaps)

    @MACOS
    def test_doctor_does_not_call_an_unknown_level_scan(self):
        mac = Mac()
        mac.setup("guard")
        state = os.path.join(mac.at(setup.LIB), "state.json")
        with open(state) as fh:
            data = json.load(fh)
        data["level"] = "weird"
        with open(state, "w") as fh:
            json.dump(data, fh)
        level, gaps, claim = mac.doctor()
        self.assertNotEqual(level, "scan")
        self.assertTrue(gaps)

    def test_asking_the_api_for_lockdown_is_an_error(self):
        with self.assertRaises(ValueError):
            setup.setup("lockdown", runner=lambda text: self.fail("ran the root step"))

    @MACOS
    def test_returning_folders_never_follows_a_link(self):
        mac = Mac()
        private = mac.at("private-folder")
        os.makedirs(private)
        os.chmod(private, 0o700)
        mac.at_old_lockdown()
        root = os.path.join(mac.home, ".claude", "skills")
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                for f in os.listdir(path):
                    os.unlink(os.path.join(path, f))
                os.rmdir(path)
        os.rmdir(root)
        os.symlink(private, root)
        mac.setup("guard")
        self.assertEqual(os.stat(private).st_mode & 0o777, 0o700)


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

    def test_hard_linked_files_are_left_alone_when_folders_are_returned(self):
        mac = Mac()
        outside = mac.at("etc/outside.conf")
        os.makedirs(os.path.dirname(outside))
        with open(outside, "w") as fh:
            fh.write("x")
        os.chmod(outside, 0o666)
        os.link(outside, os.path.join(mac.home, ".claude", "skills", "linked.md"))
        mac.at_old_lockdown()
        mac.setup("guard")
        self.assertEqual(os.stat(outside).st_mode & 0o777, 0o666)


class OldInstallRecords(unittest.TestCase):
    """Program 2026-10-06, section 1: `canary doctor` lists install records
    whose folders are gone, and `--prune` removes them only when the person
    agrees."""

    def setUp(self):
        self.home = os.path.realpath(tempfile.mkdtemp(prefix="canary-lock-"))
        os.makedirs(os.path.join(self.home, ".agents"))
        self.live = os.path.join(self.home, ".agents", "skills", "alive")
        os.makedirs(self.live)

    def write(self, skills, plugins=None, raw=None):
        path = os.path.join(self.home, ".agents", ".canary-lock.json")
        lock = {"schema": "canary.lock/1", "skills": skills}
        if plugins is not None:
            lock["plugins"] = plugins
        with open(path, "w") as fh:
            fh.write(raw if raw is not None else json.dumps(lock))

    def lock(self):
        with open(os.path.join(self.home, ".agents", ".canary-lock.json")) as fh:
            return json.load(fh)

    def gone(self, name):
        return os.path.join(self.home, ".agents", "skills", name)

    def mixed(self):
        self.write({"zeta": {"installed": [self.gone("zeta")]},
                    "alive": {"installed": [self.live]},
                    "alpha@0123456789ab": {"name": "alpha", "installed": [self.gone("alpha")]},
                    "broken": {"installed": "not a list"},
                    "mixed": {"installed": [self.gone("mixed"), 7]},
                    "empty": {"installed": []},
                    "odd": "not a record"},
                   {"tidy@mkt": {"installed": [self.gone("tidy")]},
                    "kept@mkt": {"installed": [self.live]}})

    def test_the_dead_records_are_listed_skills_first_and_malformed_ones_are_dead(self):
        self.mixed()
        self.assertEqual(setup.old_records(self.home), [
            {"kind": "skill", "key": "alpha@0123456789ab", "name": "alpha",
             "installed": [self.gone("alpha")]},
            {"kind": "skill", "key": "broken", "name": "broken", "installed": []},
            {"kind": "skill", "key": "empty", "name": "empty", "installed": []},
            {"kind": "skill", "key": "mixed", "name": "mixed", "installed": []},
            {"kind": "skill", "key": "odd", "name": "odd", "installed": []},
            {"kind": "skill", "key": "zeta", "name": "zeta", "installed": [self.gone("zeta")]},
            {"kind": "plugin", "key": "tidy@mkt", "name": "tidy@mkt",
             "installed": [self.gone("tidy")]}])

    def test_no_lockfile_has_no_records_and_a_broken_one_is_an_error(self):
        self.assertEqual(setup.old_records(self.home), [])
        self.write({}, raw="{not json")
        with self.assertRaises(add.LockError):
            setup.old_records(self.home)

    def run_cli(self, args, ask=None, doctor=("scan", [], "Scans.")):
        out, err = io.StringIO(), io.StringIO()
        patches = [unittest.mock.patch.dict(os.environ, {"HOME": self.home}),
                   unittest.mock.patch.object(setup, "doctor", return_value=doctor)]
        if ask is not None:
            patches.append(unittest.mock.patch.object(add, "ask", ask))
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = cli.main(["doctor", *args])
        return code, out.getvalue(), err.getvalue()

    def test_doctor_lists_old_records_without_changing_its_exit_code(self):
        self.mixed()
        code, out, _ = self.run_cli([])
        self.assertEqual(code, 0)
        self.assertEqual(out, (
            "Protection level: scan\nWhat SkillCanary can claim here: Scans.\n"
            "Old install records: 7 (their folders are gone)\n"
            "  alpha  ~/.agents/skills/alpha\n  broken  (no path recorded)\n"
            "  empty  (no path recorded)\n  mixed  (no path recorded)\n"
            "  odd  (no path recorded)\n  zeta  ~/.agents/skills/zeta\n"
            "  tidy@mkt  ~/.agents/skills/tidy\n"
            "Run canary doctor --prune to remove them. It asks you first.\n"))
        code, _, _ = self.run_cli([], doctor=("guard", ["a gap"], "Guards."))
        self.assertEqual(code, 10)

    def test_doctor_json_carries_old_records_and_says_one_in_the_singular(self):
        code, out, _ = self.run_cli(["--json"])
        self.assertEqual(json.loads(out).get("old_records"), [])
        self.write({"zeta": {"installed": [self.gone("zeta")]}})
        _, out, _ = self.run_cli([])
        self.assertIn("Old install records: 1 (its folder is gone)\n", out)
        _, out, _ = self.run_cli(["--json"])
        self.assertEqual(json.loads(out).get("old_records"), [
            {"kind": "skill", "key": "zeta", "name": "zeta", "installed": [self.gone("zeta")]}])

    def test_an_unreadable_lockfile_is_reported_and_doctor_carries_on(self):
        self.write({}, raw="{not json")
        code, out, err = self.run_cli([])
        self.assertEqual(code, 0)
        self.assertIn("Protection level: scan", out)
        self.assertIn("is not a Canary lockfile", err)
        self.assertTrue(err.startswith("canary: "))

    def test_prune_asks_then_removes_only_what_is_still_dead(self):
        self.mixed()
        seen = []

        def agree(text, verdict, yes=None):
            seen.append((text, verdict, yes))
            os.makedirs(self.gone("zeta"))  # comes back while the person decides
            return True

        code, out, _ = self.run_cli(["--prune"], ask=agree)
        self.assertEqual((code, out), (0, "Removed 6 old install records.\n"))
        self.assertEqual(seen[0][1:], ("NEEDS_REVIEW", "Remove records"))
        self.assertEqual(sorted(self.lock()["skills"]), ["alive", "zeta"])
        self.assertEqual(sorted(self.lock()["plugins"]), ["kept@mkt"])

    def test_the_prune_dialog_text(self):
        self.write({"a": {"installed": [self.gone("a")]}, "b": {}},
                   {"p@m": {"installed": [self.gone("p")]}})
        texts = []
        self.run_cli(["--prune"], ask=lambda t, v, yes=None: texts.append(t) or False)
        self.assertEqual(texts, [
            "SkillCanary has 3 install records for skills or plugins whose folders are gone:\n"
            "- a (~/.agents/skills/a)\n- b (no path recorded)\n- p@m (~/.agents/skills/p)\n"
            "Removing them lets you install these names again. It does not change any\n"
            "skill or plugin on this Mac.\n\n"
            "The names come from the packages, not from SkillCanary."])
        self.write({"a": {"installed": [self.gone("a")]}})
        texts.clear()
        self.run_cli(["--prune"], ask=lambda t, v, yes=None: texts.append(t) or False)
        self.assertTrue(texts[0].startswith("SkillCanary has 1 install record for a skill or "
                                            "plugin whose folders are gone:\n- a ("))
        self.write({f"s{n:02}": {"installed": [self.gone("x")]} for n in range(23)})
        texts.clear()
        self.run_cli(["--prune"], ask=lambda t, v, yes=None: texts.append(t) or False)
        lines = texts[0].splitlines()
        self.assertEqual(len([l for l in lines if l.startswith("- ")]), 21)
        self.assertEqual(lines[21], "- and 3 more")

    def test_prune_removes_nothing_unless_the_person_agrees(self):
        self.mixed()
        before = self.lock()
        for answer in (False, None, "yes"):
            with self.subTest(answer=answer):
                code, out, _ = self.run_cli(["--prune"], ask=lambda t, v, yes=None: answer)
                self.assertEqual((code, out), (10, "Nothing removed: the person did not agree "
                                                   "in SkillCanary's dialog.\n"))
                self.assertEqual(self.lock(), before)

    def test_prune_with_nothing_to_remove_shows_no_dialog_and_a_broken_lock_exits_3(self):
        self.write({"alive": {"installed": [self.live]}})

        def never(*a, **kw):
            raise AssertionError("no dialog expected")

        self.assertEqual(self.run_cli(["--prune"], ask=never)[:2], (0, "No old install records.\n"))
        self.write({}, raw="{not json")
        code, _, err = self.run_cli(["--prune"], ask=never)
        self.assertEqual(code, 3)
        self.assertTrue(err.startswith("canary: "))

    def test_doctor_takes_only_nothing_json_or_prune(self):
        for args in (["--prune", "--json"], ["--yes"], ["--json", "x"]):
            with self.subTest(args=args):
                self.assertEqual(self.run_cli(args)[0], 2)


if __name__ == "__main__":
    unittest.main()
