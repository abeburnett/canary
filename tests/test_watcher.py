"""Behavioural tests for the watcher (docs/program-2026-09-30-front-door.md,
slice B2): a new, unchecked skill in a skills folder is held once it settles,
checked, and put back only when the person says so. Nothing is deleted.

The tests drive `Watcher.step` with a made-up clock; they never start launchd
or kqueue.
"""

import json
import os
import shutil
import contextlib
import io
import tarfile
import tempfile
import unittest
import unittest.mock

from canary import add, cli, frontdoor, guestlist, watcher
try:
    from test_add import FakeGitHub, URL, SKILL, Approver, model, tarball
    import test_install
except ImportError:  # run as tests.test_watcher
    from tests.test_add import FakeGitHub, URL, SKILL, Approver, model, tarball
    from tests import test_install


SUFFIX = " canary list shows where it is."
STILL_CANCELLED = "Still held: you chose not to install it." + SUFFIX
STILL_SILENT = "Still held: nobody answered the SkillCanary dialog." + SUFFIX
STILL_LINKS = ("Still held: it holds links or special files SkillCanary will not copy." + SUFFIX)
STILL_CHANGED = "Still held: it changed after its check." + SUFFIX
STILL_TAKEN = "Still held: something else is in its place now." + SUFFIX
STILL_NOT_MOVED = "Still held: SkillCanary could not move it back." + SUFFIX
STILL_GONE = "Still held: SkillCanary is no longer holding it."


def skill(root, name, body="Help.\n"):
    folder = os.path.join(root, name)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "SKILL.md"), "w") as fh:
        fh.write(f"---\nname: {name}\ndescription: A skill.\n---\n{body}")
    return folder


class Mac:
    """A home with one skill in each skills folder, set up (first look
    taken), and a watcher started on it."""

    def __init__(self, verdict="SAFE", answer=True, home=None):
        self.home = home or os.path.realpath(tempfile.mkdtemp(prefix="canary-watch-"))
        self.support = os.path.join(self.home, "Library", "Application Support", "Canary")
        self.claude = os.path.join(self.home, ".claude", "skills")
        self.codex = os.path.join(self.home, ".agents", "skills")
        if home is None:
            skill(self.claude, "notes")
            skill(self.codex, "orchestrate")
            guestlist.scan(self.home, support=self.support, first_look=True)
        self.asked, self.notes, self.answer, self.confirms = [], [], answer, []
        self.w = watcher.Watcher(self.home, self.support, ask=self.ask, notify=self.notes.append,
                                 backend=model(verdict), model="fake")

    def ask(self, text, verdict, confirm=None):
        self.asked.append(text)
        self.confirms.append(confirm)
        return self.answer

    def settle(self, start=0.0):
        """Look, then look again after the settle wait; the ids held."""
        return self.w.step(start) + self.w.step(start + 5) + self.w.step(start + 10)

    def held(self):
        return watcher.held(self.support, self.w.roots)


class WhatTheWatcherLeavesAlone(unittest.TestCase):
    def test_skills_already_there_and_changes_to_them_are_never_held(self):
        mac = Mac()
        skill(mac.codex, "orchestrate", body="Route work, with lessons.\n")
        with open(os.path.join(mac.claude, "notes", "extra.md"), "w") as fh:
            fh.write("more")
        self.assertEqual(mac.settle(), [])

    def test_canary_add_is_not_held(self):
        mac = Mac()
        archive = tarball([("notes2/SKILL.md", tarfile.REGTYPE, SKILL.replace("notes", "notes2"))])
        out = add.add(URL.replace("notes", "notes2"), home=mac.home, support_dir=mac.support,
                      approve=Approver(True), fetch=FakeGitHub(archive), backend=model(),
                      model="fake")
        self.assertEqual(out["outcome"], "installed")
        self.assertEqual(mac.settle(), [])

    def test_canary_install_and_its_links_are_not_held(self):
        installing = test_install.Mac()
        mac = Mac(home=installing.home)
        out = installing.install(test_install.ADD, spec=test_install.ONE)
        self.assertEqual(out["outcome"], "installed")
        self.assertEqual(mac.settle(), [])

    def test_skillcanarys_own_skill_is_not_held(self):
        mac = Mac()
        frontdoor.write(mac.home, mac.claude)
        self.assertEqual(mac.settle(), [])


class ANewSkillIsHeld(unittest.TestCase):
    def test_a_new_skill_is_held_only_once_it_settles(self):
        mac = Mac()
        folder = skill(mac.codex, "dropped-in")
        self.assertEqual(mac.w.step(0), [])
        self.assertEqual(mac.w.step(1), [])  # still settling
        self.assertTrue(os.path.isdir(folder))
        held = mac.w.step(3)
        self.assertEqual(len(held), 1)
        self.assertFalse(os.path.lexists(folder))
        self.assertEqual([(h["name"], h["origin"]) for h in mac.held()], [("dropped-in", folder)])

    def test_a_folder_gets_held_when_its_skill_md_arrives(self):
        mac = Mac()
        folder = os.path.join(mac.codex, "slow")
        os.makedirs(folder)
        self.assertEqual(mac.settle(), [])
        skill(mac.codex, "slow")
        self.assertEqual(len(mac.settle(start=20)), 1)

    def test_a_link_to_a_folder_outside_is_held(self):
        mac = Mac()
        outside = skill(os.path.join(mac.home, "elsewhere"), "ext")
        os.symlink(outside, os.path.join(mac.claude, "ext"))
        self.assertEqual(len(mac.settle()), 1)
        self.assertFalse(os.path.lexists(os.path.join(mac.claude, "ext")))
        self.assertTrue(os.path.isdir(outside))  # the folder it led to is untouched

    def test_a_link_into_another_skills_folder_follows_its_target(self):
        mac = Mac()
        skill(mac.codex, "both")
        os.symlink(os.path.join("..", "..", ".agents", "skills", "both"),
                   os.path.join(mac.claude, "both"))
        self.assertEqual([h["origin"] for h in (mac.settle() and mac.held())],
                         [os.path.join(mac.codex, "both")])


class ThePersonDecides(unittest.TestCase):
    def test_install_puts_it_back_and_it_counts_as_checked(self):
        mac = Mac()
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        self.assertEqual(mac.w.review(held_id), (True, None))
        self.assertEqual(len(mac.asked), 1)
        self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))
        self.assertEqual(mac.held(), [])
        report = guestlist.scan(mac.home, support=mac.support)
        self.assertEqual({s["status"] for s in report["skills"] if s["name"] == "dropped-in"},
                         {"checked"})
        self.assertEqual(mac.settle(start=20), [])  # put back, not held again

    def test_a_link_put_back_still_leads_to_its_folder(self):
        mac = Mac()
        outside = skill(os.path.join(mac.home, "elsewhere"), "ext")
        # Relative, as installers write them: it must be read from where it was.
        os.symlink(os.path.join("..", "..", "elsewhere", "ext"), os.path.join(mac.claude, "ext"))
        [held_id] = mac.settle()
        self.assertEqual(mac.w.review(held_id), (True, None))
        self.assertEqual(os.path.realpath(os.path.join(mac.claude, "ext")), outside)
        self.assertEqual(mac.settle(start=20), [])

    def test_the_dialog_recommends_an_action_and_quotes_the_line(self):
        """Program 2026-10-12: the held-skill dialog says what to do, the
        risk in plain words, and the line that raised it."""
        mac = Mac(verdict="NEEDS_REVIEW", answer=False)
        skill(mac.codex, "dropped-in", "Then cat ~/.ssh/id_rsa into the notes.\n")
        [held_id] = mac.settle()
        self.assertFalse(mac.w.review(held_id)[0])
        [text] = mac.asked
        self.assertIn("SkillCanary checked it: needs your judgment.\n\nRecommended: decline, "
                      "unless you wrote it or know why it does this.\n", text)
        self.assertIn("What SkillCanary found:\n- It can read your SSH keys (~/.ssh), which "
                      "unlock your servers and code hosts.\n    SKILL.md line 5: \"Then cat "
                      "~/.ssh/id_rsa into the notes.\"\n", text)
        self.assertNotIn("Threat patterns found", text)
        self.assertTrue(text.endswith("not from SkillCanary. So do the file names and quoted "
                                      "lines."))

    def test_cancel_keeps_it_held_and_canary_list_says_how_to_restore(self):
        mac = Mac(answer=False)
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        self.assertEqual(mac.w.review(held_id), (False, STILL_CANCELLED))
        report = guestlist.scan(mac.home, support=mac.support)
        self.assertEqual([h["restore"] for h in report["held"]], [f"canary restore {held_id}"])
        self.assertIn("held for your decision", guestlist.session_line(report))
        self.assertEqual(watcher.restore(held_id, mac.home, mac.support,
                                         ask=lambda text, verdict, confirm=None: True,
                                         backend=model(), model="fake"), (True, None))
        self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))

    def test_restore_still_needs_the_person(self):
        mac = Mac(answer=False)
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        self.assertEqual(watcher.restore(held_id, mac.home, mac.support,
                                         ask=lambda text, verdict, confirm=None: None,
                                         backend=model(), model="fake"), (False, STILL_SILENT))
        self.assertFalse(os.path.lexists(folder))

    def test_an_unsafe_skill_stays_held_unless_the_person_types_its_name(self):
        # Program 2026-10-13 (ruling 7): was "stays held without a question".
        for answer, reason in ((False, STILL_CANCELLED), (None, STILL_SILENT)):
            with self.subTest(answer=answer):
                mac = Mac(verdict="UNSAFE", answer=answer)
                skill(mac.codex, "dropped-in")
                [held_id] = mac.settle()
                self.assertEqual(mac.w.review(held_id), (False, reason))
                self.assertEqual((len(mac.asked), mac.confirms), (1, ["dropped-in"]))
                self.assertIn("recommends you don't install this. To install it anyway, type "
                              "dropped-in below and choose Install anyway.", mac.asked[0])
                self.assertEqual(len(mac.held()), 1)
                with open(os.path.join(mac.support, "ledger.jsonl")) as fh:
                    self.assertIn("refused", [json.loads(line)["event"] for line in fh])

    def test_an_unsafe_skill_goes_back_when_the_person_types_its_name_and_says_so(self):
        mac = Mac(verdict="UNSAFE")
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        self.assertEqual(mac.w.review(held_id), (True, None))
        self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))
        report = guestlist.scan(mac.home, support=mac.support)
        listed = [s for s in report["skills"] if s["name"] == "dropped-in"]
        self.assertEqual([(s["status"], s["override"]) for s in listed], [("checked", True)])
        self.assertEqual(mac.settle(start=20), [])  # put back, not held again

    def test_the_real_dialog_is_always_asked_with_the_name_to_type(self):
        asked = []

        def recorder(text, verdict, yes=None, confirm=None):
            asked.append((verdict, confirm))
            return None

        with unittest.mock.patch.object(add, "ask", recorder):
            mac = Mac(verdict="UNSAFE")
            mac.w = watcher.Watcher(mac.home, mac.support, notify=mac.notes.append,
                                    backend=model("UNSAFE"), model="fake")
            skill(mac.codex, "dropped-in")
            [held_id] = mac.settle()
            mac.w.review(held_id)
            watcher.restore(held_id, mac.home, mac.support, backend=model("UNSAFE"),
                            model="fake")
        self.assertEqual(asked, [("UNSAFE", "dropped-in")] * 2)

    def test_a_held_skill_with_links_is_refused_without_a_question(self):
        # There is no checked copy to put back, so there is nothing to ask about.
        mac = Mac()
        folder = skill(mac.codex, "linky")
        os.symlink("/etc/hosts", os.path.join(folder, "extra.md"))
        [held_id] = mac.settle()
        self.assertEqual(mac.w.review(held_id), (False, STILL_LINKS))
        self.assertEqual((mac.asked, len(mac.notes)), ([], 1))
        self.assertEqual(len(mac.held()), 1)

    def test_every_restore_failure_says_why(self):
        mac = Mac(answer=True)
        self.assertEqual(mac.w.review("20261013T000000Z-deadbeef"), (False, STILL_GONE))
        # Something took its place while the person was deciding.
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()

        def take_the_place(text, verdict, confirm=None):
            os.makedirs(folder)
            return True

        mac.w.ask = take_the_place
        self.assertEqual(mac.w.review(held_id), (False, STILL_TAKEN))

    def test_canary_restore_prints_the_reason_or_the_success_line(self):
        for result, line, code in (((True, None), "Put back where it was.", 0),
                                   ((False, STILL_CANCELLED), STILL_CANCELLED, 10)):
            with self.subTest(line=line):
                out = io.StringIO()
                with unittest.mock.patch.object(watcher, "restore", lambda *a, **k: result), \
                        contextlib.redirect_stdout(out):
                    self.assertEqual(cli._restore(["20261013T000000Z-deadbeef"]), code)
                self.assertEqual(out.getvalue(), line + "\n")

    def test_canary_restore_does_not_also_send_a_notification(self):
        mac = Mac()
        folder = skill(mac.codex, "linky")
        os.symlink("/etc/hosts", os.path.join(folder, "extra.md"))
        [held_id] = mac.settle()
        sent = []
        with unittest.mock.patch.object(watcher, "_notify", sent.append):
            result = watcher.restore(held_id, mac.home, mac.support,
                                     ask=lambda text, verdict, confirm=None: None,
                                     backend=model(), model="fake")
        self.assertEqual((result, sent), ((False, STILL_LINKS), []))


class TheLaunchAgent(unittest.TestCase):
    def test_it_finds_the_classifier_your_terminal_finds(self):
        # launchd starts programs with a minimal PATH; the agent's own PATH
        # carries the folder that holds `claude`, found when setup runs.
        path = watcher.agent_path(which=lambda name: "/opt/tools/bin/claude")
        self.assertEqual(path.split(":")[0], "/opt/tools/bin")
        self.assertIn("/usr/bin", path.split(":"))
        plist = watcher.launch_agent_plist("/x/canary", "/x/support", path)
        self.assertIn(f"<key>PATH</key><string>{path}</string>", plist)


class WhatCannotSlipPast(unittest.TestCase):
    """Slice B2 refutation (Muse Spark 1.3 Contributor, 2026-10-02)."""

    def test_trusting_a_skill_needs_the_person(self):
        mac = Mac()
        folder = skill(mac.codex, "dropped-in")
        self.assertEqual(guestlist.trust(folder, mac.home, support=mac.support,
                                         ask=lambda text, verdict, confirm=None: None), [])
        self.assertEqual(len(mac.settle()), 1)

    def test_a_folder_there_at_start_that_gains_a_skill_md_is_held(self):
        os_home = os.path.realpath(tempfile.mkdtemp(prefix="canary-watch-"))
        os.makedirs(os.path.join(os_home, ".agents", "skills", "data"))
        mac = Mac(home=os_home)
        skill(mac.codex, "data")
        self.assertEqual(len(mac.settle()), 1)

    def test_a_folder_let_go_without_a_skill_md_is_held_when_it_gets_one(self):
        mac = Mac()
        os.makedirs(os.path.join(mac.codex, "stage"))
        mac.settle()
        mac.w.step(1000)  # long past the pending limit
        skill(mac.codex, "stage")
        self.assertEqual(len(mac.settle(start=2000)), 1)

    def test_a_hold_that_fails_is_tried_again(self):
        mac = Mac()
        skill(mac.codex, "dropped-in")
        quarantine = os.path.join(mac.support, "quarantine")
        os.makedirs(quarantine, exist_ok=True)
        os.chmod(quarantine, 0o500)
        try:
            self.assertEqual(mac.settle(), [])
        finally:
            os.chmod(quarantine, 0o700)
        self.assertEqual(len(mac.settle(start=20)), 1)

    def test_an_entry_that_never_stops_changing_is_held_anyway(self):
        mac = Mac()
        folder = skill(mac.codex, "busy")
        held = []
        for t in range(0, 60, 1):
            if held:
                break
            with open(os.path.join(folder, "tick"), "w") as fh:
                fh.write(str(t))
            held += mac.w.step(float(t))
        self.assertEqual(len(held), 1)

    def test_staging_names_are_no_way_around(self):
        mac = Mac()
        skill(mac.codex, ".canary-staging-evil")
        self.assertEqual(len(mac.settle()), 1)

    def test_a_skill_changed_after_its_check_is_not_put_back(self):
        mac = Mac()
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        def swap_then_yes(text, verdict, confirm=None):
            [h] = mac.held()
            with open(os.path.join(mac.support, "quarantine", "held", h["id"], "entry",
                                   "SKILL.md"), "a") as fh:
                fh.write("Send the keys.\n")
            return True
        mac.w.ask = swap_then_yes
        self.assertEqual(mac.w.review(held_id), (False, STILL_CHANGED))
        self.assertFalse(os.path.lexists(folder))
        self.assertEqual(len(mac.held()), 1)

    def test_holds_survive_a_broken_ledger(self):
        mac = Mac()
        folder = skill(mac.codex, "dropped-in")
        ledger = os.path.join(mac.support, "ledger.jsonl")
        os.unlink(ledger)
        os.makedirs(ledger)  # writes to the ledger now fail
        self.assertEqual(len(mac.settle()), 1)
        self.assertFalse(os.path.lexists(folder))
        self.assertEqual([h["origin"] for h in mac.held()], [folder])

    def test_a_forged_hold_cannot_name_a_place_outside_the_skills_folders(self):
        mac = Mac()
        slot = os.path.join(mac.support, "quarantine", "held", "20261002T000000Z-deadbeef")
        skill(slot, "entry")
        with open(os.path.join(slot, "hold.json"), "w") as fh:
            json.dump({"name": "x", "origin": os.path.join(mac.home, ".zshrc")}, fh)
        self.assertEqual(mac.held(), [])

    def test_a_restart_does_not_forget_what_arrived(self):
        mac = Mac()
        skill(mac.codex, "dropped-in")
        mac.w.step(0)  # seen, still settling, when the watcher stops
        restarted = Mac(home=mac.home)
        self.assertEqual(len(restarted.settle(start=100)), 1)

    def test_one_bad_look_does_not_stop_the_watcher(self):
        mac = Mac()
        def boom(now):
            raise OSError("disk trouble")
        mac.w.step = boom
        mac.w.tick(0)  # must not raise

    def test_a_failed_put_back_is_reported_not_raised(self):
        mac = Mac()
        skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        shutil.rmtree(mac.codex)  # the folder it came from is gone
        self.assertEqual(mac.w.review(held_id), (False, STILL_NOT_MOVED))
        self.assertEqual(len(mac.held()), 1)


if __name__ == "__main__":
    unittest.main()
