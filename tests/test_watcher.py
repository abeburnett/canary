"""Behavioural tests for the watcher (docs/program-2026-09-30-front-door.md,
slice B2): a new, unchecked skill in a skills folder is held once it settles,
checked, and put back only when the person says so. Nothing is deleted.

The tests drive `Watcher.step` with a made-up clock; they never start launchd
or kqueue.
"""

import os
import shutil
import tarfile
import tempfile
import unittest

from canary import add, frontdoor, guestlist, watcher
try:
    from test_add import FakeGitHub, URL, SKILL, Approver, model, tarball
    import test_install
except ImportError:  # run as tests.test_watcher
    from tests.test_add import FakeGitHub, URL, SKILL, Approver, model, tarball
    from tests import test_install


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
        self.asked, self.notes, self.answer = [], [], answer
        self.w = watcher.Watcher(self.home, self.support, ask=self.ask, notify=self.notes.append,
                                 backend=model(verdict), model="fake")

    def ask(self, text, verdict):
        self.asked.append(text)
        return self.answer

    def settle(self, start=0.0):
        """Look, then look again after the settle wait; the ids held."""
        return self.w.step(start) + self.w.step(start + 5) + self.w.step(start + 10)

    def held(self):
        return watcher.held(self.support)


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
        self.assertTrue(mac.w.review(held_id))
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
        self.assertTrue(mac.w.review(held_id))
        self.assertEqual(os.path.realpath(os.path.join(mac.claude, "ext")), outside)
        self.assertEqual(mac.settle(start=20), [])

    def test_cancel_keeps_it_held_and_canary_list_says_how_to_restore(self):
        mac = Mac(answer=False)
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        self.assertFalse(mac.w.review(held_id))
        report = guestlist.scan(mac.home, support=mac.support)
        self.assertEqual([h["restore"] for h in report["held"]], [f"canary restore {held_id}"])
        self.assertIn("held for your decision", guestlist.session_line(report))
        self.assertTrue(watcher.restore(held_id, mac.home, mac.support,
                                        ask=lambda text, verdict: True, backend=model(),
                                        model="fake"))
        self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))

    def test_restore_still_needs_the_person(self):
        mac = Mac(answer=False)
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        self.assertFalse(watcher.restore(held_id, mac.home, mac.support,
                                         ask=lambda text, verdict: None, backend=model(),
                                         model="fake"))
        self.assertFalse(os.path.lexists(folder))

    def test_an_unsafe_skill_stays_held_without_a_question(self):
        mac = Mac(verdict="UNSAFE")
        skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        self.assertFalse(mac.w.review(held_id))
        self.assertEqual((mac.asked, len(mac.notes)), ([], 1))
        self.assertEqual(len(mac.held()), 1)


if __name__ == "__main__":
    unittest.main()
