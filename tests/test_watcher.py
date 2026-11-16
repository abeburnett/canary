"""Behavioural tests for the watcher (docs/program-2026-09-30-front-door.md,
slice B2): a new, unchecked skill in a skills folder is held once it settles,
checked, and put back only when the person says so. The watcher deletes a
held copy only when the same content is installed and approved at its place,
or when the person says so with `canary drop`; each deletion is recorded
first (program 2026-11-15, quiet holds).

The tests drive `Watcher.step` with a made-up clock; they never start launchd
or kqueue.
"""

import errno
import itertools
import json
import os
import queue
import re
import shutil
import contextlib
import io
import subprocess
import tarfile
import tempfile
import unittest
import unittest.mock

from canary import add, cli, frontdoor, guestlist, replace, watcher
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
STILL_KEPT = "Still held: you chose not to delete it." + SUFFIX
STILL_NOT_DROPPED = "Still held: SkillCanary could not delete it." + SUFFIX


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
        # Program 2026-11-15, 2.6: the person answered, so the notice no longer counts it.
        self.assertIn(f"  dropped-in  from {folder}  held since {mac.held()[0]['at'][:10]}  "
                      "(you chose not to install it)\n"
                      f"    to check it again and install it: canary restore {held_id}",
                      guestlist.render_text(report))
        self.assertIsNone(guestlist.session_line(report))
        self.assertEqual(watcher.restore(held_id, mac.home, mac.support,
                                         ask=lambda text, verdict, confirm=None: True,
                                         backend=model(), model="fake"), (True, None))
        self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))

    def test_a_restored_skill_lists_as_restored(self):
        mac = Mac()
        skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        self.assertEqual(mac.w.review(held_id), (True, None))
        report = guestlist.scan(mac.home, support=mac.support)
        [item] = [s for s in report["skills"] if s["name"] == "dropped-in"]
        self.assertEqual(item["installed_from"], {"kind": "watcher"})
        self.assertRegex(guestlist.render_text(report), r"dropped-in .*restored")

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

    def test_a_folder_named_with_only_spaces_needs_the_fixed_phrase(self):
        # The folder's creator picks the name; a blank phrase must not let an
        # empty answer, or one click, approve.
        sent = []

        def fake_run(argv, **_):
            sent.append(argv)
            return subprocess.CompletedProcess(argv, 0, "Install anyway\n", "")

        with unittest.mock.patch.object(add.sys, "platform", "darwin"), \
                unittest.mock.patch.object(add.shutil, "which", lambda _: "/usr/bin/osascript"), \
                unittest.mock.patch.object(add.subprocess, "run", fake_run):
            mac = Mac(verdict="UNSAFE")
            mac.w = watcher.Watcher(mac.home, mac.support, notify=mac.notes.append,
                                    backend=model("UNSAFE"), model="fake")
            folder = skill(mac.codex, " ")
            [held_id] = mac.settle()
            self.assertEqual(mac.w.review(held_id), (False, STILL_CANCELLED))
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0][sent[0].index("--") + 1].endswith(
            "To install it anyway, type install anyway below and choose Install anyway."))
        self.assertFalse(os.path.lexists(folder))
        self.assertEqual(len(mac.held()), 1)

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
        # Program 2026-11-15, 1.3: something took its place before the review,
        # so there is nothing to ask about.
        skill(mac.codex, "taken")
        [taken_id] = mac.settle(start=20)
        skill(mac.codex, "taken")
        mac.w.ask = mac.ask
        self.assertEqual(mac.w.review(taken_id), (False, STILL_TAKEN))
        self.assertEqual(mac.asked, [])

    def test_canary_restore_prints_the_reason_or_the_success_line(self):
        # Program 2026-10-17, test 23: the line restore returns is printed.
        switched = "Put back where it was; the copy that was there is set aside as X."
        for result, line, code in (((True, None), "Put back where it was.", 0),
                                   ((True, switched), switched, 0),
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


DROP_NOTE = ("SkillCanary deleted 1 held copy that matches a skill you already installed: "
             "dropped-in. canary list shows what is still held.")
TWIN_NOTE = ("SkillCanary deleted a second held copy of dropped-in: it is the same as the copy "
             "it is already holding. canary list shows what is still held.")


def drain(w):
    """Handle whatever is on a watcher's review queue, as its loop would."""
    while True:
        try:
            item = w.reviews.get_nowait()
        except queue.Empty:
            return
        w.handle(item)


def ledger(mac, event):
    with open(os.path.join(mac.support, "ledger.jsonl")) as fh:
        return [e for e in map(json.loads, fh) if e.get("event") == event]


def ordered_ids():
    """Holds made within one second sort in the order they were made."""
    counter = itertools.count()
    return unittest.mock.patch.object(watcher.secrets, "token_hex",
                                      lambda n: f"{next(counter):08x}")


def held_with_its_place_taken(git=False):
    """A held skill whose place now holds an approved copy with the same
    SKILL.md, as `canary add` leaves one; `git` adds a file under .git."""
    mac = Mac(answer=None)
    skill(mac.codex, "dropped-in")
    [held_id] = mac.settle()
    folder = skill(mac.codex, "dropped-in")
    if git:
        os.makedirs(os.path.join(folder, ".git"))
        with open(os.path.join(folder, ".git", "HEAD"), "w") as fh:
            fh.write("ref: refs/heads/main\n")
    guestlist.record_install(mac.home, [folder], "dropped-in", "LIKELY_SAFE", support=mac.support)
    return mac, held_id, folder


class AHoldIsAskedAboutOnce(unittest.TestCase):
    """Program 2026-11-15 (quiet holds), slice 1, test 1."""

    def test_a_restart_asks_nothing_and_the_hold_still_shows(self):
        mac = Mac(answer=None)
        folder = skill(mac.codex, "dropped-in")
        [held_id] = mac.settle()
        drain(mac.w)
        self.assertEqual(len(mac.asked), 1)
        restarted = Mac(answer=None, home=mac.home)
        restarted.w.begin()
        drain(restarted.w)
        self.assertEqual(restarted.asked, [])
        report = guestlist.scan(mac.home, support=mac.support)
        day = mac.held()[0]["at"][:10]
        self.assertIn("Held by SkillCanary (arrived without its check):\n"
                      f"  dropped-in  from {folder}  held since {day}\n"
                      f"    to check it again and install it: canary restore {held_id}\n"
                      f"    to delete the held copy: canary drop {held_id}",
                      guestlist.render_text(report))
        self.assertIn("1 held for your decision (dropped-in)", guestlist.session_line(report))


class AutomaticDropsDeleteExactCopiesOnly(unittest.TestCase):
    """Program 2026-11-15 (quiet holds), slice 1, test 2."""

    def test_a_an_approved_exact_copy_at_its_place_drops_the_hold_at_start(self):
        mac, held_id, folder = held_with_its_place_taken()
        fingerprint = guestlist.digest(os.path.join(watcher.held_dir(mac.support), held_id,
                                                    "entry"))
        restarted = Mac(answer=None, home=mac.home)
        restarted.w.begin()
        self.assertEqual(restarted.held(), [])
        self.assertFalse(os.path.lexists(os.path.join(watcher.held_dir(mac.support), held_id)))
        [dropped] = ledger(mac, "dropped")
        self.assertEqual({k: dropped.get(k) for k in ("id", "name", "origin", "digest", "how",
                                                      "same_as")},
                         {"id": held_id, "name": "dropped-in", "origin": folder,
                          "digest": fingerprint, "how": "same as installed",
                          "same_as": folder})
        self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))
        self.assertEqual((restarted.asked, restarted.notes), ([], [DROP_NOTE]))

    def test_b_a_copy_that_differs_only_under_git_is_kept(self):
        # Pin (counterfactual b): the fingerprint leaves .git out, the exact copy does not.
        mac, held_id, folder = held_with_its_place_taken(git=True)
        entry = os.path.join(watcher.held_dir(mac.support), held_id, "entry")
        self.assertEqual(guestlist.digest(entry), guestlist.digest(folder))
        restarted = Mac(answer=None, home=mac.home)
        restarted.w.begin()
        self.assertEqual([h["id"] for h in restarted.held()], [held_id])
        self.assertEqual((ledger(mac, "dropped"), restarted.asked, restarted.notes), ([], [], []))
        report = guestlist.scan(mac.home, support=mac.support)
        [listed] = report["held"]
        self.assertEqual((listed["taken"], listed["drop"]), (True, f"canary drop {held_id}"))
        day = restarted.held()[0]["at"][:10]
        text = guestlist.render_text(report)
        self.assertIn(f"  dropped-in  from {folder}  held since {day}  (its place is taken)\n"
                      f"    to delete the held copy: canary drop {held_id}", text)
        self.assertNotIn(f"canary restore {held_id}", text)

    def two_holds_from_one_place(self, second_body):
        mac = Mac(answer=False)
        with ordered_ids():
            skill(mac.codex, "dropped-in")
            [first] = mac.settle()
            skill(mac.codex, "dropped-in", second_body)
            [second] = mac.settle(start=20)
        drain(mac.w)
        return mac, first, second

    def test_c_a_second_exact_copy_from_one_place_is_dropped_without_a_question(self):
        mac, first, second = self.two_holds_from_one_place("Help.\n")
        self.assertEqual([h["id"] for h in mac.held()], [first])
        self.assertEqual(len(mac.asked), 1)
        [dropped] = ledger(mac, "dropped")
        self.assertEqual((dropped["id"], dropped["how"]), (second, "same as waiting hold"))
        self.assertEqual(mac.notes, [TWIN_NOTE])

    def test_c_a_second_hold_with_different_content_is_kept(self):
        # Pin (counterfactual d): dropping either would delete the only copy of its content.
        mac, first, second = self.two_holds_from_one_place("Other help.\n")
        self.assertEqual([h["id"] for h in mac.held()], [first, second])
        self.assertEqual(len(mac.asked), 2)
        self.assertEqual(ledger(mac, "dropped"), [])

    def test_d_a_failed_record_drops_nothing(self):
        # Pin (counterfactual e). Seam: guestlist.record_events.
        mac, held_id, folder = held_with_its_place_taken()
        restarted = Mac(answer=None, home=mac.home)
        with unittest.mock.patch.object(guestlist, "record_events",
                                        side_effect=OSError(errno.EIO, "ledger")):
            restarted.w.begin()
        self.assertEqual([h["id"] for h in restarted.held()], [held_id])
        self.assertTrue(os.path.isdir(os.path.join(watcher.held_dir(mac.support), held_id,
                                                   "entry")))
        self.assertEqual(restarted.notes, [])

    def test_e_a_drop_that_stops_after_its_rename_is_finished_by_the_next_start(self):
        # Seam: watcher.shutil.rmtree, during the drop.
        mac, held_id, folder = held_with_its_place_taken()
        slot = os.path.join(watcher.held_dir(mac.support), held_id)
        restarted = Mac(answer=None, home=mac.home)
        with unittest.mock.patch.object(watcher.shutil, "rmtree"):
            restarted.w.begin()
        self.assertEqual(sorted(os.listdir(slot)), ["dropped", "hold.json"])
        self.assertEqual(restarted.held(), [])
        Mac(answer=None, home=mac.home).w.begin()
        self.assertFalse(os.path.lexists(slot))
        self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))


class CanaryDropDeletesOnlyOnAYes(unittest.TestCase):
    """Program 2026-11-15 (quiet holds), slice 1, test 3. Seam: the injected
    `ask`, as `watcher.restore` has."""

    def setUp(self):
        self.mac = Mac(answer=False)
        skill(self.mac.codex, "dropped-in")
        [self.held_id] = self.mac.settle()
        self.slot = os.path.join(watcher.held_dir(self.mac.support), self.held_id)
        self.asked = []

    def drop(self, answer):
        def ask(text, verdict):
            self.asked.append((text, verdict))
            return answer
        return watcher.drop(self.held_id, self.mac.home, self.mac.support, ask=ask)

    def test_no_keeps_the_hold(self):
        # Pin (counterfactual g).
        self.assertEqual(self.drop(False), (False, STILL_KEPT))
        self.assertEqual([h["id"] for h in self.mac.held()], [self.held_id])
        [(text, verdict)] = self.asked
        self.assertEqual(verdict, "NEEDS_REVIEW")
        day = self.mac.held()[0]["at"][:10]
        for line in ("Delete the held copy of this skill?", "Folder name: dropped-in",
                     f"Arrived in ~/.agents/skills on {day}.", "Its place is free.",
                     "Cancel keeps it held."):
            self.assertIn(line + "\n", text)
        self.assertIn("This cannot be undone", text)

    def test_a_ledger_fault_removes_nothing(self):
        # Pin (counterfactual e). Seam: the ledger path made a directory.
        path = os.path.join(self.mac.support, "ledger.jsonl")
        os.unlink(path)
        os.makedirs(path)
        with self.assertRaises(OSError):
            self.drop(True)
        self.assertEqual([h["id"] for h in self.mac.held()], [self.held_id])
        self.assertTrue(os.path.isdir(os.path.join(self.slot, "entry")))

    def test_yes_deletes_the_held_copy_and_records_it(self):
        self.assertEqual(self.drop(True), (True, "Deleted the held copy of dropped-in."))
        self.assertFalse(os.path.lexists(self.slot))
        [dropped] = ledger(self.mac, "dropped")
        self.assertEqual((dropped["id"], dropped["how"]), (self.held_id, "person"))
        self.assertEqual(guestlist.scan(self.mac.home, support=self.mac.support)["held"], [])
        with self.assertRaises(ValueError) as caught:
            self.drop(True)
        self.assertEqual(str(caught.exception), replace.NOT_KEEPING)
        self.assertEqual(len(self.asked), 1)

    def test_canary_drop_prints_the_line_and_exits_with_its_code(self):
        for result, printed, warned, code in (
                ((True, "Deleted the held copy of x."), "Deleted the held copy of x.\n", "", 0),
                ((False, STILL_KEPT), STILL_KEPT + "\n", "", 10),
                (ValueError("no such hold"), "", "canary: no such hold\n", 2),
                (OSError(errno.EISDIR, "Is a directory"), "",
                 "canary: Is a directory; it stays held.\n", 1)):
            with self.subTest(code=code):
                def fake(*args, **kwargs):
                    if isinstance(result, Exception):
                        raise result
                    return result
                out, err = io.StringIO(), io.StringIO()
                with unittest.mock.patch.object(watcher, "drop", fake), \
                        contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(cli.main(["drop", self.held_id]), code)
                self.assertEqual((out.getvalue(), err.getvalue()), (printed, warned))


COVERING = ("Your answer covers every copy with exactly the same content that arrives in your "
            "skills folders, now or later: SkillCanary will not ask about it again.")
PUT_BACK_NOTE = ("SkillCanary put dropped-in back in {folder}: it has the same content as a skill "
                 "you chose to install.")
REFUSED_NOTE = ("SkillCanary is holding dropped-in, which arrived in {folder}: it has the same "
                "content as a skill you chose not to install. canary list shows where it is.")
ASKED_NOTE = ("SkillCanary is holding dropped-in, which arrived in {folder}: it has the same "
              "content as a skill it already asked you about. canary list shows where it is.")


def three_roots(mac):
    """The three user skills folders, the Codex home's own last. It must be
    inside the test's home: CODEX_HOME could point anywhere."""
    [third] = [r for r in mac.w.roots if r not in (mac.claude, mac.codex)]
    assert third.startswith(mac.home + os.sep), third
    return [mac.claude, mac.codex, third]


class OneAnswerCoversEveryCopy(unittest.TestCase):
    """Program 2026-11-15 (quiet holds), slice 2, test 1. No seam."""

    def test_one_question_puts_every_copy_back(self):
        mac = Mac(verdict="UNSAFE", answer=True)
        roots = three_roots(mac)
        folders = [skill(root, "dropped-in") for root in roots]
        with ordered_ids():
            self.assertEqual(len(mac.settle()), 3)
        drain(mac.w)
        self.assertEqual(mac.confirms, ["dropped-in"])
        self.assertIn("Install puts it back where it was. Cancel keeps it held and deletes "
                      "nothing.\n" + COVERING + "\n", mac.asked[0])
        self.assertEqual(mac.held(), [])
        self.assertEqual(mac.notes, [PUT_BACK_NOTE.format(folder=watcher._short(r, mac.home))
                                     for r in roots[1:]])
        text = guestlist.render_text(guestlist.scan(mac.home, support=mac.support))
        for folder in folders:
            self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))
            self.assertRegex(text, rf"dropped-in +installed anyway +{re.escape(folder)}  "
                                   "from restored")

    def test_nobody_answering_is_asked_once(self):
        # Counterfactual p: without Watcher.asked, each copy is asked about.
        mac = Mac(verdict="UNSAFE", answer=None)
        roots = three_roots(mac)
        for root in roots:
            skill(root, "dropped-in")
        with ordered_ids():
            self.assertEqual(len(mac.settle()), 3)
        drain(mac.w)
        self.assertEqual(len(mac.asked), 1)
        self.assertEqual(len(mac.held()), 3)
        self.assertEqual(mac.notes, [ASKED_NOTE.format(folder="~/.agents/skills")])


class ANoIsRemembered(unittest.TestCase):
    """Program 2026-11-15 (quiet holds), slice 2, test 2. No seam. The same
    content arrives again after a restart, so `Watcher.asked` cannot be what
    withholds the question."""

    def setUp(self):
        self.mac = Mac(answer=False)
        with ordered_ids():
            self.first_folder = skill(self.mac.codex, "dropped-in")
            [self.first] = self.mac.settle()
            drain(self.mac.w)
            self.later = Mac(answer=False, home=self.mac.home)
            self.second_folder = skill(self.mac.claude, "dropped-in")
            [self.second] = self.later.settle(start=20)
        drain(self.later.w)

    def test_no_second_question_and_it_stays_held(self):
        # Counterfactual m.
        self.assertEqual((len(self.mac.asked), self.later.asked), (1, []))
        self.assertEqual([h["id"] for h in self.later.held()], [self.first, self.second])
        self.assertEqual(self.later.notes, [REFUSED_NOTE.format(folder="~/.claude/skills")])
        self.assertEqual([(e.get("id"), e.get("replay")) for e in ledger(self.mac, "declined")],
                         [(self.first, None), (self.second, True)])

    def test_canary_list_says_the_person_chose_not_to_install_it(self):
        report = guestlist.scan(self.mac.home, support=self.mac.support)
        self.assertEqual([h["refused"] for h in report["held"]], [True, True])
        text = guestlist.render_text(report)
        days = {h["id"]: h["at"][:10] for h in self.later.held()}
        for held_id, folder in ((self.first, self.first_folder),
                                (self.second, self.second_folder)):
            self.assertIn(f"  dropped-in  from {folder}  held since {days[held_id]}  "
                          "(you chose not to install it)\n"
                          f"    to check it again and install it: canary restore {held_id}", text)

    def test_the_session_notice_counts_neither_hold(self):
        # Counterfactual o.
        report = guestlist.scan(self.mac.home, support=self.mac.support)
        self.assertIsNone(guestlist.session_line(report))

    def test_canary_restore_asks_again(self):
        # Pin (counterfactual n): the remembered no is not in Watcher.review.
        asked = []
        result = watcher.restore(self.second, self.mac.home, self.mac.support,
                                 ask=lambda text, verdict, confirm=None: asked.append(text),
                                 backend=model(), model="fake")
        self.assertEqual((result, len(asked)), ((False, STILL_SILENT), 1))


class AYesAfterANoEndsIt(unittest.TestCase):
    """Program 2026-11-15 (quiet holds), slice 2, the pre-merge review's
    fold (2026-11-16). No seam. The watcher marks a hold with a replayed no
    from a ledger it read earlier, so the mark can land after a newer yes.
    The events are written directly, in that order; no threads race."""

    def test_a_replayed_no_after_a_yes_does_not_bring_the_no_back(self):
        mac = Mac(answer=None)
        folder = skill(mac.codex, "dropped-in")
        fingerprint = guestlist.digest(folder)
        at = guestlist._now()
        guestlist.record_events(mac.support, [
            {"at": at, "event": "declined", "name": "dropped-in", "id": "first-hold",
             "digest": fingerprint},
            {"at": at, "event": "approved", "how": "canary add", "name": "dropped-in",
             "skill": folder, "digest": fingerprint},
            {"at": at, "event": "declined", "name": "dropped-in", "id": "second-hold",
             "digest": fingerprint, "replay": True}])
        self.assertEqual(mac.settle(), [])
        later = Mac(answer=None, home=mac.home)
        skill(mac.claude, "dropped-in")
        self.assertEqual(len(later.settle(start=20)), 1)
        drain(later.w)
        # The yes ended the no, so the new copy is asked about.
        self.assertEqual(len(later.asked), 1)


class ChangedContentAndOlderApprovalsAreAskedAbout(unittest.TestCase):
    """Program 2026-11-15 (quiet holds), slice 2, test 3. Every case is a pin
    (counterfactuals i, j, k, l). The later copy arrives after a restart, so
    `Watcher.asked` cannot be what asks or withholds."""

    def covering_yes(self):
        mac = Mac(answer=True)
        folder = skill(mac.codex, "dropped-in")
        mac.settle()
        drain(mac.w)
        self.assertEqual(len(mac.asked), 1)
        self.assertTrue(os.path.isfile(os.path.join(folder, "SKILL.md")))
        return mac, folder

    def arrives_again(self, mac, git=False):
        """The same SKILL.md arrives in ~/.claude/skills; the watcher that
        sees it asks, with no answer. Returns that watcher's Mac."""
        later = Mac(answer=None, home=mac.home)
        copy = skill(mac.claude, "dropped-in")
        if git:
            os.makedirs(os.path.join(copy, ".git"))
            with open(os.path.join(copy, ".git", "HEAD"), "w") as fh:
                fh.write("ref: refs/heads/main\n")
        self.assertEqual(len(later.settle(start=20)), 1)
        drain(later.w)
        return later

    def test_j_a_copy_that_differs_only_under_git_is_asked_about(self):
        mac, folder = self.covering_yes()
        later = self.arrives_again(mac, git=True)
        self.assertEqual((len(later.asked), len(later.held())), (1, 1))
        copy = os.path.join(watcher.held_dir(mac.support), later.held()[0]["id"], "entry")
        self.assertEqual(guestlist.digest(copy), guestlist.digest(folder))

    def test_i_content_approved_without_covers_is_asked_about(self):
        mac = Mac(answer=None)
        folder = skill(mac.codex, "dropped-in")
        # As canary add records it: the approval comes before the files are seen.
        guestlist.record_install(mac.home, [folder], "dropped-in", "LIKELY_SAFE",
                                 support=mac.support)
        self.assertEqual(mac.settle(), [])
        later = self.arrives_again(mac)
        self.assertEqual((len(later.asked), len(later.held())), (1, 1))

    def test_k_after_the_approved_copy_is_removed_the_same_content_is_asked_about(self):
        mac, folder = self.covering_yes()
        shutil.rmtree(folder)
        later = self.arrives_again(mac)
        self.assertEqual((len(later.asked), len(later.held())), (1, 1))

    def test_l_after_an_approval_without_covers_replaces_it_the_same_content_is_asked_about(self):
        mac, folder = self.covering_yes()
        guestlist.record_install(mac.home, [folder], "dropped-in", "LIKELY_SAFE",
                                 support=mac.support)
        later = self.arrives_again(mac)
        self.assertEqual((len(later.asked), len(later.held())), (1, 1))


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
