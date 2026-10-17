"""Behavioural tests for `--replace` and for `canary restore` of a replaced
group (docs/program-2026-10-17-replace.md, section 6). Each test's name starts
with its number in that section and its docstring names the seam it uses to
inject a fault. Approval, the classifier and installers are fakes; nothing
touches the real home folder or the network.
"""

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
import unittest.mock

from canary import add, cli, guestlist, install, setup, watcher
try:
    import test_add
    import test_install
    from test_add import Approver, model
except ImportError:  # run as tests.test_replace
    from tests import test_add, test_install
    from tests.test_add import Approver, model

V1 = "---\nname: notes\ndescription: Formats meeting notes.\n---\n\nTurn notes into bullets.\n"
V2 = V1 + "\nAlso number the bullets.\n"
V3 = V1 + "\nAnd date them.\n"
HOLD_ID = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}")
CHANGED = ("What is installed as notes changed while you were deciding; nothing was changed. "
           "Run this again.")
BACK = "The earlier copy is back in place."
FIRST = "Another install got there first; nothing was installed."
NOT_MOVED = "Still set aside: SkillCanary could not move it back. canary list shows where it is."
NOTHING_LEFT = "Still set aside: nothing of it is left in SkillCanary's store."


def R():
    """canary.replace. Before the program it does not exist, and this raises
    AttributeError: the missing interface."""
    import canary
    try:
        import canary.replace  # noqa: F401
    except ImportError:
        pass
    return canary.replace


def yes(text, verdict, confirm=None):
    return True


def write_skill(folder, text=V1):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "SKILL.md"), "w") as fh:
        fh.write(text)
    return folder


class Home(test_add.Env):
    """test_add.Env with local sources, both hosts, and readers for the store,
    the ledger and the lock file."""

    def __init__(self):
        super().__init__()
        self.claude = os.path.join(self.home, ".claude", "skills", "notes")
        self.codex = os.path.join(self.home, ".agents", "skills", "notes")
        self.dests = [self.claude, self.codex]
        self.store = os.path.join(self.support, "quarantine", "replaced")

    def source(self, text):
        return write_skill(os.path.join(tempfile.mkdtemp(prefix="canary-src-"), "notes"), text)

    def run(self, text=V2, answer=True, replace=True, hosts=None, verdict="SAFE", approve=None):
        approve = approve or Approver(answer)
        kwargs = {"replace": True} if replace else {}
        out = add.add(self.source(text), home=self.home, support_dir=self.support,
                      approve=approve, backend=model(verdict), model="fake", hosts=hosts,
                      **kwargs)
        return out, approve

    def untracked(self, *folders, text=V1):
        for f in folders or self.dests:
            write_skill(f, text)

    def read(self, folder):
        with open(os.path.join(folder, "SKILL.md")) as fh:
            return fh.read()

    def ids(self):
        try:
            return sorted(d for d in os.listdir(self.store) if HOLD_ID.fullmatch(d))
        except OSError:
            return []

    def group(self, gid):
        with open(os.path.join(self.store, gid, "replaced.json")) as fh:
            return json.load(fh)

    def ledger(self):
        try:
            with open(os.path.join(self.support, "ledger.jsonl")) as fh:
                return [json.loads(line) for line in fh]
        except OSError:
            return []

    def lock_bytes(self):
        try:
            with open(os.path.join(self.home, ".agents", ".canary-lock.json"), "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def short(self, path):
        return "~" + path[len(self.home):]

    def restore(self, gid, answer=True, verdict="SAFE", ask=None):
        return watcher.restore(gid, self.home, self.support,
                               ask=ask or (lambda text, verdict, confirm=None: answer),
                               backend=model(verdict), model="fake")

    def watcher(self):
        return watcher.Watcher(self.home, self.support, ask=lambda *a, **k: None,
                               notify=lambda text: None, backend=model(), model="fake")

    def replaced_group(self):
        """Install V1 through canary add, then replace it with V2: the group id."""
        self.run(V1, replace=False)
        out, _ = self.run(V2)
        assert out["outcome"] == "installed", out
        [gid] = self.ids()
        return gid


def install_replace(mac, argv, spec=None, answer=True, verdict="SAFE"):
    """test_install.Mac.install with replace=True."""
    patch = mac.environment(FAKE_SPEC=json.dumps(spec or {"skills": []}))
    try:
        return install.install(argv, home=mac.home, cwd=mac.project, support_dir=mac.support,
                               approve=mac.approver(answer), backend=model(verdict),
                               model="fake", replace=True)
    finally:
        patch.stop()


def runs(mac):
    return mac.runs() if os.path.exists(mac.log) else []


def staging_fails_once(on_failure=None):
    """Seam for test 9: a wrapper for the global os.rename that raises OSError
    exactly once, on the second rename of a staging folder, and passes every
    other call through."""
    real = os.rename
    count = [0]

    def rename(src, dst, *a, **k):
        if os.path.basename(src).startswith(".canary-staging-"):
            count[0] += 1
            if count[0] == 2:
                if on_failure:
                    on_failure()
                raise OSError(28, "No space left on device")
        return real(src, dst, *a, **k)
    return rename


class AReplaceSetsTheOldCopyAside(unittest.TestCase):
    def test_02_a_yes_replaces_both_copies_and_keeps_the_old_ones(self):
        """No seam."""
        h = Home()
        h.run(V1, replace=False)
        old = h.lock()["skills"]["notes"]
        old_digest = guestlist.digest(h.claude)
        before = len(h.ledger())
        out, approve = h.run(V2)
        self.assertEqual(out["outcome"], "installed")
        self.assertEqual([h.read(d) for d in h.dests], [V2, V2])
        [gid] = h.ids()
        gdir = os.path.join(h.store, gid)
        self.assertEqual(sorted(os.listdir(gdir)), ["entry-0", "entry-1", "replaced.json"])
        self.assertEqual([h.read(os.path.join(gdir, e)) for e in ("entry-0", "entry-1")],
                         [V1, V1])
        rec = h.group(gid)
        self.assertEqual((rec["schema"], rec["id"], rec["name"], rec["how"]),
                         ("canary.replaced/1", gid, "notes", "canary add"))
        self.assertIsInstance(rec["at"], str)
        self.assertEqual(rec["members"], [
            {"entry": "entry-0", "origin": h.claude, "kind": "folder"},
            {"entry": "entry-1", "origin": h.codex, "kind": "folder"}])
        self.assertEqual(sorted(rec["states"]), sorted(h.dests))
        for origin in h.dests:
            state = rec["states"][origin]
            self.assertEqual((state["path"], state["status"], state["digest"], state["approved"],
                              state["override"], state["origin"]),
                             (os.path.realpath(origin), "checked", old_digest, old_digest, False,
                              {"kind": "local"}))
        self.assertEqual(rec["records"], {"notes": old})
        skills = h.lock()["skills"]
        self.assertEqual(sorted(skills), ["notes"])
        self.assertEqual(skills["notes"]["replaced"], gid)
        self.assertNotEqual(skills["notes"]["package_digest"], old["package_digest"])
        events = h.ledger()[before:]
        self.assertEqual([e["event"] for e in events],
                         ["checked", "approved", "approved", "replaced", "replaced"])
        new_digest = guestlist.digest(h.claude)
        self.assertEqual([e["digest"] for e in events[1:3]], [new_digest, new_digest])
        self.assertEqual([(e["id"], e["name"], e["skill"], e["kind"], e["how"]) for e in events[3:]],
                         [(gid, "notes", d, "folder", "canary add") for d in h.dests])
        paths = ["~/.claude/skills/notes", "~/.agents/skills/notes"]
        self.assertEqual(out["replaced"], {"id": gid, "paths": paths})
        self.assertIn(f"  Replaced: ~/.claude/skills/notes and ~/.agents/skills/notes (set aside "
                      f"as {gid}; canary restore {gid} puts it back)", add.render_text(out))

    def test_03_a_folder_and_its_link_are_set_aside_and_restored_as_a_unit(self):
        """HireReach: an untracked folder plus a relative link, as the skills
        CLI writes them, with ledger state yours. No seam."""
        h = Home()
        h.untracked(h.codex)
        os.makedirs(os.path.dirname(h.claude))
        os.symlink(os.path.join("..", "..", ".agents", "skills", "notes"), h.claude)
        guestlist.scan(h.home, support=h.support, first_look=True)
        out, _ = h.run(V2)
        self.assertEqual(out["outcome"], "installed")
        for d in h.dests:
            self.assertFalse(os.path.islink(d))
            self.assertEqual(h.read(d), V2)
        [gid] = h.ids()
        rec = h.group(gid)
        self.assertEqual(rec["members"], [
            {"entry": "entry-0", "origin": h.claude, "kind": "link"},
            {"entry": "entry-1", "origin": h.codex, "kind": "folder"}])
        self.assertEqual((rec["records"], list(rec["states"])), ({}, [h.codex]))
        self.assertEqual(rec["states"][h.codex]["status"], "yours")
        back, line = h.restore(gid)
        self.assertTrue(back)
        [g2] = h.ids()
        self.assertEqual(line, f"Put back where it was; the copy that was there is set aside as {g2}.")
        self.assertTrue(os.path.islink(h.claude))
        self.assertEqual(os.path.realpath(h.claude), os.path.realpath(h.codex))
        self.assertEqual(h.read(h.codex), V1)

    def test_25_with_nothing_there_it_is_a_fresh_install(self):
        """No seam."""
        h = Home()
        seen = []
        out, _ = h.run(V2, approve=lambda summary: seen.append(add.dialog_text(summary)) or True)
        self.assertEqual(out["outcome"], "installed")
        self.assertNotIn("replaced", out)
        self.assertEqual(h.ids(), [])
        self.assertNotIn("replaced", h.lock()["skills"]["notes"])
        self.assertNotIn("This replaces", seen[0])

    def test_26_an_old_copy_at_one_host_only_is_one_member(self):
        """No seam."""
        h = Home()
        h.run(V1, replace=False, hosts=["claude"])
        seen = []
        out, _ = h.run(V2, approve=lambda summary: seen.append(add.dialog_text(summary)) or True)
        self.assertEqual(out["outcome"], "installed")
        self.assertEqual([h.read(d) for d in h.dests], [V2, V2])
        [gid] = h.ids()
        self.assertEqual(h.group(gid)["members"],
                         [{"entry": "entry-0", "origin": h.claude, "kind": "folder"}])
        self.assertIn("This replaces the installed notes at ~/.claude/skills/notes (recorded ",
                      seen[0])


class NothingMovesUntilThePersonSaysYes(unittest.TestCase):
    def test_04_a_no_or_an_unsafe_refusal_leaves_everything(self):
        """No seam."""
        for answer, verdict, outcome in ((False, "SAFE", "declined"),
                                         (None, "UNSAFE", "refused")):
            with self.subTest(outcome=outcome):
                h = Home()
                h.run(V1, replace=False)
                lock, before = h.lock_bytes(), len(h.ledger())
                out, approve = h.run(V2, answer=answer, verdict=verdict)
                self.assertEqual(out["outcome"], outcome)
                self.assertEqual(len(approve.seen), 1)
                self.assertEqual(h.ids(), [])
                self.assertNotIn("approved", [e["event"] for e in h.ledger()[before:]])
                self.assertEqual(h.lock_bytes(), lock)
                self.assertEqual([h.read(d) for d in h.dests], [V1, V1])

    def test_05_the_dialog_says_what_it_replaces(self):
        """No seam."""
        h = Home()
        h.untracked()
        h.write_lock({"notes": {"name": "notes", "installed": h.dests,
                                "installed_at": "2026-10-05T10:00:00Z"}})
        seen = []
        h.run(V2, approve=lambda summary: seen.append(add.dialog_text(summary)) or False)
        block = ("This replaces the installed notes at ~/.claude/skills/notes and "
                 "~/.agents/skills/notes (recorded 2026-10-05).\n"
                 "The copy there now is set aside, not deleted; canary restore puts it back.")
        self.assertIn("Into: Claude Code, Codex\n\n" + block, seen[0])
        h = Home()
        h.untracked(h.claude)
        seen = []
        h.run(V2, approve=lambda summary: seen.append(add.dialog_text(summary)) or False)
        self.assertIn("This replaces the installed notes at ~/.claude/skills/notes (not installed "
                      "by SkillCanary).\nThe copy there now is set aside", seen[0])

    def test_05_the_install_dialog_says_what_it_replaces(self):
        """No seam."""
        mac = test_install.Mac()
        self.assertEqual(mac.install(test_install.ADD, spec=test_install.ONE)["outcome"],
                         "installed")
        lock = mac.lock()
        lock["skills"]["helper"]["installed_at"] = "2026-10-05T10:00:00Z"
        mac.write_lock(lock["skills"])
        out = install_replace(mac, test_install.ADD, spec=test_install.ONE, answer=False)
        self.assertEqual(out["outcome"], "declined")
        summary = mac.asked[-1]["summary"]
        text = install.dialog_text(test_install.ADD, summary["items"], summary["verdict"])
        self.assertIn("\n\nThis replaces the installed helper at ~/.agents/skills/helper and "
                      "~/.claude/skills/helper (recorded 2026-10-05).\nThe copy there now is set "
                      "aside, not deleted; canary restore puts it back.\n\nCommand: ", text)
        self.assertLess(text.index("Into: "), text.index("This replaces"))
        mac = test_install.Mac()
        write_skill(os.path.join(mac.home, ".agents", "skills", "helper"))
        install_replace(mac, test_install.ADD, spec=test_install.ONE, answer=False)
        summary = mac.asked[-1]["summary"]
        text = install.dialog_text(test_install.ADD, summary["items"], summary["verdict"])
        self.assertIn("This replaces the installed helper at ~/.agents/skills/helper (not "
                      "installed by SkillCanary).", text)


class RefusalsBeforeTheDialog(unittest.TestCase):
    def refused(self, h, sentence, hosts=None, present=()):
        lock, before = h.lock_bytes(), len(h.ledger())
        out, approve = h.run(V2, hosts=hosts)
        self.assertEqual(out["outcome"], "not_installed")
        self.assertEqual(approve.seen, [])
        self.assertIn(sentence, out["reasons"])
        self.assertEqual(h.ids(), [])
        self.assertEqual(h.lock_bytes(), lock)
        self.assertEqual([e["event"] for e in h.ledger()[before:]], ["checked", "not_installed"])
        for path in present:
            self.assertTrue(os.path.lexists(path), path)

    def test_06_a_subset_of_a_recorded_skill(self):
        """No seam."""
        h = Home()
        h.run(V1, replace=False)
        self.refused(h, "A skill named notes is installed at ~/.claude/skills/notes and "
                        "~/.agents/skills/notes; this run would replace only "
                        "~/.claude/skills/notes, so it replaced nothing. Replace all of them in "
                        "one run.", hosts=["claude"], present=h.dests)
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])

    def test_06_a_record_of_another_name(self):
        """No seam."""
        h = Home()
        h.untracked(h.claude)
        h.write_lock({"other": {"name": "other", "installed": [h.claude],
                                "installed_at": "2026-10-05T10:00:00Z"}})
        self.refused(h, "~/.claude/skills/notes is recorded as the skill other (recorded "
                        "2026-10-05); --replace replaces only a skill of the same name. Nothing "
                        "was installed.", present=[h.claude])

    def test_06_a_link_to_a_folder_outside_the_run(self):
        """No seam."""
        h = Home()
        outside = write_skill(os.path.join(h.home, "elsewhere", "notes"))
        os.makedirs(os.path.dirname(h.claude))
        os.symlink(outside, h.claude)
        self.refused(h, "~/.claude/skills/notes is a link to a folder this install would not "
                        "replace, so SkillCanary did not replace it. Nothing was installed.",
                     present=[h.claude])

    def test_06_a_link_to_the_other_destination_while_it_is_empty(self):
        """A link-only group is refused. No seam."""
        h = Home()
        os.makedirs(os.path.dirname(h.claude))
        os.symlink(os.path.join("..", "..", ".agents", "skills", "notes"), h.claude)
        self.refused(h, "~/.claude/skills/notes is a link to a folder this install would not "
                        "replace, so SkillCanary did not replace it. Nothing was installed.",
                     present=[h.claude])

    def test_06_a_folder_without_skill_md_or_a_plain_file(self):
        """No seam."""
        sentence = ("~/.claude/skills/notes exists but holds no SKILL.md, so SkillCanary does "
                    "not know what it is and left it alone. Nothing was installed.")
        h = Home()
        os.makedirs(h.claude)
        self.refused(h, sentence, present=[h.claude])
        h = Home()
        os.makedirs(os.path.dirname(h.claude))
        with open(h.claude, "w") as fh:
            fh.write("not a skill")
        self.refused(h, sentence, present=[h.claude])


class TheStoreMustBeOnTheSameDisk(unittest.TestCase):
    def device(self, h):
        store = os.path.realpath(h.store)
        return lambda path: 2 if os.path.realpath(path).startswith(store) else 1

    def test_07_a_store_on_another_disk_refuses_a_replace_and_a_restore(self):
        """Seam: patch.object(replace, "_device")."""
        h = Home()
        h.run(V1, replace=False)
        with unittest.mock.patch.object(R(), "_device", self.device(h)):
            out, approve = h.run(V2)
        self.assertEqual((out["outcome"], approve.seen), ("not_installed", []))
        self.assertIn("SkillCanary keeps replaced copies under ~/support/quarantine/replaced, "
                      "which is on a different disk from ~/.claude/skills/notes, so it cannot "
                      "set the old copy aside. Nothing was installed.", out["reasons"])
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        self.assertEqual(h.ids(), [])
        out, _ = h.run(V2)
        [gid] = h.ids()
        with unittest.mock.patch.object(R(), "_device", self.device(h)):
            result = h.restore(gid)
        self.assertEqual(result, (False, "Still set aside: SkillCanary keeps replaced copies under "
                                         "~/support/quarantine/replaced, which is on a different "
                                         "disk from ~/.claude/skills/notes, so it cannot set the "
                                         "copy that is there now aside. canary list shows where "
                                         "it is."))
        self.assertEqual([h.read(d) for d in h.dests], [V2, V2])
        self.assertEqual(h.ids(), [gid])


class UnderTheCommitLock(unittest.TestCase):
    def test_08_a_change_while_the_person_decides_refuses(self):
        """Seam: the approver changes the destinations or the lock file."""
        h = Home()
        h.untracked(h.claude)

        def second_copy(summary):
            write_skill(h.codex)
            return True

        def a_record(summary):
            h.write_lock({"notes": {"name": "notes", "installed": [h.claude],
                                    "installed_at": "2026-10-06T08:00:00Z"}})
            return True

        for approve in (second_copy, a_record):
            with self.subTest(approve.__name__):
                if approve is a_record:
                    h = Home()
                    h.untracked(h.claude)
                out, _ = h.run(V2, approve=approve)
                self.assertEqual(out["outcome"], "not_installed")
                self.assertIn(CHANGED, out["reasons"])
                self.assertEqual(h.read(h.claude), V1)
                self.assertEqual(h.ids(), [])

    def test_09_a_failed_rename_in_puts_the_old_copies_back(self):
        """Seam: patch.object(add.os, "rename") with a wrapper that raises once,
        on the second staging rename; a watcher looks while the second
        destination is empty."""
        h = Home()
        h.run(V1, replace=False)
        old_digest = guestlist.digest(h.claude)
        lock = h.lock_bytes()
        w = h.watcher()
        held = []
        with unittest.mock.patch.object(add.os, "rename",
                                        staging_fails_once(lambda: held.extend(w.step(0)))):
            out, _ = h.run(V2)
        self.assertEqual(out["outcome"], "not_installed")
        self.assertIn(FIRST, out["reasons"])
        self.assertIn(BACK, out["reasons"])
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        self.assertEqual(h.ids(), [])
        self.assertEqual(h.lock_bytes(), lock)
        tail = h.ledger()[-2:]
        self.assertEqual([(e["event"], e["how"], e["skill"], e["digest"]) for e in tail],
                         [("approved", "replace undo", os.path.realpath(d), old_digest)
                          for d in h.dests])
        self.assertEqual([e["origin"] for e in tail], [{"kind": "local"}] * 2)
        held += w.step(5) + w.step(10) + w.step(15)
        self.assertEqual(held, [])

    def test_09_an_untracked_old_copy_comes_back_as_arrived(self):
        """Seam: patch.object(add.os, "rename"), as above."""
        h = Home()
        h.untracked()
        digest = guestlist.digest(h.claude)
        with unittest.mock.patch.object(add.os, "rename", staging_fails_once()):
            out, _ = h.run(V2)
        self.assertEqual(out["outcome"], "not_installed")
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        tail = h.ledger()[-2:]
        self.assertEqual([(e["event"], e["how"], e["skill"], e["digest"]) for e in tail],
                         [("arrived", "replace undo", os.path.realpath(d), digest)
                          for d in h.dests])

    def test_10_an_undo_that_cannot_put_a_copy_back_keeps_it_for_restore(self):
        """Seams: test 9's, plus patch.object(replace, "_rename") raising on
        the rename back to the second origin."""
        h = Home()
        h.untracked()
        real = R()._rename

        def rename(src, dst):
            if dst == h.codex:
                raise OSError(5, "Input/output error")
            return real(src, dst)

        with unittest.mock.patch.object(add.os, "rename", staging_fails_once()), \
                unittest.mock.patch.object(R(), "_rename", rename):
            out, _ = h.run(V2)
        self.assertEqual(out["outcome"], "not_installed")
        [gid] = h.ids()
        self.assertIn(f"SkillCanary could not put the earlier copy of notes back at "
                      f"~/.agents/skills/notes; it is kept as {gid}. canary restore {gid} tries "
                      "again.", out["reasons"])
        self.assertEqual(h.read(h.claude), V1)
        self.assertFalse(os.path.lexists(h.codex))
        report = guestlist.scan(h.home, support=h.support)
        self.assertEqual([(g["id"], g["kept"]) for g in report["replaced"]], [(gid, [h.codex])])
        self.assertEqual(h.restore(gid), (True, None))
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        self.assertEqual(h.ids(), [])

    def test_11_a_failed_lock_write_puts_the_old_copies_back(self):
        """Seam: patch.object(add.os, "replace", side_effect=OSError)."""
        h = Home()
        h.run(V1, replace=False)
        old_digest = guestlist.digest(h.claude)
        lock = h.lock_bytes()
        with unittest.mock.patch.object(add.os, "replace", side_effect=OSError(28, "full")):
            out, _ = h.run(V2)
        self.assertEqual(out["outcome"], "not_installed")
        self.assertIn("SkillCanary could not record the install, so it removed it again.",
                      out["reasons"])
        self.assertIn(BACK, out["reasons"])
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        self.assertEqual([(e["event"], e["how"], e["digest"]) for e in h.ledger()[-2:]],
                         [("approved", "replace undo", old_digest)] * 2)
        self.assertEqual(h.lock_bytes(), lock)
        self.assertEqual(h.ids(), [])

    def test_12_a_death_after_the_set_aside_is_recovered_by_restore(self):
        """Seam: patch.object(add, "_install", side_effect=RuntimeError)."""
        h = Home()
        h.run(V1, replace=False)
        lock, before = h.lock_bytes(), len(h.ledger())
        with unittest.mock.patch.object(add, "_install", side_effect=RuntimeError("killed")):
            with self.assertRaises(RuntimeError):
                h.run(V2)
        self.assertEqual([os.path.lexists(d) for d in h.dests], [False, False])
        [gid] = h.ids()
        self.assertEqual(sorted(os.listdir(os.path.join(h.store, gid))),
                         ["entry-0", "entry-1", "replaced.json"])
        self.assertEqual(h.lock_bytes(), lock)
        self.assertEqual([e["event"] for e in h.ledger()[before:]],
                         ["checked", "approved", "approved"])
        w = h.watcher()
        self.assertEqual(h.restore(gid), (True, None))
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        self.assertEqual(h.ids(), [])
        self.assertEqual(w.step(0) + w.step(5) + w.step(10), [])

    def test_13_the_ledger_lock_is_never_taken_twice(self):
        """Seam: wrappers on guestlist._Lock.__enter__ and __exit__ that count
        the depth per thread and fail above 1."""
        depth = threading.local()
        entered = []
        real_enter, real_exit = guestlist._Lock.__enter__, guestlist._Lock.__exit__

        def enter(self):
            n = getattr(depth, "n", 0)
            if n >= 1:
                raise AssertionError("guestlist._Lock taken while already held")
            depth.n = n + 1
            entered.append(n + 1)
            return real_enter(self)

        def exit_(self, *exc):
            depth.n -= 1
            return real_exit(self, *exc)

        h = Home()
        h.run(V1, replace=False)
        with unittest.mock.patch.object(guestlist._Lock, "__enter__", enter), \
                unittest.mock.patch.object(guestlist._Lock, "__exit__", exit_):
            out, _ = h.run(V2)
            self.assertEqual(out["outcome"], "installed")
            with unittest.mock.patch.object(add.os, "rename", staging_fails_once()):
                out, _ = h.run(V3)
            self.assertEqual(out["outcome"], "not_installed")
            [gid] = h.ids()
            self.assertTrue(h.restore(gid)[0])
        self.assertTrue(entered)
        self.assertEqual(set(entered), {1})


class TheWatcherAndTheNotice(unittest.TestCase):
    def test_14_a_replace_is_not_held_and_not_counted(self):
        """Seam: a wrapper on add._install that lets a watcher look while both
        destinations are empty and the approval is recorded."""
        h = Home()
        h.run(V1, replace=False)
        w = h.watcher()
        held = []
        real_install = add._install

        def look_then_install(*a, **k):
            held.extend(w.step(0))
            return real_install(*a, **k)

        with unittest.mock.patch.object(add, "_install", look_then_install):
            out, _ = h.run(V2)
        self.assertEqual(out["outcome"], "installed")
        held += w.step(5) + w.step(10) + w.step(15)
        self.assertEqual(held, [])
        self.assertEqual(watcher.held(h.support, w.roots), [])
        report = guestlist.scan(h.home, support=h.support)
        self.assertIsNone(guestlist.session_line(report))
        [gid] = h.ids()
        [group] = report["replaced"]
        self.assertEqual((group["id"], group["name"], group["paths"], group["kept"],
                          group["how"], group["restore"]),
                         (gid, "notes", h.dests, h.dests, "canary add", f"canary restore {gid}"))
        self.assertIn("Set aside by a replace (nothing is deleted):\n  notes  replaced ",
                      guestlist.render_text(report))
        self.assertIn(f"to restore: canary restore {gid}", guestlist.render_text(report))


ONE_V2 = {"skills": [{"name": "helper", "link": True, "body": "Help, second edition.\n"}]}


class CanaryInstallReplace(unittest.TestCase):
    def test_15_an_npx_layout_is_replaced_as_a_unit(self):
        """No seam."""
        mac = test_install.Mac()
        self.assertEqual(mac.install(test_install.ADD, spec=test_install.ONE)["outcome"],
                         "installed")
        before = len(runs(mac))
        out = install_replace(mac, test_install.ADD, spec=ONE_V2)
        self.assertEqual(out["outcome"], "installed")
        self.assertEqual(len(runs(mac)), before + 1)
        folder = os.path.join(mac.home, ".agents", "skills", "helper")
        link = os.path.join(mac.home, ".claude", "skills", "helper")
        with open(os.path.join(folder, "SKILL.md")) as fh:
            self.assertIn("second edition", fh.read())
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.path.realpath(link), folder)
        store = os.path.join(mac.support, "quarantine", "replaced")
        [gid] = os.listdir(store)
        with open(os.path.join(store, gid, "replaced.json")) as fh:
            rec = json.load(fh)
        self.assertEqual((rec["how"], rec["members"]), ("canary install", [
            {"entry": "entry-0", "origin": folder, "kind": "folder"},
            {"entry": "entry-1", "origin": link, "kind": "link"}]))
        self.assertTrue(os.path.islink(os.path.join(store, gid, "entry-1")))
        skills = mac.lock()["skills"]
        self.assertEqual(sorted(skills), ["helper"])
        self.assertEqual(skills["helper"]["replaced"], gid)
        self.assertEqual(out["replaced"]["id"], gid)
        self.assertIn(f"  Replaced: ~/.agents/skills/helper and ~/.claude/skills/helper (set "
                      f"aside as {gid}; canary restore {gid} puts it back)",
                      install.render_text(out))

    def test_16_what_install_replace_refuses(self):
        """No seam."""
        mac = test_install.Mac()
        ledger = mac.ledger()
        two = {"skills": [{"name": "alpha"}, {"name": "beta"}]}
        out = install_replace(mac, test_install.ADD, spec=two)
        self.assertEqual(out["outcome"], "not_installed")
        self.assertIn("This install would add 2 skills; --replace works for one skill at a "
                      "time. Nothing was installed.", out["reasons"])
        self.assertEqual((len(runs(mac)), mac.asked, mac.ledger()), (1, [], ledger))
        self.assertFalse(os.path.isdir(os.path.join(mac.support, "quarantine", "replaced"))
                         and os.listdir(os.path.join(mac.support, "quarantine", "replaced")))
        mac = test_install.Mac()
        ledger = mac.ledger()
        out = install_replace(mac, test_install.PROJECT_ADD, spec=test_install.ONE)
        self.assertEqual(out["outcome"], "not_installed")
        self.assertIn("--replace works only in your own skills folders (~/.claude/skills, "
                      "~/.agents/skills), not in a project. Nothing was installed.", out["reasons"])
        self.assertEqual((mac.asked, mac.ledger()), ([], ledger))
        for argv, sentence in (
                (["claude", "plugin", "install", "tidy@mkt"],
                 "--replace applies to skills only. To update a plugin, run: canary install -- "
                 "claude plugin update tidy@mkt"),
                (["claude", "plugin", "marketplace", "add", "someone/mkt"],
                 "--replace applies to skills only; a marketplace add has nothing to replace.")):
            with self.subTest(argv=argv):
                mac = test_install.Mac()
                with self.assertRaises(install.InstallError) as ctx:
                    install_replace(mac, argv)
                self.assertEqual(str(ctx.exception), sentence)
                self.assertEqual((runs(mac), mac.asked), ([], []))


class RestoringAReplacedGroup(unittest.TestCase):
    def test_17_a_yes_switches_back_and_sets_the_newer_copy_aside(self):
        """No seam; a variant keeps the old record under a hashed key."""
        for hashed in (False, True):
            with self.subTest(hashed=hashed):
                h = Home()
                h.run(V1, replace=False)
                key = "notes"
                if hashed:
                    places = sorted(os.path.realpath(os.path.dirname(d)) for d in h.dests)
                    key = "notes@" + hashlib.sha256("\n".join(places).encode()).hexdigest()[:12]
                    h.write_lock({key: h.lock()["skills"]["notes"]})
                old = h.lock()["skills"][key]
                h.run(V2)
                [g1] = h.ids()
                new = h.lock()["skills"][key]
                self.assertEqual(new["replaced"], g1)
                before = len(h.ledger())
                w = h.watcher()
                back, line = h.restore(g1)
                [g2] = h.ids()
                self.assertNotEqual(g1, g2)
                self.assertEqual((back, line), (True, "Put back where it was; the copy that was "
                                                      f"there is set aside as {g2}."))
                self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
                rec = h.group(g2)
                self.assertEqual((rec["how"], rec["records"]), ("restore", {key: new}))
                self.assertEqual([h.read(os.path.join(h.store, g2, e))
                                  for e in ("entry-0", "entry-1")], [V2, V2])
                self.assertEqual(h.lock()["skills"], {key: dict(old, replaced=g2)})
                events = h.ledger()[before:]
                self.assertEqual([e["event"] for e in events],
                                 ["checked", "approved", "checked", "approved", "replaced",
                                  "replaced", "restored"])
                for e in (events[1], events[3]):
                    self.assertEqual((e["how"], e["origin"]), ("restore", {"kind": "local"}))
                self.assertEqual([(e["id"], e["how"]) for e in events[4:6]],
                                 [(g2, "restore")] * 2)
                self.assertEqual(events[6]["id"], g1)
                report = guestlist.scan(h.home, support=h.support)
                self.assertEqual([g["id"] for g in report["replaced"]], [g2])
                self.assertEqual(w.step(0) + w.step(5) + w.step(10), [])

    def test_18_with_both_origins_empty_nothing_is_set_aside(self):
        """No seam."""
        h = Home()
        h.run(V1, replace=False)
        old = h.lock()["skills"]["notes"]
        h.run(V2)
        [g1] = h.ids()
        for d in h.dests:
            shutil.rmtree(d)
        self.assertEqual(h.restore(g1), (True, None))
        self.assertEqual(h.ids(), [])
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        self.assertEqual(h.lock()["skills"], {"notes": old})

    def test_19_what_a_restore_refuses(self):
        """No seam."""
        h = Home()
        g1 = h.replaced_group()
        shutil.rmtree(h.claude)
        with open(h.claude, "w") as fh:
            fh.write("not a skill")
        self.assertEqual(h.restore(g1), (False, "Still set aside: something SkillCanary does not "
                                                "move is at ~/.claude/skills/notes. canary list "
                                                "shows where it is."))
        self.assertEqual((h.ids(), h.read(h.codex)), ([g1], V2))

        h = Home()
        h.untracked(h.claude)
        out, _ = h.run(V2, hosts=["claude"])
        [g1] = h.ids()
        write_skill(h.codex, V2)
        lock = h.lock()["skills"]
        lock["notes"]["installed"] = h.dests
        h.write_lock(lock)
        self.assertEqual(h.restore(g1), (False, "Still set aside: the copy at "
                                                "~/.claude/skills/notes is also installed at "
                                                "~/.agents/skills/notes; replace all of them in "
                                                "one run first. canary list shows where it is."))
        self.assertEqual(h.read(h.claude), V2)

        h = Home()
        g1 = h.replaced_group()
        self.assertEqual(h.restore(g1, answer=False), (False, "Still set aside: you chose not to "
                                                              "put it back. canary list shows "
                                                              "where it is."))
        silent = ("Still set aside: nobody answered the SkillCanary dialog. canary list shows "
                  "where it is.")
        self.assertEqual(h.restore(g1, answer=None), (False, silent))
        before = len(h.ledger())
        self.assertEqual(h.restore(g1, answer=None, verdict="UNSAFE"), (False, silent))
        self.assertIn("refused", [e["event"] for e in h.ledger()[before:]])
        self.assertEqual(([h.read(d) for d in h.dests], h.ids()), ([V2, V2], [g1]))

        with self.assertRaises(ValueError) as ctx:
            h.restore("20261017T000000Z-deadbeef")
        self.assertEqual(str(ctx.exception), "SkillCanary is not holding or keeping anything with "
                                             "that id; canary list shows what it has.")

        for entry in ("entry-0", "entry-1"):
            shutil.rmtree(os.path.join(h.store, g1, entry))
        self.assertEqual(h.restore(g1), (False, NOTHING_LEFT))

    def test_20_a_failed_move_back_returns_the_current_copies(self):
        """Seam: patch.object(replace, "_rename") raising on the second old
        entry's move; a variant also raises on one put-back from the new group."""
        for also in (False, True):
            with self.subTest(also_the_put_back=also):
                h = Home()
                g1 = h.replaced_group()
                new_digest = guestlist.digest(h.claude)
                g1dir = os.path.join(h.store, g1)
                real = R()._rename

                def rename(src, dst):
                    if src == os.path.join(g1dir, "entry-1"):
                        raise OSError(5, "Input/output error")
                    if also and dst == h.codex and not src.startswith(g1dir + os.sep):
                        raise OSError(5, "Input/output error")
                    return real(src, dst)

                before = len(h.ledger())
                with unittest.mock.patch.object(R(), "_rename", rename):
                    result = h.restore(g1)
                self.assertEqual(sorted(os.listdir(g1dir)), ["entry-0", "entry-1", "replaced.json"])
                self.assertEqual(h.read(os.path.join(g1dir, "entry-0")), V1)
                events = h.ledger()[before:]
                self.assertEqual([e["event"] for e in events],
                                 ["checked", "approved", "checked", "approved", "approved",
                                  "approved"])
                self.assertEqual([(e["how"], e["digest"]) for e in events[4:]],
                                 [("replace undo", new_digest)] * 2)
                self.assertEqual(h.read(h.claude), V2)
                if not also:
                    self.assertEqual(result, (False, NOT_MOVED))
                    self.assertEqual(h.read(h.codex), V2)
                    self.assertEqual(h.ids(), [g1])
                else:
                    [g2] = [g for g in h.ids() if g != g1]
                    self.assertEqual(result, (False, "Still set aside: SkillCanary could not move "
                                                     "it back, and could not put the copy that "
                                                     "was there back at ~/.agents/skills/notes; "
                                                     f"that copy is kept as {g2}. canary list "
                                                     "shows where it is."))
                    self.assertFalse(os.path.lexists(h.codex))
                    self.assertEqual(sorted(os.listdir(os.path.join(h.store, g2))),
                                     ["entry-1", "replaced.json"])

    def test_21_an_unsafe_earlier_copy_needs_the_typed_name(self):
        """No seam."""
        h = Home()
        g1 = h.replaced_group()
        asked = []

        def ask(text, verdict, confirm=None):
            asked.append((text, verdict, confirm))
            return False

        before = len(h.ledger())
        self.assertEqual(h.restore(g1, verdict="UNSAFE", ask=ask),
                         (False, "Still set aside: you chose not to put it back. canary list "
                                 "shows where it is."))
        self.assertEqual([(v, c) for _, v, c in asked], [("UNSAFE", "notes")])
        self.assertTrue(asked[0][0].startswith("Put back the earlier notes you replaced on "))
        self.assertTrue(asked[0][0].endswith(add.override_sentence("notes")))
        self.assertIn("refused", [e["event"] for e in h.ledger()[before:]])
        self.assertEqual(h.ids(), [g1])

    def test_22_every_folder_member_is_checked_and_approved_with_its_own_digest(self):
        """Seam: patch.object(replace.classify, "check", wraps=...) counting calls."""
        h = Home()
        g1 = h.replaced_group()
        with open(os.path.join(h.store, g1, "entry-1", "SKILL.md"), "a") as fh:
            fh.write("\nEdited by hand after the replace.\n")
        before = len(h.ledger())
        real = R().classify.check
        with unittest.mock.patch.object(R().classify, "check", wraps=real) as spy:
            self.assertTrue(h.restore(g1)[0])
        self.assertEqual(spy.call_count, 2)
        approved = [e for e in h.ledger()[before:] if e["event"] == "approved"]
        self.assertEqual(len(approved), 2)
        self.assertNotEqual(approved[0]["digest"], approved[1]["digest"])
        self.assertEqual([e["digest"] for e in approved],
                         [guestlist.digest(h.claude), guestlist.digest(h.codex)])

    def test_28_a_death_between_the_record_and_the_first_rename(self):
        """Seam: patch.object(replace, "_rename", side_effect=RuntimeError)."""
        h = Home()
        h.run(V1, replace=False)
        lock, before = h.lock_bytes(), len(h.ledger())
        with unittest.mock.patch.object(R(), "_rename", side_effect=RuntimeError("killed")):
            with self.assertRaises(RuntimeError):
                h.run(V2)
        [gid] = h.ids()
        self.assertEqual(os.listdir(os.path.join(h.store, gid)), ["replaced.json"])
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        self.assertEqual(len(h.ledger()), before)
        self.assertEqual(h.lock_bytes(), lock)
        report = guestlist.scan(h.home, support=h.support)
        self.assertEqual([(g["id"], g["kept"]) for g in report["replaced"]], [(gid, [])])
        self.assertEqual(h.restore(gid), (False, NOTHING_LEFT))

    def test_29_no_key_under_the_lock_puts_the_files_back_and_writes_nothing(self):
        """Seam: patch.object(add, "choose_key", return_value=None)."""
        h = Home()
        h.untracked()
        with unittest.mock.patch.object(add, "choose_key", return_value=None):
            out, _ = h.run(V2)
        self.assertEqual(out["outcome"], "not_installed")
        self.assertIn(FIRST, out["reasons"])
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        self.assertEqual(h.ids(), [])
        self.assertEqual(h.ledger(), [])

    def test_30_a_restore_that_died_after_its_set_aside_is_finished_by_another(self):
        """Seam: patch.object(replace, "_rename") raising RuntimeError on the
        first old entry's move, then a second restore without it."""
        for recorded in (True, False):
            with self.subTest(recorded=recorded):
                h = Home()
                if recorded:
                    h.run(V1, replace=False)
                else:
                    h.untracked()
                old = h.lock()["skills"] if recorded else {}
                h.run(V2)
                [g1] = h.ids()
                g1dir = os.path.join(h.store, g1)
                real = R()._rename

                def rename(src, dst):
                    if src.startswith(g1dir + os.sep):
                        raise RuntimeError("killed")
                    return real(src, dst)

                with unittest.mock.patch.object(R(), "_rename", rename):
                    with self.assertRaises(RuntimeError):
                        h.restore(g1)
                [g2] = [g for g in h.ids() if g != g1]
                self.assertEqual([os.path.lexists(d) for d in h.dests], [False, False])
                self.assertEqual(h.restore(g1), (True, None))
                self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
                self.assertEqual(h.lock()["skills"], old)
                report = guestlist.scan(h.home, support=h.support)
                self.assertEqual([g["id"] for g in report["replaced"]], [g2])

    def test_31_a_failed_lock_write_after_the_move_says_the_record_is_stale(self):
        """Seam: patch.object(add, "_write_lock", side_effect=OSError)."""
        h = Home()
        g1 = h.replaced_group()
        lock = h.lock_bytes()
        before = len(h.ledger())
        with unittest.mock.patch.object(add, "_write_lock", side_effect=OSError(28, "full")):
            result = h.restore(g1)
        self.assertEqual(result, (True, "Put back where it was, but SkillCanary could not update "
                                        "its lock file; its record of this skill is stale until "
                                        "the next replace or restore."))
        self.assertEqual([h.read(d) for d in h.dests], [V1, V1])
        [g2] = [g for g in h.ids() if g != g1]
        self.assertEqual([h.read(os.path.join(h.store, g2, e)) for e in ("entry-0", "entry-1")],
                         [V2, V2])
        self.assertTrue(os.path.isfile(os.path.join(h.store, g1, "replaced.json")))
        self.assertEqual(h.lock_bytes(), lock)
        self.assertEqual([e.get("how") for e in h.ledger()[before:] if e["event"] == "approved"],
                         ["restore", "restore"])
        out, _ = h.run(V3)
        self.assertEqual(out["outcome"], "installed")
        [g3] = [g for g in h.ids() if g not in (g1, g2)]
        record = h.lock()["skills"]["notes"]
        self.assertEqual((record["replaced"], record["installed"]), (g3, h.dests))
        self.assertEqual([h.read(d) for d in h.dests], [V3, V3])

    def test_32_a_watcher_look_between_the_move_and_the_lock_holds_nothing(self):
        """Seam: patch.object(replace, "_rename") wrapping the real rename; a
        watcher started while the origins are empty looks right after the
        first old entry lands, at mock clock 0, 5 and 10."""
        h = Home()
        g1 = h.replaced_group()
        g1dir = os.path.join(h.store, g1)
        real = R()._rename
        held, looked = [], []

        def rename(src, dst):
            if src.startswith(g1dir + os.sep) and not looked:
                w = h.watcher()
                real(src, dst)
                looked.append(dst)
                held.extend(w.step(0) + w.step(5) + w.step(10))
                return
            return real(src, dst)

        with unittest.mock.patch.object(R(), "_rename", rename):
            back, _ = h.restore(g1)
        self.assertTrue(back)
        self.assertEqual(looked, [h.claude])
        self.assertEqual(held, [])


class OlderDataIsReadAsBefore(unittest.TestCase):
    def test_24_replaced_fields_and_events_change_nothing_older_code_reads(self):
        """A pin, green before the program. No seam."""
        h = Home()
        h.run(V1, replace=False)
        lock = h.lock()
        plain = json.loads(json.dumps(lock))
        lock["skills"]["notes"]["replaced"] = "20261017T101500Z-9f3c2a1b"
        h.write_lock(lock["skills"])
        digest = guestlist.digest(h.codex)
        with open(os.path.join(h.support, "ledger.jsonl"), "a") as fh:
            for e in ({"event": "replaced", "id": "20261017T101500Z-9f3c2a1b", "name": "notes",
                       "skill": h.claude, "kind": "folder", "how": "canary add"},
                      {"event": "restored", "id": "20261017T101500Z-9f3c2a1b"},
                      {"event": "approved", "how": "replace undo", "name": "notes",
                       "skill": os.path.realpath(h.codex), "digest": digest}):
                fh.write(json.dumps(dict(e, at="2026-10-17T10:15:00Z")) + "\n")
        group = os.path.join(h.store, "20261017T101500Z-9f3c2a1b")
        write_skill(os.path.join(group, "entry-0"))
        with open(os.path.join(group, "replaced.json"), "w") as fh:
            json.dump({"schema": "canary.replaced/1", "id": "20261017T101500Z-9f3c2a1b",
                       "name": "notes", "at": "2026-10-17T10:15:00Z", "how": "canary add",
                       "members": [{"entry": "entry-0", "origin": h.claude, "kind": "folder"}],
                       "states": {}, "records": {}}, fh)
        report = guestlist.scan(h.home, support=h.support)
        self.assertEqual({s["status"] for s in report["skills"] if s["name"] == "notes"},
                         {"checked"})
        self.assertEqual(report["unchecked"] + report["changed"], [])
        places = add.places_of(h.dests)
        self.assertEqual(add.plan_key(lock, "notes", places), add.plan_key(plain, "notes", places))
        self.assertEqual(add.plan_key(lock, "notes", places)[1], lock["skills"]["notes"])
        self.assertEqual(setup.old_records(h.home), [])
        roots = guestlist.user_roots(h.home)
        self.assertEqual(watcher.held(h.support, roots), [])
        for d in h.dests:
            shutil.rmtree(d)
        self.assertEqual([r["key"] for r in setup.old_records(h.home)], ["notes"])


class TheCommandLine(unittest.TestCase):
    def test_23_the_flag_reaches_add_and_install_and_nothing_else(self):
        """Seams: patch.object(add, "add") and patch.object(install, "install")."""
        for args, expected in ((["x", "--replace"], True), (["x"], False)):
            with self.subTest(args=args):
                with unittest.mock.patch.object(add, "add", return_value={"outcome": "installed"}) \
                        as fake, contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cli._add(args), 0)
                self.assertIs(fake.call_args.kwargs.get("replace"), expected)
        for args, expected in ((["--replace", "--", "npx", "skills", "add", "x"], True),
                               (["--", "npx", "skills", "add", "x"], False)):
            with self.subTest(args=args):
                with unittest.mock.patch.object(install, "install",
                                                return_value={"outcome": "installed"}) as fake, \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cli._install(args), 0)
                self.assertIs(fake.call_args.kwargs.get("replace"), expected)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["scan", "x", "--replace"]), cli.EXIT_USAGE)
        self.assertIn("canary add <github-link-or-folder> [--replace]", cli.USAGE)
        self.assertIn("canary install [--replace]", cli.USAGE)
        self.assertIn("canary restore <held-id-or-replaced-id>", cli.USAGE)


if __name__ == "__main__":
    unittest.main()
