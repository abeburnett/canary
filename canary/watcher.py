"""The watcher (docs/architecture.md, "The watcher"; program 2026-09-30, slice
B2): a launch agent that holds a new, unchecked skill until the person
decides.

It watches the person's Claude Code and Codex skills folders. When a new
entry appears there and stops changing, and it is a skill SkillCanary has no
approval for, the watcher moves it into the quarantine ("holds" it), checks
it, and asks the person once. Approval puts it back where it was, if it
still matches what was checked; anything else leaves it held, and `canary
list` shows how to restore it. The watcher deletes a held copy only when the
same content is installed and approved at its place, or when the person says
so with `canary drop`; each deletion is recorded first.

What it leaves alone: what was there when it was set up, changes to skills
already there, SkillCanary's own installs (they record their approval before
the files appear), skills the person marked as theirs, and SkillCanary's own
skill. A folder that later gains a SKILL.md counts as a new skill. Skills
inside repositories are the guest list's to report. The watcher remembers
what it has seen, so a skill that arrives while it is stopped is held when it
starts again.
"""

import json
import os
import queue
import re
import secrets
import select
import shutil
import sys
import tempfile
import threading
import time

from canary import add, classify, explain, frontdoor, guestlist

LABEL = "com.skillcanary.watcher"
SETTLE_SECONDS = 2.0
# An entry that keeps changing is held after this long anyway.
MAX_WAIT_SECONDS = 30.0
POLL_SECONDS = 2.0
SEEN = "watcher-seen.json"
SUFFIX = " canary list shows where it is."
STILL_CANCELLED = "Still held: you chose not to install it." + SUFFIX
STILL_SILENT = "Still held: nobody answered the SkillCanary dialog." + SUFFIX
STILL_LINKS = "Still held: it holds links or special files SkillCanary will not copy." + SUFFIX
STILL_CHANGED = "Still held: it changed after its check." + SUFFIX
STILL_TAKEN = "Still held: something else is in its place now." + SUFFIX
STILL_NOT_MOVED = "Still held: SkillCanary could not move it back." + SUFFIX
STILL_GONE = "Still held: SkillCanary is no longer holding it."
STILL_KEPT = "Still held: you chose not to delete it." + SUFFIX
STILL_NOT_DROPPED = "Still held: SkillCanary could not delete it." + SUFFIX
DROPPED = "Deleted the held copy of {name}."
NOT_A_HOLD = ("canary drop deletes a held skill only; canary restore {id} puts a replaced "
              "copy back.")
HOLD_ID = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}")
# On the review queue: run the sweep (program 2026-11-15, section 1.2).
SWEEP = object()


def held_dir(support):
    return os.path.join(support, "quarantine", "held")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _key(path):
    """Changes whenever the entry or anything in it (followed through links)
    does; used to wait until a new entry settles."""
    try:
        st = os.lstat(path)
        target = os.readlink(path) if os.path.islink(path) else ""
    except OSError:
        return None
    return f"{st.st_mtime_ns}:{st.st_ctime_ns}:{target}:{guestlist._quick_key(path)}"


def _is_frontdoor(path):
    """SkillCanary's own skill, exactly as setup writes it."""
    if os.path.basename(path) != "canary" or os.path.islink(path):
        return False
    try:
        if sorted(os.listdir(path)) != ["SKILL.md"]:
            return False
        with open(os.path.join(path, "SKILL.md"), encoding="utf-8") as fh:
            return fh.read() == frontdoor.installed_text()
    except (OSError, UnicodeDecodeError):
        return False


def _approved(path, support):
    """True when the ledger approves what this entry resolves to, with the
    same content (checked by SkillCanary, or the person's own)."""
    real = os.path.realpath(path)
    state, _ = guestlist._state(guestlist._events(support))
    s = state.get(real)
    if not s or s.get("status") not in (guestlist.CHECKED, guestlist.YOURS):
        return False
    want = s.get("approved") if s.get("status") == guestlist.CHECKED else s.get("digest")
    return want is not None and guestlist.digest(real) == want


def _has_skill(path):
    return os.path.isfile(os.path.join(path, "SKILL.md"))


def held(support, roots):
    """What the watcher is holding, read from the quarantine itself (each
    hold's own record), never from the ledger: [{id, name, origin, at}],
    oldest first. A hold whose origin is not directly in one of `roots` is
    not listed, so a forged record cannot send a restore elsewhere."""
    out = []
    try:
        ids = sorted(os.listdir(held_dir(support)))
    except OSError:
        return out
    for held_id in ids:
        slot = os.path.join(held_dir(support), held_id)
        try:
            with open(os.path.join(slot, "hold.json"), encoding="utf-8") as fh:
                rec = json.load(fh)
            origin, name = rec["origin"], rec["name"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if (not HOLD_ID.fullmatch(held_id) or not isinstance(origin, str)
                or os.path.dirname(origin) not in roots
                or not os.path.lexists(os.path.join(slot, "entry"))):
            continue
        out.append({"id": held_id, "name": name, "origin": origin, "at": rec.get("at")})
    return out


def _held_path(support, h):
    return os.path.join(held_dir(support), h["id"], "entry")


def _resolved(entry, origin):
    """Where a held entry leads once it is back at `origin`: a link's target
    is read from where it was found, not from the quarantine."""
    if not os.path.islink(entry):
        return entry
    target = os.readlink(entry)
    return os.path.realpath(target if os.path.isabs(target)
                            else os.path.join(os.path.dirname(origin), target))


def _record(support, events):
    """The ledger is a report: a failure to write it never stops a hold."""
    try:
        guestlist.record_events(support, events)
    except OSError:
        pass


def _fail(err):
    raise err


def same_tree(a, b):
    """True only when two real folders hold exactly the same bytes, paths and
    program bits, `.git` included. A link, a special file or anything that
    cannot be read makes them not the same."""
    for root in (a, b):
        if os.path.islink(root) or not os.path.isdir(root):
            return False
    try:
        # tree_digest's walk skips a folder it cannot list; this one does not.
        for root in (a, b):
            for _ in os.walk(root, onerror=_fail):
                pass
        return add.tree_digest(a) == add.tree_digest(b)
    except (add.SourceError, OSError):
        return False


def _drop_hold(support, h, how, same_as=None):
    """Delete one held copy, recording it first. True once the held copy is
    committed to deletion; False when it could not be, and nothing was
    deleted. A failed ledger write raises OSError and removes nothing."""
    slot = os.path.join(held_dir(support), h["id"])
    entry = os.path.join(slot, "entry")
    try:
        fingerprint = None if os.path.islink(entry) else guestlist.digest(entry)
    except (OSError, ValueError):
        fingerprint = None
    record = {"at": _now(), "event": "dropped", "id": h["id"], "name": h["name"],
              "origin": h["origin"], "digest": fingerprint, "how": how}
    if same_as is not None:
        record["same_as"] = same_as
    guestlist.record_events(support, [record])
    try:
        # The commit point: `held` stops listing it, and a put-back's rename fails.
        os.rename(entry, os.path.join(slot, "dropped"))
    except OSError:
        _record(support, [{"at": _now(), "event": "drop_failed", "id": h["id"]}])
        return False
    shutil.rmtree(slot, ignore_errors=True)
    return True


def _installed_note(names):
    n = len(names)
    what = ("held copy that matches a skill" if n == 1
            else "held copies that match skills")
    return (f"SkillCanary deleted {n} {what} you already installed: {', '.join(names)}. "
            "canary list shows what is still held.")


class Watcher:
    """`step(now)` notices, settles and holds; `review(id)` checks and asks.
    The loop runs reviews on their own thread, so holding never waits for a
    dialog."""

    def __init__(self, home, support=None, *, ask=None, notify=None, backend="auto",
                 model=None, settle=SETTLE_SECONDS, max_wait=MAX_WAIT_SECONDS):
        self.home = home
        self.support = support or os.path.join(home, guestlist.SUPPORT[2:])
        self.ask = ask or add.ask
        self.notify = notify or _notify
        self.backend, self.model = backend, model
        self.settle, self.max_wait = settle, max_wait
        self.roots = guestlist.user_roots(home)
        self.reviews = queue.Queue()
        # Set while a SWEEP waits on the queue: only `step` sets it, only `handle` clears it.
        self.sweep_waiting = threading.Event()
        self.pending = {}  # path -> {"first", "key", "changed"}
        # What the last run saw, so a restart does not take arrivals as given.
        saved = self._load_seen()
        self.seen = {r: set(saved[r]) if r in saved else self._list(r) for r in self.roots}
        # Entries without a SKILL.md are watched until they get one.
        self.skill_less = {os.path.join(r, n) for r in self.roots for n in self.seen[r]
                           if not _has_skill(os.path.join(r, n))}
        self._save_seen()

    @staticmethod
    def _list(root):
        try:
            return set(os.listdir(root))
        except OSError:
            return set()

    def _load_seen(self):
        try:
            with open(os.path.join(self.support, SEEN), encoding="utf-8") as fh:
                data = json.load(fh)
            return {k: v for k, v in data.items() if isinstance(v, list)}
        except (OSError, ValueError, AttributeError):
            return {}

    def _save_seen(self):
        try:
            os.makedirs(self.support, mode=0o700, exist_ok=True)
            tmp = os.path.join(self.support, SEEN + f".{os.getpid()}")
            # An entry still settling is not saved as seen: after a restart
            # it is new again, and still gets its look.
            waiting = set(self.pending)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({r: sorted(n for n in names if os.path.join(r, n) not in waiting)
                           for r, names in self.seen.items()}, fh)
            os.replace(tmp, os.path.join(self.support, SEEN))
        except OSError:
            pass

    def tick(self, now):
        """One look that never ends the loop: an error is logged and the next
        look tries again."""
        try:
            return self.step(now)
        except Exception as exc:
            print(f"canary watch: {type(exc).__name__}: {exc}", file=sys.stderr)
            return []

    def step(self, now):
        """Look once: note new entries, and hold the ones that have settled.
        Returns the ids held in this step."""
        changed = False
        for root in self.roots:
            names = self._list(root)
            for name in names - self.seen[root]:
                path = os.path.join(root, name)
                self.pending[path] = {"first": now, "key": _key(path), "changed": now}
            if names != self.seen[root]:
                self.seen[root], changed = names, True
        for path in list(self.skill_less):
            if not os.path.lexists(path):
                self.skill_less.discard(path)
            elif _has_skill(path):
                self.skill_less.discard(path)
                self.pending[path] = {"first": now, "key": _key(path), "changed": now}
        done, before = [], set(self.pending)
        for path, p in list(self.pending.items()):
            key = _key(path)
            if key is None:
                del self.pending[path]  # gone again
                continue
            waited_long = now - p["first"] >= self.max_wait
            if key != p["key"]:
                p["key"], p["changed"] = key, now
                if not waited_long:
                    continue
            if now - p["changed"] < self.settle and not waited_long:
                continue
            if not _has_skill(path):
                del self.pending[path]
                self.skill_less.add(path)
                continue
            # Read after the wait: SkillCanary's installs record approval first.
            if _approved(path, self.support):
                del self.pending[path]
                # An approved arrival may match a held copy. Set first, then
                # put, so a set event always has a SWEEP on the queue or one
                # being taken.
                if not self.sweep_waiting.is_set():
                    self.sweep_waiting.set()
                    self.reviews.put(SWEEP)
                continue
            if _is_frontdoor(path):
                del self.pending[path]
                continue
            # A link into another watched folder (an installer's
            # ~/.claude/skills/x -> ~/.agents/skills/x) follows its target:
            # the target is the one held or approved.
            if os.path.islink(path) and os.path.dirname(os.path.realpath(path)) in self.roots:
                del self.pending[path]
                continue
            held_id = self.hold(path)
            if held_id:
                del self.pending[path]
                done.append(held_id)
            # else: stays pending, and the next look tries again
        if changed or set(self.pending) != before:
            self._save_seen()
        return done

    def hold(self, path):
        """Move the entry (a folder, or a link) into the quarantine, next to
        a record of where it came from."""
        held_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
        slot = os.path.join(held_dir(self.support), held_id)
        name = os.path.basename(path)
        try:
            os.makedirs(slot, mode=0o700)
            with open(os.path.join(slot, "hold.json"), "w", encoding="utf-8") as fh:
                json.dump({"name": name, "origin": path, "at": _now()}, fh)
            os.rename(path, os.path.join(slot, "entry"))
        except OSError:
            shutil.rmtree(slot, ignore_errors=True)
            return None
        _record(self.support, [{"at": _now(), "event": "held", "id": held_id, "name": name,
                                "origin": path}])
        self.reviews.put(held_id)
        return held_id

    def review(self, held_id):
        """Check a held entry and ask the person. (True, None) when it went
        back, else (False, the line that says why it stays held)."""
        h = next((h for h in held(self.support, self.roots) if h["id"] == held_id), None)
        if h is None:
            return False, STILL_GONE
        entry = _held_path(self.support, h)
        if os.path.lexists(h["origin"]):
            # Nothing could go back, so there is nothing to check or ask about.
            return False, STILL_TAKEN
        work = tempfile.mkdtemp(prefix="canary-held-")
        try:
            snap = os.path.join(work, "skill")
            try:
                add._copy_local(_resolved(entry, h["origin"]), snap)
                result = classify.check(snap, backend=self.backend, model=self.model,
                                        log_dir=os.path.join(self.support, "quarantine", "logs"))
                verdict, reasons = result["verdict"], result["reasons"]
                caps = sorted({c["kind"] for c in result["scan"]["capabilities"]})
            except (add.SourceError, OSError):
                # No checked copy exists, so there is nothing to put back or ask about.
                _decision(self, h["name"], "UNSAFE", "refused")
                self.notify(f"SkillCanary is holding {h['name']}, which arrived in "
                            f"{_short(os.path.dirname(h['origin']), self.home)} without its "
                            "check: it holds links or special files SkillCanary will not copy. "
                            "canary list shows where it is.")
                return False, STILL_LINKS
            text = dialog_text(h, verdict, reasons, caps, self.home, result=result, snapshot=snap)
            if verdict == "UNSAFE":
                answer = self.ask(text, verdict, confirm=_phrase(h["name"]))
            else:
                answer = self.ask(text, verdict)
            if answer is True:
                return self.put_back(h, snap, verdict)
            _decision(self, h["name"], verdict,
                      "refused" if verdict == "UNSAFE" else
                      "declined" if answer is False else "not_installed")
            return False, STILL_CANCELLED if answer is False else STILL_SILENT
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def put_back(self, h, snap, verdict):
        """Only what was checked goes back: the held entry must still match
        the checked copy. Approval first, then the move, if the place is
        still free."""
        origin, entry = h["origin"], _held_path(self.support, h)
        try:
            if guestlist.digest(_resolved(entry, origin)) != guestlist.digest(snap):
                self.notify(f"SkillCanary did not put {h['name']} back: it changed after "
                            "its check. It stays held; canary list shows how to restore it.")
                return False, STILL_CHANGED
            if os.path.lexists(origin):
                self.notify(f"SkillCanary could not put {h['name']} back: something else is "
                            "there now. It stays held; canary list shows where.")
                return False, STILL_TAKEN
            # The approval names where the entry will resolve once it is back.
            resolved = origin if not os.path.islink(entry) else _resolved(entry, origin)
            guestlist.record_install(self.home, [resolved], h["name"], verdict,
                                     support=self.support, source=snap, how="watcher",
                                     override=(verdict == "UNSAFE"),
                                     origin={"kind": "watcher"})
            os.rename(entry, origin)
        except OSError:
            self.notify(f"SkillCanary could not put {h['name']} back. It stays held; "
                        "canary list shows where.")
            return False, STILL_NOT_MOVED
        shutil.rmtree(os.path.dirname(entry), ignore_errors=True)
        _record(self.support, [{"at": _now(), "event": "restored", "id": h["id"]}])
        return True, None

    def run(self, stop=None):
        """The launch agent's loop: kqueue on the skills folders, with a look
        every couple of seconds for folders that appear later."""
        threading.Thread(target=self._review_loop, daemon=True).start()
        while not (stop and stop.is_set()):
            self._wait()
            self.tick(time.monotonic())

    def _review_loop(self):
        self.begin()
        while True:
            # A held skill stays held; `canary list` shows it.
            self.handle(self.reviews.get())

    def begin(self):
        """At start: one sweep. No hold goes on the review queue: the watcher
        asked about each one when it made it."""
        try:
            self.sweep()
        except Exception:
            pass

    def handle(self, item):
        """One item from the review queue: SWEEP, or a hold's id. Any error
        leaves the hold held."""
        try:
            if item is SWEEP:
                self.sweep_waiting.clear()
                self.sweep()
            else:
                self._handle_hold(item)
        except Exception:
            pass

    def _handle_hold(self, held_id):
        holds = held(self.support, self.roots)
        h = next((h for h in holds if h["id"] == held_id), None)
        if h is None:
            return
        entry = _held_path(self.support, h)
        if os.path.islink(entry):
            self.review(held_id)
            return
        for older in holds:
            if older["id"] == held_id:
                break
            if older["origin"] == h["origin"] and same_tree(_held_path(self.support, older),
                                                            entry):
                try:
                    if _drop_hold(self.support, h, "same as waiting hold"):
                        self.notify(f"SkillCanary deleted a second held copy of {h['name']}: "
                                    "it is the same as the copy it is already holding. "
                                    "canary list shows what is still held.")
                except OSError:
                    pass  # the record failed: both stay, and nothing is asked
                return
        if os.path.lexists(h["origin"]):
            try:
                gone = self._drop_if_installed(h)
            except OSError:
                gone = False
            if gone:
                self.notify(_installed_note([h["name"]]))
            elif os.path.lexists(entry):
                self.notify(f"SkillCanary is holding {h['name']}, which arrived in "
                            f"{_short(os.path.dirname(h['origin']), self.home)} without its "
                            "check. Its place is taken now, so SkillCanary did not ask about "
                            "it. canary list shows where it is.")
            return
        back, _ = self.review(held_id)
        if back:
            self.sweep()

    def _drop_if_installed(self, h):
        """The taken-place rule: drop a hold whose place is a real folder,
        approved, with exactly the same bytes. The tests run in this order
        and stop at the first that fails."""
        place = h["origin"]
        if os.path.islink(place) or not os.path.isdir(place):
            return False
        if not _approved(place, self.support):
            return False
        if not same_tree(_held_path(self.support, h), place):
            return False
        return _drop_hold(self.support, h, "same as installed", same_as=place)

    def sweep(self):
        """One pass over the holds, oldest first: drop each one whose place
        holds an approved exact copy. Then remove what a stopped drop left."""
        dropped = []
        for h in held(self.support, self.roots):
            try:
                if os.path.islink(_held_path(self.support, h)):
                    continue
                if os.path.lexists(h["origin"]) and self._drop_if_installed(h):
                    dropped.append(h["name"])
            except Exception:
                continue
        try:
            slots = os.listdir(held_dir(self.support))
        except OSError:
            slots = []
        for name in slots:
            slot = os.path.join(held_dir(self.support), name)
            # Only _drop_hold makes `dropped`, after its record.
            if (HOLD_ID.fullmatch(name) and os.path.lexists(os.path.join(slot, "dropped"))
                    and not os.path.lexists(os.path.join(slot, "entry"))):
                shutil.rmtree(slot, ignore_errors=True)
        if dropped:
            self.notify(_installed_note(dropped))

    def _wait(self):
        timeout = 0.5 if self.pending else POLL_SECONDS
        fds = []
        try:
            kq = select.kqueue()
        except (AttributeError, OSError):
            time.sleep(timeout)
            return
        try:
            for root in self.roots:
                try:
                    fds.append(os.open(root, os.O_RDONLY | getattr(os, "O_EVTONLY", 0)))
                except OSError:
                    pass
            events = [select.kevent(fd, filter=select.KQ_FILTER_VNODE,
                                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                                    fflags=select.KQ_NOTE_WRITE) for fd in fds]
            kq.control(events, 1, timeout)
        finally:
            for fd in fds:
                os.close(fd)
            kq.close()


def _decision(w, name, verdict, outcome):
    try:
        guestlist.record_decision(w.home, name, verdict, outcome, support=w.support)
    except OSError:
        pass


def dialog_text(h, verdict, reasons, caps, home, result=None, snapshot=None):
    """The held-skill dialog. With the check's `result`, it leads with the
    recommendation and says what SkillCanary found in plain words; with the
    checked `snapshot`, it quotes the lines that raised each risk."""
    word = {"LIKELY_SAFE": "no problems found",
            "NEEDS_REVIEW": "needs your judgment"}.get(verdict, verdict)
    lines = [f"A skill appeared in {_short(os.path.dirname(h['origin']), home)} without "
             "SkillCanary's check, so SkillCanary is holding it.", "",
             f"SkillCanary checked it: {word}."]
    found = []
    if result is not None:
        lines += ["", result["recommendation"]["text"]]
        if result["headline"] != explain.GENERIC_HEADLINE:
            lines += ["", result["headline"]]
        found = add.found_block({"_snapshot": snapshot, "risks": result["risks"]})
        if found:
            lines += [""] + found
    can = sorted({add.PLAIN[k] for k in caps if k in add.PLAIN})
    if can:
        lines += ["", "What it can do:"] + [f"- It {c}." for c in can]
    other = [r for r in reasons if not r.startswith("Runs code or grants tools")
             and not (found and r.startswith("Threat patterns found"))]
    if other:
        lines += ([""] if result is not None else []) + [f"- {r}" for r in other]
    lines += ["", f"Folder name: {h['name']}", "",
              "Install puts it back where it was. Cancel keeps it held and deletes nothing.",
              "The folder name comes from whoever put it there, not from SkillCanary."
              + (" So do the file names and quoted lines." if found and snapshot else "")]
    if verdict == "UNSAFE":
        lines += ["", add.override_sentence(_phrase(h["name"]))]
    return "\n".join(lines)


def _phrase(name):
    """What the person types to put an unsafe skill back: its folder name,
    which whoever made the folder chose, so a blank name gets a fixed phrase."""
    return name if name.strip() else "install anyway"


def _short(path, home):
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def _notify(text):
    try:
        import subprocess
        subprocess.run(["osascript", "-e", "on run argv\ndisplay notification (item 1 of argv) "
                        "with title \"SkillCanary\"\nend run", "--", text],
                       capture_output=True, timeout=30)
    except Exception:
        pass


def restore(held_id, home=None, support=None, ask=None, backend="auto", model=None):
    """`canary restore <id>`: check again and ask the person; only their
    approval puts it back. (True, None), or (False, the line saying why not).
    An id the watcher holds takes that path; a replaced group's id goes to
    replace.restore (program 2026-10-17), which may return (True, a line)."""
    home = home or os.path.expanduser("~")
    w = Watcher.__new__(Watcher)
    w.home = home
    w.support = support or os.path.join(home, guestlist.SUPPORT[2:])
    # The command prints why it failed, so it sends no notification as well.
    w.ask, w.notify = ask or add.ask, lambda text: None
    w.backend, w.model = backend, model
    w.roots = guestlist.user_roots(home)
    if any(h["id"] == held_id for h in held(w.support, w.roots)):
        return w.review(held_id)
    from canary import replace
    if any(g["id"] == held_id for g in replace.groups(w.support, w.roots)):
        return replace.restore(held_id, home, w.support, w.ask, backend, model)
    raise ValueError(replace.NOT_KEEPING)


def drop_text(h, home):
    """The `canary drop` dialog."""
    day = (h.get("at") or "")[:10]
    folder = _short(os.path.dirname(h["origin"]), home)
    return "\n".join([
        "Delete the held copy of this skill?", "",
        f"Folder name: {h['name']}",
        f"Arrived in {folder} on {day}." if day else f"Arrived in {folder}.",
        "Another copy is in its place now." if os.path.lexists(h["origin"])
        else "Its place is free.", "",
        "Delete removes the copy SkillCanary is holding. This cannot be undone: to get it "
        "back, install the skill again from where it came. Nothing in your skills folders "
        "changes.",
        "Cancel keeps it held.",
        "The folder name comes from whoever put it there, not from SkillCanary."])


def drop(held_id, home=None, support=None, ask=None):
    """`canary drop <id>`: delete a held copy after the person says so in
    SkillCanary's dialog. (True, the line), or (False, the line saying why
    it stays held). A failed ledger write raises OSError and deletes nothing."""
    home = home or os.path.expanduser("~")
    support = support or os.path.join(home, guestlist.SUPPORT[2:])
    ask = ask or (lambda text, verdict: add.ask(text, verdict, yes="Delete"))
    roots = guestlist.user_roots(home)
    h = next((h for h in held(support, roots) if h["id"] == held_id), None)
    if h is None:
        from canary import replace
        if any(g["id"] == held_id for g in replace.groups(support, roots)):
            raise ValueError(NOT_A_HOLD.format(id=held_id))
        raise ValueError(replace.NOT_KEEPING)
    answer = ask(drop_text(h, home), "NEEDS_REVIEW")
    if answer is True:
        if _drop_hold(support, h, "person"):
            return True, DROPPED.format(name=h["name"])
        still = os.path.lexists(_held_path(support, h))
        return False, STILL_NOT_DROPPED if still else STILL_GONE
    return False, STILL_KEPT if answer is False else STILL_SILENT


def agent_path(which=shutil.which):
    """The PATH the launch agent runs with. launchd's own is minimal, so the
    folder that holds `claude` (the classifier `canary check` uses) is put
    first, as found when setup runs."""
    dirs = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    found = which("claude")
    if found:
        dirs.insert(0, os.path.dirname(found))
    return ":".join(dict.fromkeys(dirs))


def launch_agent_plist(canary_bin, support, path=None):
    """The launch agent setup installs, as the person."""
    args = "".join(f"<string>{_xml(a)}</string>" for a in
                   ("/usr/bin/python3", "-I", "-B", canary_bin, "watch"))
    log = _xml(os.path.join(support, "watcher.log"))
    path = _xml(path or agent_path())
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            f'  <key>Label</key><string>{LABEL}</string>\n'
            f'  <key>ProgramArguments</key><array>{args}</array>\n'
            '  <key>RunAtLoad</key><true/>\n'
            '  <key>KeepAlive</key><true/>\n'
            '  <key>ProcessType</key><string>Interactive</string>\n'
            f'  <key>EnvironmentVariables</key><dict><key>PATH</key><string>{path}</string></dict>\n'
            f'  <key>StandardErrorPath</key><string>{log}</string>\n'
            '</dict></plist>\n')


def _xml(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def plist_path(home):
    return os.path.join(home, "Library", "LaunchAgents", LABEL + ".plist")
