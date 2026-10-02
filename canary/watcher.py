"""The watcher (docs/architecture.md, "The watcher"; program 2026-09-30, slice
B2): a launch agent that holds a new, unchecked skill until the person
decides.

It watches the person's Claude Code and Codex skills folders. When a new
entry appears there and stops changing, and it is a skill SkillCanary has no
approval for, the watcher moves it into the quarantine ("holds" it), checks
it, and asks the person once. Approval puts it back where it was, if it
still matches what was checked; anything else leaves it held, and `canary
list` shows how to restore it. Nothing is deleted.

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

from canary import add, classify, frontdoor, guestlist

LABEL = "com.skillcanary.watcher"
SETTLE_SECONDS = 2.0
# An entry that keeps changing is held after this long anyway.
MAX_WAIT_SECONDS = 30.0
POLL_SECONDS = 2.0
SEEN = "watcher-seen.json"
HOLD_ID = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}")


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
        with guestlist._Lock(support):
            guestlist._append(support, events)
    except OSError:
        pass


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
            if _approved(path, self.support) or _is_frontdoor(path):
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
        """Check a held entry and ask the person. True when it went back."""
        h = next((h for h in held(self.support, self.roots) if h["id"] == held_id), None)
        if h is None:
            return False
        entry = _held_path(self.support, h)
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
                verdict, reasons, caps = "UNSAFE", ["It holds links or special files "
                                                    "SkillCanary will not copy."], []
            if verdict == "UNSAFE":
                _decision(self, h["name"], verdict, "refused")
                self.notify(f"SkillCanary is holding {h['name']}, which arrived in "
                            f"{_short(os.path.dirname(h['origin']), self.home)} without its "
                            "check: it judged it unsafe. canary list shows where it is.")
                return False
            answer = self.ask(dialog_text(h, verdict, reasons, caps, self.home), verdict)
            if answer is True:
                return self.put_back(h, snap, verdict)
            _decision(self, h["name"], verdict, "declined" if answer is False else "not_installed")
            return False
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
                return False
            if os.path.lexists(origin):
                self.notify(f"SkillCanary could not put {h['name']} back: something else is "
                            "there now. It stays held; canary list shows where.")
                return False
            # The approval names where the entry will resolve once it is back.
            resolved = origin if not os.path.islink(entry) else _resolved(entry, origin)
            guestlist.record_install(self.home, [resolved], h["name"], verdict,
                                     support=self.support, source=snap, how="watcher")
            os.rename(entry, origin)
        except OSError:
            self.notify(f"SkillCanary could not put {h['name']} back. It stays held; "
                        "canary list shows where.")
            return False
        shutil.rmtree(os.path.dirname(entry), ignore_errors=True)
        _record(self.support, [{"at": _now(), "event": "restored", "id": h["id"]}])
        return True

    def run(self, stop=None):
        """The launch agent's loop: kqueue on the skills folders, with a look
        every couple of seconds for folders that appear later."""
        threading.Thread(target=self._review_loop, daemon=True).start()
        while not (stop and stop.is_set()):
            self._wait()
            self.tick(time.monotonic())

    def _review_loop(self):
        for h in held(self.support, self.roots):
            self.reviews.put(h["id"])  # ones left from before a restart
        while True:
            held_id = self.reviews.get()
            try:
                self.review(held_id)
            except Exception:
                pass  # a held skill stays held; the next restart asks again

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


def dialog_text(h, verdict, reasons, caps, home):
    word = {"LIKELY_SAFE": "no problems found",
            "NEEDS_REVIEW": "needs your judgment"}.get(verdict, verdict)
    lines = [f"A skill appeared in {_short(os.path.dirname(h['origin']), home)} without "
             "SkillCanary's check, so SkillCanary is holding it.", "",
             f"SkillCanary checked it: {word}."]
    can = sorted({add.PLAIN[k] for k in caps if k in add.PLAIN})
    if can:
        lines += ["", "What it can do:"] + [f"- It {c}." for c in can]
    other = [r for r in reasons if not r.startswith("Runs code or grants tools")]
    lines += [f"- {r}" for r in other]
    lines += ["", f"Folder name: {h['name']}", "",
              "Install puts it back where it was. Cancel keeps it held; nothing is deleted.",
              "The folder name comes from whoever put it there, not from SkillCanary."]
    return "\n".join(lines)


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
    approval puts it back."""
    home = home or os.path.expanduser("~")
    w = Watcher.__new__(Watcher)
    w.home = home
    w.support = support or os.path.join(home, guestlist.SUPPORT[2:])
    w.ask, w.notify = ask or add.ask, _notify
    w.backend, w.model = backend, model
    w.roots = guestlist.user_roots(home)
    if not any(h["id"] == held_id for h in held(w.support, w.roots)):
        raise ValueError("SkillCanary is not holding anything with that id; canary list "
                         "shows what it holds.")
    return w.review(held_id)


def launch_agent_plist(canary_bin, support):
    """The launch agent setup installs, as the person."""
    args = "".join(f"<string>{_xml(a)}</string>" for a in
                   ("/usr/bin/python3", "-I", "-B", canary_bin, "watch"))
    log = _xml(os.path.join(support, "watcher.log"))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0"><dict>\n'
            f'  <key>Label</key><string>{LABEL}</string>\n'
            f'  <key>ProgramArguments</key><array>{args}</array>\n'
            '  <key>RunAtLoad</key><true/>\n'
            '  <key>KeepAlive</key><true/>\n'
            '  <key>ProcessType</key><string>Interactive</string>\n'
            f'  <key>StandardErrorPath</key><string>{log}</string>\n'
            '</dict></plist>\n')


def _xml(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def plist_path(home):
    return os.path.join(home, "Library", "LaunchAgents", LABEL + ".plist")
