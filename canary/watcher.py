"""The watcher (docs/architecture.md, "The watcher"; program 2026-09-30, slice
B2): a launch agent that holds a new, unchecked skill until the person
decides.

It watches the person's Claude Code and Codex skills folders. When a new
entry appears there and stops changing, and it is a skill SkillCanary has no
approval for, the watcher moves it into the quarantine ("holds" it), checks
it, and asks the person once. Approval puts it back where it was; anything
else leaves it held, and `canary list` shows how to restore it. Nothing is
deleted.

What it leaves alone: everything present when it starts, changes to skills
already there, SkillCanary's own installs (they record their approval before
the files appear), and SkillCanary's own skill. Skills inside repositories
are the guest list's to report. Anything that arrives while the watcher is
not running is reported at the next session start, not held.
"""

import json
import os
import queue
import secrets
import select
import shutil
import tempfile
import threading
import time

from canary import add, classify, frontdoor, guestlist

LABEL = "com.skillcanary.watcher"
SETTLE_SECONDS = 2.0
# A new folder with no SKILL.md yet is watched this long before it is let go.
PENDING_SECONDS = 600.0
POLL_SECONDS = 2.0


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


def held(support):
    """Entries the watcher is holding: [{id, name, origin, at}], oldest first."""
    out = {}
    for e in guestlist._events(support):
        if e["event"] == "held" and isinstance(e.get("id"), str):
            out[e["id"]] = {"id": e["id"], "name": e.get("name"), "origin": e.get("origin"),
                            "at": e.get("at")}
        elif e["event"] == "restored":
            out.pop(e.get("id"), None)
    return [h for h in out.values() if os.path.lexists(_held_path(support, h))]


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
    with guestlist._Lock(support):
        guestlist._append(support, events)


class Watcher:
    """`step(now)` notices, settles and holds; `review(id)` checks and asks.
    The loop runs reviews on their own thread, so holding never waits for a
    dialog."""

    def __init__(self, home, support=None, *, ask=None, notify=None, backend="auto",
                 model=None, settle=SETTLE_SECONDS, pending=PENDING_SECONDS):
        self.home = home
        self.support = support or os.path.join(home, guestlist.SUPPORT[2:])
        self.ask = ask or add.ask
        self.notify = notify or _notify
        self.backend, self.model = backend, model
        self.settle, self.pending_limit = settle, pending
        self.roots = guestlist.user_roots(home)
        self.seen = {r: self._list(r) for r in self.roots}
        self.pending = {}  # path -> {"first", "key", "changed"}
        self.reviews = queue.Queue()

    @staticmethod
    def _list(root):
        try:
            return set(os.listdir(root))
        except OSError:
            return set()

    def step(self, now):
        """Look once: note new entries, and hold the ones that have settled.
        Returns the ids held in this step."""
        for root in self.roots:
            names = self._list(root)
            for name in names - self.seen[root]:
                if not name.startswith(".canary-staging-"):
                    path = os.path.join(root, name)
                    self.pending[path] = {"first": now, "key": _key(path), "changed": now}
            self.seen[root] = names
        done = []
        for path, p in list(self.pending.items()):
            key = _key(path)
            if key is None:
                del self.pending[path]  # gone again
                continue
            if key != p["key"]:
                p["key"], p["changed"] = key, now
                continue
            if now - p["changed"] < self.settle:
                continue
            if not os.path.isfile(os.path.join(path, "SKILL.md")):
                if now - p["first"] > self.pending_limit:
                    del self.pending[path]
                continue
            del self.pending[path]
            # Read after the wait: SkillCanary's installs record approval first.
            if _approved(path, self.support) or _is_frontdoor(path):
                continue
            # A link into another watched folder (an installer's
            # ~/.claude/skills/x -> ~/.agents/skills/x) follows its target:
            # the target is the one held or approved.
            if os.path.islink(path) and os.path.dirname(os.path.realpath(path)) in self.roots:
                continue
            held_id = self.hold(path)
            if held_id:
                done.append(held_id)
        return done

    def hold(self, path):
        """Move the entry (a folder, or a link) into the quarantine."""
        held_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
        slot = os.path.join(held_dir(self.support), held_id)
        try:
            os.makedirs(slot, mode=0o700)
            os.rename(path, os.path.join(slot, "entry"))
        except OSError:
            shutil.rmtree(slot, ignore_errors=True)
            return None
        _record(self.support, [{"at": _now(), "event": "held", "id": held_id,
                                "name": os.path.basename(path), "origin": path}])
        self.reviews.put(held_id)
        return held_id

    def review(self, held_id):
        """Check a held entry and ask the person. True when it went back."""
        h = next((h for h in held(self.support) if h["id"] == held_id), None)
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
                guestlist.record_decision(self.home, h["name"], verdict, "refused",
                                          support=self.support)
                self.notify(f"SkillCanary is holding {h['name']}, which arrived in "
                            f"{_short(os.path.dirname(h['origin']), self.home)} without its "
                            "check: it judged it unsafe. canary list shows where it is.")
                return False
            answer = self.ask(dialog_text(h, verdict, reasons, caps, self.home), verdict)
            if answer is True:
                return self.put_back(h, snap, verdict)
            guestlist.record_decision(self.home, h["name"], verdict,
                                      "declined" if answer is False else "not_installed",
                                      support=self.support)
            return False
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def put_back(self, h, snap, verdict):
        """Approval first, then the move back, if the place is still free."""
        origin, entry = h["origin"], _held_path(self.support, h)
        if os.path.lexists(origin):
            self.notify(f"SkillCanary could not put {h['name']} back: something else is "
                        f"there now. It stays held; canary list shows where.")
            return False
        # The approval names where the entry will resolve once it is back.
        resolved = origin if not os.path.islink(entry) else _resolved(entry, origin)
        guestlist.record_install(self.home, [resolved], h["name"], verdict,
                                 support=self.support, source=snap, how="watcher")
        os.rename(entry, origin)
        shutil.rmtree(os.path.dirname(entry), ignore_errors=True)
        _record(self.support, [{"at": _now(), "event": "restored", "id": h["id"]}])
        return True

    def run(self, stop=None):
        """The launch agent's loop: kqueue on the skills folders, with a poll
        every couple of seconds for folders that appear later."""
        threading.Thread(target=self._review_loop, daemon=True).start()
        while not (stop and stop.is_set()):
            self._wait()
            self.step(time.monotonic())

    def _review_loop(self):
        for held_id in held(self.support):
            self.reviews.put(held_id["id"])  # ones left from before a restart
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
    except (OSError, Exception):
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
    if not any(h["id"] == held_id for h in held(w.support)):
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
