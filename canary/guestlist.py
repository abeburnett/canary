"""The guest list (docs/architecture.md, "The guest list"; program
2026-09-30, slice C).

SkillCanary records every skill that arrives in a skills folder, how it got
there, and every later change or removal, in an append-only ledger. It
reports two things, and only these:

- a skill that arrived without SkillCanary's check ("unchecked");
- a skill that came in through the check and has changed since it was
  approved ("changed since approval").

Skills present the first time SkillCanary looks, and skills the person marks
with `canary trust`, are theirs: their changes are recorded, never reported.

This is a report, not proof: the ledger lives in the person's account, and
software running as them can change it.
"""

import fcntl
import hashlib
import json
import os
import stat
import time

from canary.hosts import claude as claude_host
from canary.hosts import codex as codex_host

SUPPORT = os.path.join("~", "Library", "Application Support", "Canary")
LEDGER = "ledger.jsonl"
CACHE = "guestlist-cache.json"
REPO_ROOTS = (".claude/skills", ".agents/skills", ".codex/skills")
YOURS, CHECKED, UNCHECKED = "yours", "checked", "unchecked"


def _support(support):
    return os.path.expanduser(support or SUPPORT)


def user_roots(home):
    roots = [claude_host.install_root(home), codex_host.install_root(home)]
    try:
        roots += codex_host.extra_skill_roots(home)
    except ValueError:
        pass
    return list(dict.fromkeys(os.path.realpath(r) for r in roots))


def repo_roots(cwd):
    """The skills folders of the repository around `cwd`, up to its root."""
    if not cwd or not os.path.isabs(cwd):
        return []
    folders, current = [], os.path.realpath(cwd)
    while True:
        folders += [os.path.join(current, rel) for rel in REPO_ROOTS]
        if os.path.exists(os.path.join(current, ".git")) or current == os.path.dirname(current):
            break
        current = os.path.dirname(current)
    return [f for f in folders if os.path.isdir(f)]


def _skills(roots):
    """{real path of each skill folder: name}. A skill folder is a folder (or
    a link to one) directly in a skills folder, holding a SKILL.md."""
    found = {}
    for root in roots:
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            folder = os.path.join(root, name)
            if os.path.isfile(os.path.join(folder, "SKILL.md")):
                found.setdefault(os.path.realpath(folder), name)
    return found


def _quick_key(folder):
    """Names, sizes and modification times of everything in the skill: cheap
    to read, and it changes whenever the content can have."""
    rows = []
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames) + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            rows.append(f"{os.path.relpath(path, folder)}\0{st.st_size}\0{st.st_mtime_ns}\0{st.st_mode}")
    return hashlib.sha256("\n".join(rows).encode("utf-8", "surrogateescape")).hexdigest()


def digest(folder):
    """A fingerprint of every file's bytes, path and program bit (and each
    link's target), without `.git`. Links are recorded, never followed."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames) + sorted(dirnames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, folder)
            try:
                st = os.lstat(path)
            except OSError:
                entries.append(f"?\0{rel}")
                continue
            if stat.S_ISLNK(st.st_mode):
                entries.append(f"l\0{rel}\0{os.readlink(path)}")
            elif stat.S_ISREG(st.st_mode):
                h = hashlib.sha256()
                try:
                    with open(path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(1 << 16), b""):
                            h.update(chunk)
                except OSError:
                    entries.append(f"?\0{rel}")
                    continue
                entries.append(f"f\0{rel}\0{'x' if st.st_mode & 0o100 else '-'}\0{h.hexdigest()}")
            elif not stat.S_ISDIR(st.st_mode):
                entries.append(f"s\0{rel}")
    data = "skillcanary.guest.v1\n" + "\n".join(sorted(entries))
    return "sha256:" + hashlib.sha256(data.encode("utf-8", "surrogateescape")).hexdigest()


class _Lock:
    def __init__(self, support):
        self.path = os.path.join(support, "ledger.lock")

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def _events(support):
    try:
        with open(os.path.join(support, LEDGER), encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue  # a damaged line is skipped, never fatal
        if isinstance(e, dict) and isinstance(e.get("event"), str):
            out.append(e)
    return out


def _append(support, events):
    os.makedirs(support, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(support, LEDGER), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, sort_keys=True) + "\n")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _state(events):
    """Replay the ledger: {skill path: {status, digest, approved, name, since}}."""
    skills, started = {}, False
    for e in events:
        path, kind = e.get("skill"), e["event"]
        if kind == "started":
            started = True
        if not isinstance(path, str):
            continue
        s = skills.get(path)
        if kind in ("baseline", "trusted"):
            skills[path] = {"status": YOURS, "digest": e.get("digest"), "approved": None,
                            "name": e.get("name"), "since": e.get("at")}
        elif kind == "approved":
            skills[path] = {"status": CHECKED, "digest": e.get("digest"),
                            "approved": e.get("digest"), "name": e.get("name"), "since": e.get("at")}
        elif kind == "arrived":
            skills[path] = {"status": UNCHECKED, "digest": e.get("digest"), "approved": None,
                            "name": e.get("name"), "since": e.get("at")}
        elif kind == "changed" and s:
            s["digest"] = e.get("digest")
        elif kind == "removed":
            skills.pop(path, None)
    return skills, started


def _cached_digest(folder, cache):
    key = _quick_key(folder)
    entry = cache.get(folder)
    if isinstance(entry, dict) and entry.get("key") == key and isinstance(entry.get("digest"), str):
        return entry["digest"]
    value = digest(folder)
    cache[folder] = {"key": key, "digest": value}
    return value


def _read_cache(support):
    try:
        with open(os.path.join(support, CACHE), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_cache(support, cache):
    tmp = os.path.join(support, CACHE + f".{os.getpid()}")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cache, fh)
    os.replace(tmp, os.path.join(support, CACHE))


def scan(home=None, support=None, cwd=None):
    """Compare the skills folders with the ledger, record what is new,
    changed or gone, and return the report."""
    home = home or os.path.expanduser("~")
    support = _support(support) if support else os.path.join(home, SUPPORT[2:])
    with _Lock(support):
        events = _events(support)
        known, started = _state(events)
        present = _skills(user_roots(home) + repo_roots(cwd))
        cache = _read_cache(support)
        new, at = [], _now()
        if not started:
            new.append({"at": at, "event": "started"})
        for path, name in present.items():
            d = _cached_digest(path, cache)
            s = known.get(path)
            if s is None:
                # On the very first look, what is already here is the person's.
                kind = "baseline" if not started else "arrived"
                new.append({"at": at, "event": kind, "skill": path, "name": name, "digest": d,
                            **({"how": "found"} if kind == "arrived" else {})})
            elif s.get("digest") != d:
                new.append({"at": at, "event": "changed", "skill": path, "name": name, "digest": d})
        for path, s in known.items():
            if path not in present:
                new.append({"at": at, "event": "removed", "skill": path, "name": s.get("name")})
        if new:
            _append(support, new)
        _write_cache(support, cache)
        state, _ = _state(events + new)
    skills = []
    for path, name in sorted(present.items(), key=lambda kv: (kv[1], kv[0])):
        s = state.get(path, {})
        changed = s.get("status") == CHECKED and s.get("digest") != s.get("approved")
        skills.append({"name": name, "path": path, "status": s.get("status", UNCHECKED),
                       "changed_since_approval": changed, "since": s.get("since")})
    return {"schema": "canary.list/1", "skills": skills,
            "unchecked": [s for s in skills if s["status"] == UNCHECKED],
            "changed": [s for s in skills if s["changed_since_approval"]]}


def record_install(home, folders, name, verdict, support=None):
    """`canary add` installed `folders`: record the check and the approval."""
    support = _support(support) if support else os.path.join(home, SUPPORT[2:])
    at = _now()
    with _Lock(support):
        events = [{"at": at, "event": "checked", "name": name, "verdict": verdict}]
        events += [{"at": at, "event": "approved", "how": "canary add", "name": name,
                    "skill": os.path.realpath(f), "digest": digest(os.path.realpath(f))}
                   for f in folders]
        _append(support, events)


def record_decision(home, name, verdict, outcome, support=None):
    """`canary add` checked a skill that was not installed."""
    support = _support(support) if support else os.path.join(home, SUPPORT[2:])
    with _Lock(support):
        _append(support, [{"at": _now(), "event": "checked", "name": name, "verdict": verdict},
                          {"at": _now(), "event": outcome, "name": name}])


def trust(folder, home=None, support=None):
    """Mark a skill folder, or every skill in a skills folder, as the person's."""
    home = home or os.path.expanduser("~")
    support = _support(support) if support else os.path.join(home, SUPPORT[2:])
    real = os.path.realpath(folder)
    targets = ({real: os.path.basename(real)} if os.path.isfile(os.path.join(real, "SKILL.md"))
               else _skills([real]))
    if not targets:
        raise ValueError("That is neither a skill folder nor a folder of skills.")
    at = _now()
    with _Lock(support):
        _append(support, [{"at": at, "event": "trusted", "skill": p, "name": n, "digest": digest(p)}
                          for p, n in targets.items()])
    return sorted(targets.values())


def session_line(report):
    """One sentence when something needs a look, else None."""
    parts = []
    if report["unchecked"]:
        names = ", ".join(s["name"] for s in report["unchecked"][:5])
        more = len(report["unchecked"]) - 5
        parts.append(f"{len(report['unchecked'])} skill(s) arrived without SkillCanary's check "
                     f"({names}{f' and {more} more' if more > 0 else ''})")
    if report["changed"]:
        names = ", ".join(s["name"] for s in report["changed"][:5])
        parts.append(f"{len(report['changed'])} changed since you approved them ({names})")
    if not parts:
        return None
    return ("SkillCanary: " + "; ".join(parts) + ". Run canary list to see them; canary trust "
            "<folder> marks a skill as yours.")


def render_text(report):
    if not report["skills"]:
        return "No skills found."
    width = max(len(s["name"]) for s in report["skills"])
    lines = []
    for s in report["skills"]:
        status = "changed since approval" if s["changed_since_approval"] else s["status"]
        lines.append(f"{s['name']:<{width}}  {status:<22}  {s['path']}")
    return "\n".join(lines)
