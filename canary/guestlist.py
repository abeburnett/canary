"""The guest list (docs/architecture.md, "The guest list"; program
2026-09-30, slice C).

SkillCanary records every skill that arrives in a skills folder, how it got
there, and every later change or removal, in an append-only ledger. It
reports two things, and only these:

- a skill that arrived without SkillCanary's check ("unchecked");
- a skill that came in through the check and has changed since it was
  approved ("changed since approval").

Skills present at setup's first look, and skills the person marks with
`canary trust`, are theirs: their changes are recorded, never reported.
Without a ledger, every skill counts as unchecked until setup or `canary
trust` says otherwise.

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
# A link inside a skill is followed, so a change to what it points at is a
# change to the skill. These bound how much one skill costs to fingerprint.
MAX_ENTRIES, MAX_BYTES = 5000, 64 << 20


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
    """{real path of each skill folder: [names]}. A skill folder is a folder
    (or a link to one) directly in a skills folder, holding a SKILL.md; one
    skill reached under several names lists them all."""
    found = {}
    for root in roots:
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for name in names:
            folder = os.path.join(root, name)
            if os.path.isfile(os.path.join(folder, "SKILL.md")):
                found.setdefault(os.path.realpath(folder), [])
                if name not in found[os.path.realpath(folder)]:
                    found[os.path.realpath(folder)].append(name)
    return {path: sorted(names) for path, names in found.items()}


def _walk(folder):
    """(relative path, path, lstat, stat) for everything in the skill except
    `.git`, following links (each folder once, so a loop ends), up to
    MAX_ENTRIES. stat is None when a link leads nowhere."""
    seen, stack, count = set(), [(folder, "")], 0
    while stack:
        directory, rel_dir = stack.pop()
        try:
            st = os.stat(directory)
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        if (st.st_dev, st.st_ino) in seen:
            continue
        seen.add((st.st_dev, st.st_ino))
        for name in names:
            if name == ".git":
                continue
            count += 1
            if count > MAX_ENTRIES:
                yield "\0too-many", None, None, None
                return
            path = os.path.join(directory, name)
            rel = os.path.join(rel_dir, name) if rel_dir else name
            try:
                lst = os.lstat(path)
            except OSError:
                continue
            try:
                full = os.stat(path) if stat.S_ISLNK(lst.st_mode) else lst
            except OSError:
                full = None
            yield rel, path, lst, full
            if full is not None and stat.S_ISDIR(full.st_mode):
                stack.append((path, rel))


def _quick_key(folder):
    """Names, sizes, times and inodes of everything in the skill, and of what
    its links point at. Cheap to read, and the change time (ctime) moves with
    every write; software cannot set it back."""
    rows = []
    for rel, _path, lst, full in _walk(folder):
        for st in (lst, full):
            rows.append(f"{rel}\0" + ("-" if st is None else
                        f"{st.st_size}\0{st.st_mtime_ns}\0{st.st_ctime_ns}\0{st.st_ino}\0{st.st_mode}"))
    return hashlib.sha256("\n".join(rows).encode("utf-8", "surrogateescape")).hexdigest()


def digest(folder):
    """A fingerprint of every file's bytes, path and program bit, without
    `.git`. A link is recorded with its target and followed, so a change to
    what it points at changes the fingerprint. Past MAX_ENTRIES files or
    MAX_BYTES read, the rest is left out and the fingerprint says so."""
    entries, budget = [], MAX_BYTES
    for rel, path, lst, full in _walk(folder):
        if path is None:
            entries.append("!\0too many files")
            break
        if stat.S_ISLNK(lst.st_mode):
            try:
                entries.append(f"l\0{rel}\0{os.readlink(path)}")
            except OSError:
                entries.append(f"?\0{rel}")
        if full is None:
            entries.append(f"?\0{rel}")
        elif stat.S_ISREG(full.st_mode):
            h, budget = hashlib.sha256(), budget - full.st_size
            if budget < 0:
                entries.append(f"!\0{rel}\0too large")
                break
            try:
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 16), b""):
                        h.update(chunk)
            except OSError:
                entries.append(f"?\0{rel}")
                continue
            entries.append(f"f\0{rel}\0{'x' if full.st_mode & 0o100 else '-'}\0{h.hexdigest()}")
        elif not stat.S_ISDIR(full.st_mode):
            entries.append(f"s\0{rel}")
    data = "skillcanary.guest.v2\n" + "\n".join(sorted(entries))
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
    skills, looked = {}, False
    for e in events:
        path, kind = e.get("skill"), e["event"]
        if kind == "first_look":
            looked = True
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
    return skills, looked


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


def scan(home=None, support=None, cwd=None, first_look=False):
    """Compare the skills folders with the ledger, record what is new,
    changed or gone, and return the report. Setup passes `first_look`: if
    the ledger has no first look yet, the skills here now are the person's.
    Any other scan counts a skill it has no record of as unchecked."""
    home = home or os.path.expanduser("~")
    support = _support(support) if support else os.path.join(home, SUPPORT[2:])
    present = _skills(user_roots(home) + repo_roots(cwd))
    # Fingerprint before taking the lock, so a large skill never holds up
    # another session's scan.
    os.makedirs(support, mode=0o700, exist_ok=True)
    cache = _read_cache(support)
    digests = {path: _cached_digest(path, cache) for path in present}
    with _Lock(support):
        events = _events(support)
        known, looked = _state(events)
        new, at = [], _now()
        baseline = first_look and not looked
        if baseline:
            new.append({"at": at, "event": "first_look"})
        for path, names in present.items():
            d, name = digests[path], names[0]
            s = known.get(path)
            if s is None:
                kind = "baseline" if baseline else "arrived"
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
    for path, names in sorted(present.items(), key=lambda kv: (kv[1], kv[0])):
        s = state.get(path, {})
        changed = s.get("status") == CHECKED and s.get("digest") != s.get("approved")
        for name in names:
            skills.append({"name": name, "names": names, "path": path,
                           "status": s.get("status", UNCHECKED),
                           "changed_since_approval": changed, "since": s.get("since")})
    from canary import watcher
    held = [{"id": h["id"], "name": h["name"], "origin": h["origin"], "since": h["at"],
             "restore": f"canary restore {h['id']}"} for h in watcher.held(support)]
    return {"schema": "canary.list/1", "skills": skills,
            "unchecked": [s for s in skills if s["status"] == UNCHECKED],
            "changed": [s for s in skills if s["changed_since_approval"]],
            "held": held}


def record_install(home, folders, name, verdict, support=None, source=None, how="canary add"):
    """Record the check and the approval of `folders`. With `source`, the
    checked copy they are about to be made from: SkillCanary records the
    approval before the files appear, so the watcher never holds its own
    installs. A failed install leaves an approval for a path that is not
    there, which the next scan records as removed."""
    support = _support(support) if support else os.path.join(home, SUPPORT[2:])
    at = _now()
    fixed = digest(source) if source else None
    with _Lock(support):
        events = [{"at": at, "event": "checked", "name": name, "verdict": verdict}]
        events += [{"at": at, "event": "approved", "how": how, "name": name,
                    "skill": os.path.realpath(f), "digest": fixed or digest(os.path.realpath(f))}
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
               else {p: names[0] for p, names in _skills([real]).items()})
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
    if report.get("held"):
        names = ", ".join(h["name"] for h in report["held"][:5])
        parts.append(f"{len(report['held'])} held for your decision ({names})")
    if not parts:
        return None
    return ("SkillCanary: " + "; ".join(parts) + ". Run canary list to see them; canary trust "
            "<folder> marks a skill as yours.")


def render_text(report):
    lines = []
    if report["skills"]:
        width = max(len(s["name"]) for s in report["skills"])
        for s in report["skills"]:
            status = "changed since approval" if s["changed_since_approval"] else s["status"]
            lines.append(f"{s['name']:<{width}}  {status:<22}  {s['path']}")
    else:
        lines.append("No skills found.")
    if report.get("held"):
        lines += ["", "Held by SkillCanary (arrived without its check; nothing is deleted):"]
        lines += [f"  {h['name']}  from {h['origin']}  to restore: {h['restore']}"
                  for h in report["held"]]
    return "\n".join(lines)
