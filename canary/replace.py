"""Replacing an installed skill (`--replace`), and putting a replaced copy back
(`canary restore <id>`). docs/architecture.md, "Replacing an installed
skill"; program 2026-10-17.

One file-level primitive, *set aside*: the copies at a run's destinations are
renamed into `quarantine/replaced/<id>/entry-<n>`, next to `replaced.json`,
which is written before any rename. A replace sets the old copies aside, then
runs the unchanged fresh-install path; a restore sets aside whatever is there
now, then puts the old copies back. Nothing here deletes an entry.

The ledger lock (`guestlist._Lock`) is never taken here: the ledger is written
only through `guestlist.record_install` and `guestlist.record_events`, which
take it themselves. Callers hold `add._Commit` around the moves.

Every rename of an entry goes through `_rename`, and every device read
through `_device`, so tests can inject faults without patching `os`.
"""

import json
import os
import re
import secrets
import shutil
import tempfile
import time

from canary import add, classify, explain, guestlist, watcher

SCHEMA = "canary.replaced/1"
RECORD = "replaced.json"
ENTRY = re.compile(r"entry-\d+")
WORST = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 1, "UNSAFE": 2}
SUFFIX = " canary list shows where it is."

PROJECT = ("--replace works only in your own skills folders (~/.claude/skills, "
           "~/.agents/skills), not in a project. Nothing was installed.")
BACK = "The earlier copy is back in place."
FIRST = "Another install got there first; nothing was installed."
NOT_KEEPING = ("SkillCanary is not holding or keeping anything with that id; canary list "
               "shows what it has.")
NOTHING_LEFT = "Still set aside: nothing of it is left in SkillCanary's store."
STILL_LINKS = ("Still set aside: it holds links or special files SkillCanary will not copy."
               + SUFFIX)
STILL_CANCELLED = "Still set aside: you chose not to put it back." + SUFFIX
STILL_SILENT = "Still set aside: nobody answered the SkillCanary dialog." + SUFFIX
STILL_FIRST = "Still set aside: another install got there first." + SUFFIX
STILL_CURRENT = "Still set aside: SkillCanary could not move the copy that is there now." + SUFFIX
STILL_NOT_MOVED = "Still set aside: SkillCanary could not move it back." + SUFFIX
STALE_LOCK = ("Put back where it was, but SkillCanary could not update its lock file; its "
              "record of this skill is stale until the next replace or restore.")


class SetAsideError(Exception):
    """A set-aside rename failed. `left` names the origins whose copy could
    not be renamed back, kept in group `group_id`; both are empty when every
    copy went back and the group was removed."""

    def __init__(self, group_id=None, left=()):
        super().__init__("set aside failed")
        self.group_id, self.left = group_id, list(left)


# ---- seams and small helpers -------------------------------------------------

def _rename(src, dst):
    os.rename(src, dst)


def _device(path):
    return os.stat(path).st_dev


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def store_dir(support):
    return os.path.join(support, "quarantine", "replaced")


def _norm(path):
    """How paths are compared: the parent resolved, the last part as it is,
    so a differently spelled home matches and a link is never collapsed onto
    its target folder."""
    return (os.path.realpath(os.path.dirname(path)), os.path.basename(path))


def _same(a, b):
    return _norm(a) == _norm(b)


def _date(rec):
    stamp = rec.get("installed_at") if isinstance(rec, dict) else None
    return stamp if isinstance(stamp, str) and add.DATE.match(stamp) else None


def _folders_first(members):
    return ([m for m in members if m["kind"] == "folder"]
            + [m for m in members if m["kind"] != "folder"])


def _remove_group(gdir):
    """Remove an emptied group: the record, then the folder, which `rmdir`
    refuses while any entry remains. Never `rmtree`."""
    try:
        os.unlink(os.path.join(gdir, RECORD))
        os.rmdir(gdir)
        return True
    except OSError:
        return False


# ---- sentences ------------------------------------------------------------

def changed_sentence(name):
    return (f"What is installed as {name} changed while you were deciding; nothing was "
            "changed. Run this again.")


def changed_after_check(group_id):
    return (f"Still set aside: it changed after its check; it stays set aside as {group_id}."
            + SUFFIX)


def set_aside_sentence(name):
    return f"SkillCanary could not set the earlier copy of {name} aside, so nothing was changed."


def undo_incomplete(name, left, group_id, home):
    return (f"SkillCanary could not put the earlier copy of {name} back at "
            f"{add._join(add._short(p, home) for p in left)}; it is kept as {group_id}. "
            f"canary restore {group_id} tries again.")


def restore_undo_incomplete(left, group_id, home):
    return ("Still set aside: SkillCanary could not move it back, and could not put the copy "
            f"that was there back at {add._join(add._short(p, home) for p in left)}; that copy "
            f"is kept as {group_id}." + SUFFIX)


def _different_disk(store, path, home):
    return (f"SkillCanary keeps replaced copies under {add._short(store, home)}, which is on a "
            f"different disk from {add._short(path, home)}")


# ---- the plan -------------------------------------------------------------

def _existing(destinations, home):
    """(reason, [(destination, "folder" | "link")]) for what is at the
    destinations now. A link must lead to another destination that is a
    folder holding SKILL.md; anything else that exists must be such a folder."""
    folders = [d for d in destinations if os.path.lexists(d) and not os.path.islink(d)
               and os.path.isdir(d) and os.path.isfile(os.path.join(d, "SKILL.md"))]
    existing = []
    for d in destinations:
        if not os.path.lexists(d):
            continue
        if os.path.islink(d):
            target = os.path.realpath(d)
            if not any(f != d and os.path.realpath(f) == target for f in folders):
                return (f"{add._short(d, home)} is a link to a folder this install would not "
                        "replace, so SkillCanary did not replace it. Nothing was installed."), None
            existing.append((d, "link"))
        elif d in folders:
            existing.append((d, "folder"))
        else:
            return (f"{add._short(d, home)} exists but holds no SKILL.md, so SkillCanary does "
                    "not know what it is and left it alone. Nothing was installed."), None
    return None, existing


def _preflight(existing, support):
    """The path whose parent is on another disk from the store, or None. The
    store is created first; OSError when it cannot be."""
    if not existing:
        return None
    store = store_dir(support)
    os.makedirs(store, mode=0o700, exist_ok=True)
    here = _device(store)
    for d, _ in existing:
        if _device(os.path.dirname(d)) != here:
            return d
    return None


def plan(lock, name, destinations, roots, home, support):
    """(reason, plan) for replacing `name` at `destinations`. `reason` is a
    refusal sentence, or None. The plan is {"existing": [(destination, kind)],
    "records": {key: record}, "paths": sorted existing destinations}; both
    empty means a fresh install. With `name=None` only the filesystem rules
    run (canary install, before its names are known)."""
    if any(os.path.realpath(os.path.dirname(d)) not in roots for d in destinations):
        return PROJECT, None
    reason, existing = _existing(destinations, home)
    if reason:
        return reason, None
    try:
        other_disk = _preflight(existing, support)
    except OSError:
        return set_aside_sentence(name or os.path.basename(destinations[0])), None
    if other_disk:
        return (_different_disk(store_dir(support), other_disk, home)
                + ", so it cannot set the old copy aside. Nothing was installed."), None
    records = {}
    if name is not None:
        mine = set(add.places_of(destinations))
        for key, rec in lock["skills"].items():
            if not add.is_live(rec):
                continue
            listed = [d for d in destinations if any(_same(d, p) for p in add.record_paths(rec))]
            other = add.record_name(key, rec)
            if other != name:
                if listed:
                    date = _date(rec)
                    return (f"{add._short(listed[0], home)} is recorded as the skill {other}"
                            + (f" (recorded {date[:10]})" if date else "")
                            + "; --replace replaces only a skill of the same name. Nothing was "
                              "installed."), None
                continue
            if listed or mine & set(add.record_places(rec)):
                records[key] = rec
        live = list(dict.fromkeys(p for rec in records.values() for p in add.record_paths(rec)
                                  if os.path.exists(p)))
        inside = [p for p in live if any(_same(p, d) for d in destinations)]
        if len(inside) != len(live):
            only = (f"only {add._join(add._short(p, home) for p in inside)}" if inside
                    else "none of them")
            return (f"A skill named {name} is installed at "
                    f"{add._join(add._short(p, home) for p in live)}; this run would replace "
                    f"{only}, so it replaced nothing. Replace all of them in one run."), None
    return None, {"existing": existing, "records": records,
                  "paths": sorted(d for d, _ in existing)}


def summary(plan_, home):
    """What the dialog says it replaces, or None for a fresh install."""
    if not plan_ or not plan_["existing"]:
        return None
    dates = sorted(d for d in (_date(r) for r in plan_["records"].values()) if d)
    return {"paths": [add._short(d, home) for d, _ in plan_["existing"]],
            "recorded": dates[-1][:10] if dates else None,
            "tracked": bool(plan_["records"])}


def ledger_states(support, paths):
    """{origin: the ledger's state for it, or None}, read without the ledger
    lock as the watcher reads it, looked up by the origin's real path (what
    record_install stores and the watcher reads)."""
    state, _ = guestlist._state(guestlist._events(support))
    out = {}
    for origin in paths:
        real = os.path.realpath(origin)
        s = state.get(real)
        out[origin] = None if s is None else {
            "path": real, "status": s.get("status"), "digest": s.get("digest"),
            "approved": s.get("approved"), "override": bool(s.get("override")),
            "origin": s.get("origin"), "since": s.get("since")}
    return out


# ---- set aside, put back, undo --------------------------------------------

def set_aside(support, name, how, plan_, states):
    """Rename every existing destination into a new group, after writing the
    group's record. The group (its record plus "dir"), or None for an empty
    plan. Raises SetAsideError when a rename fails, after renaming back what
    it moved."""
    if not plan_["existing"]:
        return None
    gid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
    gdir = os.path.join(store_dir(support), gid)
    members = [{"entry": f"entry-{n}", "origin": d, "kind": kind}
               for n, (d, kind) in enumerate(plan_["existing"])]
    record = {"schema": SCHEMA, "id": gid, "name": name, "at": _now(), "how": how,
              "members": members,
              "states": {m["origin"]: states.get(m["origin"]) for m in members
                         if m["kind"] == "folder"},
              "records": plan_["records"]}
    try:
        os.makedirs(gdir, mode=0o700)
    except OSError:
        raise SetAsideError() from None
    try:
        fd = os.open(os.path.join(gdir, RECORD),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")
    except OSError:
        _remove_group(gdir)
        raise SetAsideError() from None
    moved = []
    try:
        for m in members:
            _rename(m["origin"], os.path.join(gdir, m["entry"]))
            moved.append(m)
    except OSError:
        left = []
        for m in reversed(moved):
            try:
                _rename(os.path.join(gdir, m["entry"]), m["origin"])
            except OSError:
                left.append(m["origin"])
        if not left:
            _remove_group(gdir)
        raise SetAsideError(gid if left else None,
                            [m["origin"] for m in members if m["origin"] in left]) from None
    return dict(record, dir=gdir)


def put_back_files(support, group):
    """Rename each kept entry back to its origin (folders first). An origin
    that is no longer empty, or a rename that fails, leaves that entry in the
    store. Removes the group when every entry went back. Writes nothing to the
    ledger. Returns the origins left in the store."""
    gdir = group.get("dir") or os.path.join(store_dir(support), group["id"])
    left = []
    for m in _folders_first(group["members"]):
        entry = os.path.join(gdir, m["entry"])
        if not os.path.lexists(entry):
            continue
        if os.path.lexists(m["origin"]):
            left.append(m["origin"])
            continue
        try:
            _rename(entry, m["origin"])
        except OSError:
            left.append(m["origin"])
    if not left:
        _remove_group(gdir)
    return [m["origin"] for m in group["members"] if m["origin"] in left]


def _compensating(group, states, name):
    """The events that give each folder member back the ledger state it had
    when it was set aside (section 1.4)."""
    gdir = group.get("dir") or ""
    at, events = _now(), []
    for m in group["members"]:
        if m["kind"] != "folder":
            continue  # a link's target member gets the event
        s = states.get(m["origin"])
        path = s["path"] if s else os.path.realpath(m["origin"])
        status = s.get("status") if s else None
        if status == guestlist.CHECKED:
            events.append({"at": at, "event": "approved", "how": "replace undo", "name": name,
                           "skill": path, "digest": s.get("approved"),
                           **({"override": True} if s.get("override") else {}),
                           **({"origin": s["origin"]} if isinstance(s.get("origin"), dict)
                              else {})})
            if s.get("digest") != s.get("approved"):
                events.append({"at": at, "event": "changed", "skill": path, "name": name,
                               "digest": s.get("digest")})
        elif status == guestlist.YOURS:
            events.append({"at": at, "event": "trusted", "how": "replace undo", "name": name,
                           "skill": path, "digest": s.get("digest")})
        else:
            digest = s.get("digest") if s and s.get("digest") else \
                guestlist.digest(os.path.join(gdir, m["entry"]))
            events.append({"at": at, "event": "arrived", "how": "replace undo", "name": name,
                           "skill": path, "digest": digest})
    return events


def undo(home, support, group, states, name):
    """After the install or the lock write failed: compensating ledger events
    first, then the files back. Returns the origins left in the store."""
    if not group:
        return []
    events = _compensating(group, states, name)
    if events:
        add._record(guestlist.record_events, support, events)
    return put_back_files(support, group)


def record_replaced(support, group, how):
    """One `replaced` event per member of `group`."""
    at = _now()
    guestlist.record_events(support, [
        {"at": at, "event": "replaced", "id": group["id"], "name": group["name"],
         "skill": m["origin"], "kind": m["kind"], "how": how} for m in group["members"]])


# ---- the store, as canary list shows it -------------------------------------

def _load(support, gid, roots):
    """A group read from the store and validated, or None."""
    if not isinstance(gid, str) or not watcher.HOLD_ID.fullmatch(gid):
        return None
    gdir = os.path.join(store_dir(support), gid)
    try:
        with open(os.path.join(gdir, RECORD), encoding="utf-8") as fh:
            rec = json.load(fh)
    except (OSError, ValueError):
        return None
    if (not isinstance(rec, dict) or rec.get("schema") != SCHEMA or rec.get("id") != gid
            or not isinstance(rec.get("name"), str) or not add.NAME.fullmatch(rec["name"])
            or not isinstance(rec.get("at"), str) or not isinstance(rec.get("members"), list)):
        return None
    entries, origins = set(), set()
    for m in rec["members"]:
        if not isinstance(m, dict):
            return None
        origin, entry, kind = m.get("origin"), m.get("entry"), m.get("kind")
        if (not isinstance(origin, str) or not os.path.isabs(origin)
                or os.path.basename(origin) in ("", ".", "..")
                or os.path.realpath(os.path.dirname(origin)) not in roots
                or not isinstance(entry, str) or not ENTRY.fullmatch(entry)
                or kind not in ("folder", "link") or entry in entries or origin in origins):
            return None
        entries.add(entry)
        origins.add(origin)
    states = rec.get("states") if isinstance(rec.get("states"), dict) else {}
    records = rec.get("records") if isinstance(rec.get("records"), dict) else {}
    return dict(rec, dir=gdir, states=states, records=records,
                how=rec.get("how") if isinstance(rec.get("how"), str) else None)


def _kept(group):
    return [m for m in group["members"]
            if os.path.lexists(os.path.join(group["dir"], m["entry"]))]


def groups(support, roots):
    """What replaces set aside, read from the store itself (each group's own
    record), never from the ledger, oldest first. A group whose record does
    not validate is not listed."""
    try:
        ids = sorted(os.listdir(store_dir(support)))
    except OSError:
        return []
    out = []
    for gid in ids:
        g = _load(support, gid, roots)
        if g is None:
            continue
        out.append({"id": gid, "name": g["name"], "paths": [m["origin"] for m in g["members"]],
                    "kept": [m["origin"] for m in _kept(g)], "at": g["at"], "how": g["how"],
                    "restore": f"canary restore {gid}"})
    return out


# ---- canary restore <id> for a replaced group --------------------------------

def current_plan(lock, origins, roots, home, support):
    """(reason, plan) for setting aside what is at a group's origins now. Unlike
    `plan` it has no name rule, and it finds every lock record listing an
    origin, live or not."""
    existing = []
    for o in origins:
        if not os.path.lexists(o):
            continue
        if os.path.islink(o):
            target = os.path.realpath(o)
            if any(p != o and os.path.realpath(p) == target for p in origins):
                existing.append((o, "link"))
                continue
        elif os.path.isdir(o) and os.path.isfile(os.path.join(o, "SKILL.md")):
            existing.append((o, "folder"))
            continue
        return (f"Still set aside: something SkillCanary does not move is at "
                f"{add._short(o, home)}." + SUFFIX), None
    records = {}
    for key, rec in lock["skills"].items():
        paths = add.record_paths(rec)
        ours = [p for p in paths if any(_same(p, o) for o in origins)]
        if not ours:
            continue
        others = [p for p in paths if p not in ours]
        if others:
            return (f"Still set aside: the copy at {add._short(ours[0], home)} is also "
                    f"installed at {add._join(add._short(p, home) for p in others)}; replace "
                    "all of them in one run first." + SUFFIX), None
        records[key] = rec
    try:
        other_disk = _preflight(existing, support)
    except OSError:
        return STILL_CURRENT, None
    if other_disk:
        return ("Still set aside: " + _different_disk(store_dir(support), other_disk, home)
                + ", so it cannot set the copy that is there now aside." + SUFFIX), None
    return None, {"existing": existing, "records": records,
                  "paths": sorted(d for d, _ in existing)}


def dialog_text(group, checked, home):
    """The restore dialog: the worst member's check leads."""
    name = group["name"]
    _, snap, result = max(checked, key=lambda c: WORST.get(c[2]["verdict"], 2))
    verdict = result["verdict"]
    word = {"LIKELY_SAFE": "no problems found",
            "NEEDS_REVIEW": "needs your judgment"}.get(verdict, verdict)
    lines = [f"Put back the earlier {name} you replaced on {group['at'][:10]}?", "",
             f"SkillCanary checked that earlier copy again: {word}.", "",
             result["recommendation"]["text"]]
    if result["headline"] != explain.GENERIC_HEADLINE:
        lines += ["", result["headline"]]
    found = add.found_block({"_snapshot": snap, "risks": result["risks"]})
    if found:
        lines += [""] + found
    can = sorted({add.PLAIN[c["kind"]] for _, _, r in checked
                  for c in r["scan"]["capabilities"] if c["kind"] in add.PLAIN})
    if can:
        lines += ["", "What it can do:"] + [f"- It {c}." for c in can]
    lines += ["", "Folders: " + ", ".join(add._short(m["origin"], home) for m in _kept(group)),
              "",
              "Install puts it back. The copy there now is set aside the same way, so you can "
              "switch again. Cancel keeps it set aside; nothing is deleted.",
              "The folder names come from the packages, not from SkillCanary."
              + (" So do the file names and quoted lines." if found and snap else "")]
    if verdict == "UNSAFE":
        lines += ["", add.override_sentence(name)]
    return "\n".join(lines)


def restore(group_id, home, support, ask, backend="auto", model=None):
    """Check the kept copies again and ask the person; only their yes puts them
    back. (True, line or None), or (False, the line saying why not)."""
    roots = guestlist.user_roots(home)
    group = _load(support, group_id, roots)
    if group is None:
        raise ValueError(NOT_KEEPING)
    name = group["name"]
    kept = _kept(group)
    folders = [m for m in kept if m["kind"] == "folder"]
    if not folders:
        return False, NOTHING_LEFT
    work = tempfile.mkdtemp(prefix="canary-replaced-")
    try:
        checked, checked_digests = [], {}
        for n, m in enumerate(folders):
            snap = os.path.join(work, str(n))
            try:
                add._copy_local(os.path.join(group["dir"], m["entry"]), snap)
                checked_digests[m["entry"]] = add.tree_digest(snap)
                result = classify.check(snap, backend=backend, model=model,
                                        log_dir=os.path.join(support, "quarantine", "logs"))
            except (add.SourceError, OSError):
                add._record(guestlist.record_decision, home, name, "UNSAFE", "refused",
                            support=support)
                return False, STILL_LINKS
            checked.append((m, snap, result))
        verdict = max((r["verdict"] for _, _, r in checked), key=lambda v: WORST.get(v, 2))
        text = dialog_text(group, checked, home)
        answer = ask(text, verdict, confirm=name) if verdict == "UNSAFE" else ask(text, verdict)
        if answer is not True:
            if verdict == "UNSAFE":
                add._record(guestlist.record_decision, home, name, verdict, "refused",
                            support=support)
            return False, STILL_CANCELLED if answer is False else STILL_SILENT
        with add._Commit(home):
            return _restore_committed(group, kept, checked, checked_digests, home, support,
                                      roots)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _unchanged(gdir, checked_digests):
    """True when every folder member's store entry still has the tree digest
    of the copy that was checked (the automated review's TOCTOU finding: an
    entry could change between the check and the rename, as watcher.put_back
    guards against)."""
    try:
        return all(add.tree_digest(os.path.join(gdir, entry)) == digest
                   for entry, digest in checked_digests.items())
    except (add.SourceError, OSError):
        return False


def _restore_committed(group, kept, checked, checked_digests, home, support, roots):
    """Section 4, step 4, under the commit lock."""
    name, gdir = group["name"], group["dir"]
    again = _load(support, group["id"], roots)
    if again is None or any(not os.path.lexists(os.path.join(gdir, m["entry"])) for m in kept):
        return False, NOTHING_LEFT
    # Only what was checked goes back: before anything moves or is recorded.
    if not _unchanged(gdir, checked_digests):
        return False, changed_after_check(group["id"])
    origins = [m["origin"] for m in kept]
    lock = add._read_lock(home)
    reason, current = current_plan(lock, origins, roots, home, support)
    if reason:
        return False, reason
    for key in current["records"]:
        del lock["skills"][key]
    keys = {}
    for key, rec in group["records"].items():
        if not isinstance(rec, dict):
            continue
        if key not in lock["skills"] or not add.is_live(lock["skills"][key]):
            chosen = key
        else:
            chosen = add.choose_key(lock, add.record_name(key, rec), add.record_places(rec))
        if chosen is None or chosen in keys.values():
            return False, STILL_FIRST
        keys[key] = chosen
    states = ledger_states(support, [o for o, kind in current["existing"] if kind == "folder"])
    try:
        g2 = set_aside(support, name, "restore", current, states)
    except SetAsideError as exc:
        if exc.left:
            return False, restore_undo_incomplete(exc.left, exc.group_id, home)
        return False, STILL_CURRENT
    # Approval first, one call per folder member with its own verdict, so the
    # watcher leaves each copy alone once it is back.
    for m, snap, result in checked:
        old = group["states"].get(m["origin"])
        origin = (old["origin"] if isinstance(old, dict) and old.get("status") == guestlist.CHECKED
                  and isinstance(old.get("origin"), dict) else {"kind": "watcher"})
        add._record(guestlist.record_install, home, [m["origin"]], name, result["verdict"],
                    support=support, source=snap, how="restore",
                    override=(result["verdict"] == "UNSAFE"), origin=origin)
    moved = []
    try:
        for m in _folders_first(kept):
            _rename(os.path.join(gdir, m["entry"]), m["origin"])
            moved.append(m)
    except OSError:
        for m in reversed(moved):
            try:
                _rename(m["origin"], os.path.join(gdir, m["entry"]))
            except OSError:
                pass
        left = undo(home, support, g2, states, name)
        if left:
            return False, restore_undo_incomplete(left, g2["id"], home)
        return False, STILL_NOT_MOVED
    for key, rec in group["records"].items():
        if key not in keys:
            continue
        back = {k: v for k, v in rec.items() if k != "replaced"}
        if g2:
            back["replaced"] = g2["id"]
        lock["skills"][keys[key]] = back
    try:
        add._write_lock(home, lock)
    except OSError:
        if g2:
            add._record(record_replaced, support, g2, "restore")
        return True, STALE_LOCK
    if g2:
        add._record(record_replaced, support, g2, "restore")
    add._record(guestlist.record_events, support,
                [{"at": _now(), "event": "restored", "id": group["id"]}])
    _remove_group(gdir)
    return True, (f"Put back where it was; the copy that was there is set aside as {g2['id']}."
                  if g2 else None)
