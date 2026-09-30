"""`canary edit`: the sanctioned way to change an installed skill
(docs/architecture.md, "canary edit"; docs/program-2026-09-28-skill-edits.md).

The agent copies a skill into a draft, edits the draft with ordinary tools,
and asks SkillCanary to apply it. SkillCanary snapshots the draft, compares
it with the installed skill file by file, scans only the change, and asks
the person once, unless a root-owned allowance the person created with their
password covers a text change. It writes only the changed files.

Everything in the draft folder, including edit.json, is written by the
agent: targets are re-validated here, and the recorded starting point only
detects a conflicting edit; it never grants anything.
"""

import base64
import difflib
import fnmatch
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time

from canary import add, classify, scan, setup

SCHEMA = "canary.edit/1"
ALLOW_SCHEMA = "canary.allow/1"
DRAFTS = os.path.join("~", ".skillcanary", "drafts")
ALLOW_FILE = "allowances.json"
EXIT_FOR_OUTCOME = {"started": 0, "applied": 0, "unchanged": 0, "allowed": 0, "revoked": 0,
                    "declined": 10, "not_applied": 10, "conflict": 10, "refused": 20}
MAX_DAYS, DEFAULT_DAYS = 30, 7
MAX_ADDED_LINES, MAX_ADDED_BYTES = 200, 16 * 1024
URL = re.compile(r"(?i)\b(?:https?|ftp|file)://|\bwww\.")
SHELL_FENCE = re.compile(r"^\s*(```|~~~)\s*(!|sh|bash|zsh|shell|console|fish|ksh)\b", re.I)
FRONTMATTER = re.compile(rb"\A(?:\xef\xbb\xbf)?---\r?\n.*?\r?\n---(?:\r?\n|\Z)", re.S)


class EditError(Exception):
    """Safe to show the agent: carries no skill text."""


# ---- skill folders ---------------------------------------------------------

def _is_skill_folder(real):
    """A real folder directly inside a skills folder the hook protects: any
    repository's `.claude/skills`, `.agents/skills` or `.codex/skills`, or a
    host's user skills folder (which may live under CODEX_HOME)."""
    if not (os.path.isdir(real) and not os.path.islink(real)
            and os.path.basename(os.path.dirname(real)) == "skills"
            and os.path.isfile(os.path.join(real, "SKILL.md"))):
        return False
    from canary import gate
    home = os.path.expanduser("~")
    roots = {os.path.realpath(m.install_root(home)) for _, m, _ in add.HOSTS.values()}
    roots.add(os.path.realpath(os.path.join(add.HOSTS["codex"][1]._codex_home(home), "skills")))
    return gate._in_any_skills_folder(real) or os.path.dirname(real) in roots


def resolve(target, home, cwd):
    """(name, [real skill folders]). A name finds every copy in the user skill
    folders; a path names one folder in any skills folder."""
    if "/" not in target and add.NAME.fullmatch(target):
        found = []
        for _, module, _ in add.HOSTS.values():
            candidate = os.path.join(module.install_root(home), target)
            if os.path.lexists(candidate):
                real = os.path.realpath(candidate)
                if not _is_skill_folder(real):
                    raise EditError("That skill is not a folder SkillCanary can edit.")
                found.append(real)
        if not found:
            raise EditError("No installed skill has that name; pass its folder instead.")
        return target, list(dict.fromkeys(found))
    real = os.path.realpath(os.path.join(cwd, os.path.expanduser(target)))
    if not _is_skill_folder(real):
        raise EditError("That is not a skill folder inside a skills folder. Skills outside "
                        "the protected folders can be edited directly.")
    return os.path.basename(real), [real]


def tree(root):
    """{relative path: (sha256, executable)} for every file, without .git.
    Links and special files raise EditError."""
    files = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                raise EditError("The skill contains links or special files; SkillCanary "
                                "cannot edit it.")
            if stat.S_ISREG(st.st_mode):
                h = hashlib.sha256()
                fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 16), b""):
                        h.update(chunk)
                files[os.path.relpath(p, root)] = (h.hexdigest(), bool(st.st_mode & 0o100))
    return files


def _copy(src, dest):
    try:
        add._copy_local(src, dest)
    except add.SourceError as exc:
        raise EditError(str(exc)) from None


# ---- start -----------------------------------------------------------------

def start(target, *, home=None, cwd=None, drafts=None):
    home = home or os.path.expanduser("~")
    cwd = cwd or os.getcwd()
    name, targets = resolve(target, home, cwd)
    trees = [tree(t) for t in targets]
    if any(t != trees[0] for t in trees[1:]):
        raise EditError("The copies of this skill differ; pass the folder you want to edit.")
    drafts = drafts or os.path.expanduser(DRAFTS)
    folder = os.path.join(drafts, f"{name}-{time.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}")
    os.makedirs(folder, mode=0o700)
    _copy(targets[0], os.path.join(folder, "skill"))
    record = {"schema": SCHEMA, "name": name, "targets": targets,
              "base": {rel: list(v) for rel, v in trees[0].items()}}
    with open(os.path.join(folder, "edit.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)
    return {"schema": SCHEMA, "outcome": "started", "name": name,
            "draft": os.path.join(folder, "skill"),
            "reasons": ["Edit the files in the draft, then run canary edit apply with the "
                        "draft folder. The person approves the change."]}


def _load(draft):
    draft = os.path.realpath(draft)
    folder = os.path.dirname(draft) if os.path.basename(draft) == "skill" else draft
    try:
        with open(os.path.join(folder, "edit.json"), encoding="utf-8") as fh:
            record = json.load(fh)
        assert record["schema"] == SCHEMA
        targets = [os.path.realpath(t) for t in record["targets"]]
        base = {rel: (v[0], bool(v[1])) for rel, v in record["base"].items()}
        name = record["name"]
    except (OSError, ValueError, KeyError, TypeError, AssertionError, IndexError):
        raise EditError("That is not a draft from canary edit start.") from None
    if not targets or not all(_is_skill_folder(t) for t in targets):
        raise EditError("The draft points at a folder that is not an installed skill.")
    # edit.json is the agent's file: the name the person sees comes from the
    # folder actually being changed.
    name = os.path.basename(targets[0])
    return folder, name, list(dict.fromkeys(targets)), base


# ---- the change ------------------------------------------------------------

def _read(root, rel):
    fd = os.open(os.path.join(root, rel), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


def _frontmatter(data):
    m = FRONTMATTER.match(data)
    return m.group(0) if m else b""


def _capabilities(root):
    """{relative path: {capability kinds that block auto-approval}}, and the
    paths the scanner could not read as text."""
    result = scan.scan_package(root, excerpts=True, exclude=[".git"])
    caps = {}
    for c in result["capabilities"]:
        if c["kind"] in scan.REVIEW_CAPABILITIES:
            caps.setdefault(c["path"], set()).add(c["kind"])
    unread = {s["path"] for s in result["coverage"]["skipped"]}
    return caps, unread


def _added_lines(old, new):
    old_lines = old.decode("utf-8", "replace").splitlines()
    new_lines = new.decode("utf-8", "replace").splitlines()
    return [line[1:] for line in difflib.unified_diff(old_lines, new_lines, lineterm="", n=0)
            if line.startswith("+") and not line.startswith("+++")]


def classify_change(installed, snapshot, before, after):
    """(changes, kind, added capability kinds). kind is "text" or "code"."""
    changes = {"added": sorted(set(after) - set(before)),
               "removed": sorted(set(before) - set(after)),
               "changed": sorted(r for r in set(before) & set(after) if before[r] != after[r])}
    touched = changes["added"] + changes["removed"] + changes["changed"]
    old_caps, old_unread = _capabilities(installed)
    new_caps, new_unread = _capabilities(snapshot)
    code = False
    for rel in touched:
        if old_caps.get(rel) or new_caps.get(rel) or rel in old_unread or rel in new_unread:
            code = True
        if rel in before and rel in after and before[rel][1] != after[rel][1]:
            code = True
    if "SKILL.md" in changes["changed"] and (
            _frontmatter(_read(installed, "SKILL.md")) != _frontmatter(_read(snapshot, "SKILL.md"))):
        code = True
    added_kinds = set()
    for rel, kinds in new_caps.items():
        added_kinds |= kinds - old_caps.get(rel, set())
    if added_kinds:
        code = True
    return changes, ("code" if code else "text"), sorted(added_kinds)


def _change_package(snapshot, rels, dest):
    os.makedirs(dest)
    for rel in rels:
        os.makedirs(os.path.join(dest, os.path.dirname(rel)), exist_ok=True)
        shutil.copy2(os.path.join(snapshot, rel), os.path.join(dest, rel), follow_symlinks=False)
    return dest


# ---- allowances ------------------------------------------------------------

def _allow_path(prefix):
    return setup._at(prefix, setup.LIB + "/" + ALLOW_FILE)


def _root_owned(path, uid):
    st = os.lstat(path)
    return st.st_uid == uid and not st.st_mode & 0o022


def read_allowances(prefix="/", uid=0, now=None):
    """Unexpired allowances from the root-owned file; [] for anything else.
    A file or folder the person's account could change grants nothing."""
    path = _allow_path(prefix)
    try:
        st = os.lstat(path)
        if (not stat.S_ISREG(st.st_mode) or not _root_owned(path, uid)
                or not _root_owned(os.path.dirname(path), uid)):
            return []
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["schema"] == ALLOW_SCHEMA
        now = now or time.time()
        return [a for a in data["allowances"]
                if isinstance(a, dict) and _valid_pattern(a.get("pattern"))
                and isinstance(a.get("skill"), str) and isinstance(a.get("expires"), (int, float))
                and a["expires"] > now]
    except (OSError, ValueError, KeyError, TypeError, AssertionError):
        return []


def _valid_pattern(pattern):
    """Relative, no `..`, matches only .md files and never SKILL.md."""
    if not isinstance(pattern, str) or not pattern or pattern.startswith("/") or "\\" in pattern:
        return False
    parts = pattern.split("/")
    if any(p in ("", ".", "..") or "**" in p for p in parts):
        return False
    last = parts[-1]
    return last.endswith(".md") and not fnmatch.fnmatchcase("SKILL.md", last)


def _matches(rel, pattern):
    """Segment by segment, so `*` never crosses a folder."""
    rp, pp = rel.split("/"), pattern.split("/")
    return len(rp) == len(pp) and all(fnmatch.fnmatchcase(r, p) for r, p in zip(rp, pp))


def _allowance_covers(allowances, targets, changes, kind, check_result, texts):
    """None when an allowance covers this change, else the reason it does not."""
    if kind != "text":
        return "it changes more than text"
    if changes["added"] or changes["removed"]:
        return "it adds or removes files"
    for rel in changes["changed"]:
        if rel == "SKILL.md" or os.path.basename(rel) == "SKILL.md" or not rel.endswith(".md"):
            return "it changes a file allowances never cover"
        if not all(any(a["skill"] == t and _matches(rel, a["pattern"]) for a in allowances)
                   for t in targets):
            return "no allowance covers every changed file"
    if check_result["verdict"] != "LIKELY_SAFE" or check_result["classifier"]["status"] != "ok":
        return "the change's scan was not clean, or the classifier did not run"
    added = [line for lines in texts.values() for line in lines]
    if len(added) > MAX_ADDED_LINES or sum(len(x.encode()) + 1 for x in added) > MAX_ADDED_BYTES:
        return "the change is larger than an allowance covers"
    if any(URL.search(x) or SHELL_FENCE.match(x) for x in added):
        return "the change adds a link or a shell block"
    return None


def _admin_allowances(prefix, allowances):
    q = shlex.quote
    path = _allow_path(prefix)
    data = base64.b64encode(json.dumps({"schema": ALLOW_SCHEMA, "allowances": allowances},
                                       indent=2).encode()).decode("ascii")
    return "\n".join(["set -eu", "umask 022",
                      f"printf %s {q(data)} | /usr/bin/base64 -D > {q(path + '.new')}",
                      f"chmod 644 {q(path + '.new')}", f"mv {q(path + '.new')} {q(path)}"]) + "\n"


def _require_guard(prefix):
    level = (setup.read_state(prefix) or {}).get("level")
    if level != "guard":
        raise EditError("Allowances work at Guard only: at Scan nothing blocks an edit, and "
                        "at Lockdown every edit asks for the password.")


def allow(target, pattern, days=DEFAULT_DAYS, *, home=None, cwd=None, prefix="/",
          approve=None, admin=None, uid=0, now=None):
    home = home or os.path.expanduser("~")
    _require_guard(prefix)
    if not _valid_pattern(pattern):
        raise EditError("The pattern must be a relative path to .md files other than SKILL.md, "
                        "such as references/lessons-*.md.")
    if not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        raise EditError(f"Allowances last 1 to {MAX_DAYS} days.")
    name, targets = resolve(target, home, cwd or os.getcwd())
    now = now or time.time()
    expires = now + days * 86400
    summary = {"kind": "allow", "name": name, "targets": targets, "pattern": pattern,
               "expires": expires}
    if (approve or dialog)(summary) is not True:
        return {"schema": SCHEMA, "outcome": "declined", "name": name,
                "reasons": ["The person did not approve the allowance."]}
    current = [a for a in read_allowances(prefix, uid, now)
               if not (a["pattern"] == pattern and a["skill"] in targets)]
    current += [{"skill": t, "pattern": pattern, "expires": expires, "created": now}
                for t in targets]
    if not (admin or setup.run_as_admin)(_admin_allowances(prefix, current)):
        return {"schema": SCHEMA, "outcome": "not_applied", "name": name,
                "reasons": ["The password step was declined; no allowance was created."]}
    return {"schema": SCHEMA, "outcome": "allowed", "name": name, "pattern": pattern,
            "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires)),
            "reasons": ["Text changes to matching files now apply without a dialog until "
                        "the allowance expires. Code, SKILL.md and new files still ask."]}


def revoke(target, pattern, *, home=None, cwd=None, prefix="/", admin=None, uid=0):
    home = home or os.path.expanduser("~")
    name, targets = resolve(target, home, cwd or os.getcwd())
    keep = [a for a in read_allowances(prefix, uid)
            if not (a["pattern"] == pattern and a["skill"] in targets)]
    if not (admin or setup.run_as_admin)(_admin_allowances(prefix, keep)):
        return {"schema": SCHEMA, "outcome": "not_applied", "name": name,
                "reasons": ["The password step was declined; the allowance stays."]}
    return {"schema": SCHEMA, "outcome": "revoked", "name": name, "reasons": []}


def list_allowances(prefix="/", uid=0):
    return {"schema": SCHEMA, "allowances": [
        {"skill": a["skill"], "pattern": a["pattern"],
         "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(a["expires"]))}
        for a in read_allowances(prefix, uid)]}


# ---- the person's approval -------------------------------------------------

def dialog_text(summary):
    if summary["kind"] == "allow":
        until = time.strftime("%Y-%m-%d %H:%M", time.localtime(summary["expires"]))
        return "\n".join([
            f"Let agents change files matching {summary['pattern']} in the skill "
            f"{summary['name']} without asking you, until {until}?", "",
            "Each change is still scanned. Changes to SKILL.md, code, settings, and new or "
            "removed files still ask you. You will get a notification after each change.", "",
            "Folders: " + ", ".join(summary["targets"]), "",
            "Next, macOS asks for your password to record the allowance."])
    verdict = {"LIKELY_SAFE": "no problems found in the change",
               "NEEDS_REVIEW": "the change needs your judgment"}.get(summary["verdict"],
                                                                      summary["verdict"])
    lines = [f"An agent wants to change the skill {summary['name']}.",
             f"SkillCanary checked the change: {verdict}.", ""]
    if summary["kind_of_change"] == "code":
        lines += ["This change can make the skill run code, use tools or change when it "
                  "loads. Read it before you apply it."]
        can = sorted({add.PLAIN[k] for k in summary["added"] if k in add.PLAIN})
        lines += [f"- It now {c}." for c in can] + [""]
    for key, label in (("changed", "Changes"), ("added", "Adds"), ("removed", "Removes")):
        names = summary["changes"][key]
        if names:
            shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
            lines.append(f"{label}: {shown}")
    lines += ["", f"Lines added: {summary['lines_added']}",
              f"The full change: {summary['diff']}",
              "Folders: " + ", ".join(summary["targets"]), "",
              "File names come from the skill, not from SkillCanary."]
    return "\n".join(lines)


DIALOG_SCRIPT = """on run argv
  set theText to item 1 of argv
  if item 2 of argv is "review" then
    set r to display dialog theText with title "SkillCanary" buttons {"Apply anyway", "Cancel"} default button "Cancel" cancel button "Cancel" with icon caution giving up after (item 3 of argv as integer)
  else
    set r to display dialog theText with title "SkillCanary" buttons {"Cancel", "Apply"} default button "Apply" cancel button "Cancel" giving up after (item 3 of argv as integer)
  end if
  if gave up of r then return "timeout"
  return button returned of r
end run"""


def dialog(summary):
    """True to go ahead, False when the person cancels, None when nobody answered."""
    if sys.platform != "darwin" or not shutil.which("osascript"):
        return None
    review = summary["kind"] == "allow" or summary.get("kind_of_change") == "code" \
        or summary.get("verdict") != "LIKELY_SAFE"
    try:
        proc = subprocess.run(["osascript", "-e", DIALOG_SCRIPT, "--", dialog_text(summary),
                               "review" if review else "safe", str(add.DIALOG_SECONDS)],
                              capture_output=True, text=True, timeout=add.DIALOG_SECONDS + 30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return False if "-128" in proc.stderr else None
    return {"Apply": True, "Apply anyway": True}.get(proc.stdout.strip())


def notify(message):
    if sys.platform == "darwin" and shutil.which("osascript"):
        subprocess.run(["osascript", "-e", "on run argv\ndisplay notification (item 1 of argv) "
                        "with title \"SkillCanary\"\nend run", "--", message],
                       capture_output=True, timeout=30)


# ---- writing ---------------------------------------------------------------

def _write_file(target, rel, snapshot, sha, executable):
    dest = os.path.join(target, rel)
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    if not os.path.realpath(parent).startswith(os.path.realpath(target) + os.sep) and \
            os.path.realpath(parent) != os.path.realpath(target):
        raise EditError("The skill changed shape during the edit.")
    tmp = os.path.join(parent, f".canary-edit-{secrets.token_hex(4)}")
    data = _read(snapshot, rel)
    if hashlib.sha256(data).hexdigest() != sha:
        raise EditError("The draft changed after it was checked.")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o755 if executable else 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise


def _admin_apply(targets, changes, snapshot, after, run_id, owner):
    """Lockdown: stage each file in a root-owned folder inside the skill,
    confirm its SHA-256 there, then move it into place, in one step."""
    q = shlex.quote
    stages = [os.path.join(t, f".canary-edit-{run_id}") for t in targets]
    lines = ["set -eu", "umask 022", "cleanup() { rm -rf " + " ".join(q(s) for s in stages) + "; }",
             "trap cleanup EXIT"]
    for target, stage in zip(targets, stages):
        lines.append(f"mkdir {q(stage)}")
        for i, rel in enumerate(changes["added"] + changes["changed"]):
            sha, executable = after[rel]
            staged = os.path.join(stage, str(i))
            lines += [f"cp {q(os.path.join(snapshot, rel))} {q(staged)}",
                      f"chown {q(owner)} {q(staged)}",
                      f"chmod {'755' if executable else '644'} {q(staged)}",
                      f"[ \"$(/usr/bin/shasum -a 256 < {q(staged)} | cut -d ' ' -f 1)\" = {q(sha)} ]"]
    for target, stage in zip(targets, stages):
        for i, rel in enumerate(changes["added"] + changes["changed"]):
            dest = os.path.join(target, rel)
            lines += [f"mkdir -p {q(os.path.dirname(dest))}",
                      f"mv {q(os.path.join(stage, str(i)))} {q(dest)}"]
        lines += [f"rm -f {q(os.path.join(target, rel))}" for rel in changes["removed"]]
    return "\n".join(lines) + "\n"


def _update_lock(home, targets, digest):
    lock = add._read_lock(home)
    changed = False
    for entry in lock["skills"].values():
        installed = [os.path.realpath(p) for p in entry.get("installed", [])]
        if any(t in installed for t in targets):
            entry["package_digest"] = digest
            entry["edited_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            changed = True
    if changed:
        add._write_lock(home, lock)


def _log(support, entry):
    os.makedirs(support, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(support, "edits.jsonl"),
                 os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


# ---- apply -----------------------------------------------------------------

def apply(draft, *, home=None, support_dir=None, approve=None, admin=None, notifier=None,
          backend="auto", model=None, timeout_s=classify.DEFAULT_TIMEOUT_S, prefix="/",
          admin_owner="root:wheel", uid=0):
    """Scan the draft's change, get it approved, write it. Returns a
    canary.edit/1 result; raises EditError for a draft it cannot use."""
    home = home or os.path.expanduser("~")
    support = support_dir or add.SUPPORT_DIR
    folder, name, targets, base = _load(draft)
    out = {"schema": SCHEMA, "outcome": None, "name": name, "class": None, "verdict": None,
           "route": None, "changes": None, "reasons": []}
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
    run = os.path.join(support, "edits", run_id)
    os.makedirs(run, mode=0o700)
    snapshot = os.path.join(run, "new")
    # A private copy: the agent cannot change it while the person decides.
    _copy(os.path.join(folder, "skill"), snapshot)
    if not os.path.isfile(os.path.join(snapshot, "SKILL.md")):
        raise EditError("The draft has no SKILL.md; a skill needs one.")
    after = tree(snapshot)
    before = tree(targets[0])
    if any(tree(t) != before for t in targets[1:]) or before != base:
        out["outcome"] = "conflict"
        out["reasons"].append("The installed skill changed since canary edit start; start "
                              "again from the current version.")
        return out
    changes, kind, added_kinds = classify_change(targets[0], snapshot, before, after)
    out["class"], out["changes"] = kind, changes
    if not any(changes.values()):
        out["outcome"] = "unchanged"
        out["reasons"].append("The draft is the same as the installed skill.")
        return out

    texts, diff = {}, []
    for rel in changes["added"] + changes["changed"]:
        old = _read(targets[0], rel) if rel in before else b""
        new = _read(snapshot, rel)
        texts[rel] = _added_lines(old, new)
        diff += difflib.unified_diff(old.decode("utf-8", "replace").splitlines(),
                                     new.decode("utf-8", "replace").splitlines(),
                                     f"a/{rel}", f"b/{rel}", lineterm="")
    for rel in changes["removed"]:
        diff.append(f"removed: {rel}")
    diff_path = os.path.join(run, "change.diff")
    with open(diff_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(diff) + "\n")

    rels = changes["added"] + changes["changed"]
    if rels:
        result = classify.check(_change_package(snapshot, rels, os.path.join(run, "change")),
                                backend=backend, model=model, timeout_s=timeout_s,
                                log_dir=os.path.join(support, "logs"))
    else:  # only removals: nothing new to read
        result = {"verdict": "LIKELY_SAFE", "classifier": {"status": "ok"}, "reasons": [],
                  "package_digest": None}
    out["verdict"] = result["verdict"]
    out["reasons"] += list(result["reasons"])
    if result["verdict"] == "UNSAFE":
        out["outcome"] = "refused"
        out["reasons"].append("Not applied: SkillCanary judged the change unsafe.")
        return out

    level = (setup.read_state(prefix) or {}).get("level")
    why_not = "allowances apply at Guard only"
    if level == "guard":
        why_not = _allowance_covers(read_allowances(prefix, uid), targets, changes, kind,
                                    result, texts)
    if why_not is None:
        out["route"] = "allowance"
    else:
        summary = {"kind": "edit", "name": name, "targets": targets, "changes": changes,
                   "kind_of_change": kind, "added": added_kinds, "verdict": result["verdict"],
                   "lines_added": sum(len(v) for v in texts.values()), "diff": diff_path}
        answer = (approve or dialog)(summary)
        if answer is not True:
            out["outcome"] = "declined" if answer is False else "not_applied"
            out["reasons"].append(
                "The person declined the change; the draft is kept." if answer is False else
                "Nobody approved it on the Mac's screen. The draft is kept; the person can "
                f"run canary edit apply {os.path.join(folder, 'skill')} themselves.")
            return out
        out["route"] = "dialog"

    with add._Commit(home):
        # Re-check inside the lock, right before writing.
        if any(tree(t) != base for t in targets) or tree(snapshot) != after:
            out["outcome"] = "conflict"
            out["reasons"].append("The skill or the draft changed while waiting; nothing "
                                  "was written.")
            return out
        previous = os.path.join(run, "previous")
        for rel in changes["changed"] + changes["removed"]:
            os.makedirs(os.path.join(previous, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(previous, rel), "wb") as fh:
                fh.write(_read(targets[0], rel))
        if level == "lockdown":
            out["route"] = "admin"
            script = _admin_apply(targets, changes, snapshot, after, run_id, admin_owner)
            if not (admin or setup.run_as_admin)(script):
                out["outcome"] = "not_applied"
                out["reasons"].append("The password step was declined, or a staged file did "
                                      "not match what was checked; nothing was written.")
                return out
        else:
            for target in targets:
                for rel in changes["added"] + changes["changed"]:
                    _write_file(target, rel, snapshot, *after[rel])
                for rel in changes["removed"]:
                    os.unlink(os.path.join(target, rel))
        _update_lock(home, targets, scan.scan_package(targets[0], exclude=[".git"])["package_digest"])
    _log(support, {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "run": run_id,
                   "skill": name, "targets": targets, "class": kind, "route": out["route"],
                   "verdict": result["verdict"], "changes": changes,
                   "before": {r: before[r][0] for r in changes["changed"] + changes["removed"]},
                   "after": {r: after[r][0] for r in changes["added"] + changes["changed"]}})
    if out["route"] == "allowance":
        (notifier or notify)(f"Applied an agent's change to {name} under your allowance: "
                             + ", ".join(changes["changed"]))
    shutil.rmtree(folder, ignore_errors=True)
    out["outcome"] = "applied"
    return out


def render_text(out):
    lines = [f"SkillCanary edit: {out['outcome']}"]
    for key in ("name", "draft", "class", "verdict", "route"):
        if out.get(key):
            lines.append(f"{key.capitalize()}: {out[key]}")
    lines += [f"  - {r}" for r in out.get("reasons", [])]
    return "\n".join(lines)
