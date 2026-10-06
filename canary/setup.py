"""`canary setup` and `canary doctor` (docs/architecture.md).

Everything privileged happens in one shell script that travels as a string
to the macOS administrator dialog, with Canary's files inside it as a
checksummed archive, so nothing on disk can be swapped while the person types
their password. `prefix` and `owner` exist so tests can run the real script
in a temporary folder as the current user.
"""

import base64
import hashlib
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import tarfile
import time

from canary import frontdoor
from canary.hosts import claude as claude_host
from canary.hosts import codex as codex_host

LEVELS = ("scan", "guard")
# Lockdown was removed in the front-door program (2026-09-30). A recorded
# Lockdown level is still read, so setup can return the skill folders.
RECORDED_LEVELS = LEVELS + ("lockdown",)
# macOS keeps every folder on this path root-owned, so no user account can
# swap the install. 0.1.0 used usr/local/lib, which old Homebrew installs
# leave owned by the person.
LIB = "Library/Application Support/SkillCanary"
OLD_LIBS = ("usr/local/lib/skillcanary",)
LINK = "usr/local/bin/canary"
PYTHON = "/usr/bin/python3"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLAIMS = {
    "scan": "Scans skills when asked. Nothing is enforced.",
    "guard": "Guards installs by agents in Claude Code and Codex.",
}
LEVEL_TEXT = {
    "scan": "Scan: check skills when you ask. No password, nothing enforced.",
    "guard": "Guard (recommended): block agents from installing skills any way but "
             "canary add. Password once.",
}


def _at(prefix, path):
    return os.path.join(prefix, path.lstrip("/"))


def hook_command(prefix, host):
    """-I ignores PYTHONPATH and user site-packages, so an agent's
    environment cannot change what the hook runs."""
    return f"{PYTHON} -I -B {shlex.quote(_at(prefix, LIB + '/bin/canary'))} hook --host {host}"


def lock_roots(home):
    return [claude_host.install_root(home), codex_host.install_root(home)]


def _payload():
    """Canary's own files as a gzip tar, and its SHA-256."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in ["bin/canary"] + sorted(
                os.path.relpath(os.path.join(d, f), PACKAGE_ROOT)
                for d, _, fs in os.walk(os.path.join(PACKAGE_ROOT, "canary"))
                for f in fs if f.endswith(".py")):
            info = tar.gettarinfo(os.path.join(PACKAGE_ROOT, rel), arcname=rel)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if rel == "bin/canary" else 0o644
            with open(os.path.join(PACKAGE_ROOT, rel), "rb") as fh:
                tar.addfile(info, fh)
    data = buf.getvalue()
    return base64.b64encode(data).decode("ascii"), hashlib.sha256(data).hexdigest()


def _sha_file(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def _state_at(prefix, lib):
    try:
        with open(_at(prefix, lib + "/state.json"), encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return None
    return state if isinstance(state, dict) and state.get("level") in RECORDED_LEVELS else None


def _raw_state(prefix):
    """The level string in the root-owned state file, whatever it is, or None."""
    try:
        with open(_at(prefix, LIB + "/state.json"), encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return None
    return state.get("level") if isinstance(state, dict) else None


def read_state(prefix="/"):
    """This Mac's recorded level: the root-owned install's state, else a 0.1.0
    state from a folder the person may control (a hint only; see plan)."""
    for lib in (LIB,) + OLD_LIBS:
        state = _state_at(prefix, lib)
        if state:
            return state
    return None


def _policies(prefix):
    """The only files setup ever writes or removes: {path: (content now,
    contents an earlier SkillCanary wrote)}."""
    out = {}
    for host, adapter in (("claude", claude_host), ("codex", codex_host)):
        for planned in adapter.managed_install_plan(_at(prefix, LIB + "/bin/canary")):
            target = _at(prefix, planned.path)
            earlier = set()
            for old in OLD_LIBS:
                for was in adapter.managed_install_plan(_at(prefix, old + "/bin/canary")):
                    if _at(prefix, was.path) == target:
                        earlier.add(was.content)
            out[target] = (planned.content, earlier)
    return out


MISSING = object()


def _read(path):
    """The file's text; MISSING only when nothing is there. An unreadable or
    undecodable file returns None, which is never treated as missing."""
    if not os.path.lexists(path):
        return MISSING
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def plan(level, home, prefix="/"):
    """What the privileged script must do to move this Mac to `level`.

    Nothing read from disk authorizes a root operation by itself: setup only
    touches the two policy files and the two skill roots it knows, rewrites
    or removes a policy file only when its content is exactly what this or an
    earlier SkillCanary writes (or its hash is recorded in the root-owned
    state), and leaves anything else as a manual step."""
    trusted = _state_at(prefix, LIB) or {}
    hint = read_state(prefix) or {"level": "scan"}
    recorded = trusted.get("created") if isinstance(trusted.get("created"), dict) else {}
    files, remove, manual, created = [], [], [], {}
    for target, (content, earlier) in _policies(prefix).items():
        now = _read(target)
        known = isinstance(now, str)
        sha = hashlib.sha256(now.encode()).hexdigest() if known else None
        ours = known and (now == content or now in earlier or (
            isinstance(recorded.get(target), str) and recorded[target] == sha))
        if level == "scan":
            if ours:
                remove.append(target)
        elif now is MISSING or ours:
            if now != content:
                files.append({"path": target, "content": content})
            created[target] = hashlib.sha256(content.encode()).hexdigest()
        else:
            manual.append({"path": target, "block": content})
    roots = lock_roots(home)
    return {"level": level, "files": files, "remove": remove, "manual": manual,
            "frontdoor": frontdoor.targets(home, roots),
            # Only the root-owned state may start a root operation; a Lockdown
            # level in 0.1.0's user-controlled state is a hint and unlocks nothing.
            "unlock": roots if trusted.get("level") == "lockdown" else [],
            "home": home,
            "state": {"level": level, "created": created,
                      "locked": [],
                      "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}


def _open_dirs(path, create_under=None, person=None):
    """An fd for the folder at `path`, opened from / one component at a time
    without following links. Missing components below `create_under` are
    created owned by `person` (uid, gid). Raises OSError on a link."""
    parts = [c for c in os.path.abspath(path).split("/") if c]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    walked = "/"
    try:
        for part in parts:
            walked = os.path.join(walked, part)
            try:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if create_under is None or not walked.startswith(create_under.rstrip("/") + "/"):
                    raise
                os.mkdir(part, 0o755, dir_fd=fd)
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                if person:
                    os.fchown(nfd, *person)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _ids(spec):
    import grp
    import pwd
    user, _, group = spec.partition(":")
    uid = int(user) if user.isdigit() else pwd.getpwnam(user).pw_uid
    gid = int(group) if group.isdigit() else grp.getgrnam(group).gr_gid
    return uid, gid


def change_roots(action, owner, person, home, roots):
    """Return each skill root to the person (Lockdown, removed 2026-09-30, made
    them root-owned) through folder handles, never following links. A root
    reached through a link is skipped. Runs as root inside the privileged
    step, from the root-owned install. `action` must be "unlock"."""
    if action != "unlock":
        raise ValueError("SkillCanary no longer locks skill folders")
    known = {os.path.normpath(r) for r in lock_roots(home)}
    if not roots or any(os.path.normpath(r) not in known for r in roots):
        raise ValueError("Only the two user skill folders can be returned")
    uid, gid = _ids(person)
    skipped = []
    for root in roots:
        try:
            fd = _open_dirs(root)
        except FileNotFoundError:
            continue
        except OSError:
            skipped.append(root)
            continue
        try:
            # Bottom up: a folder becomes the person's only after everything in
            # it, so nothing can be swapped in below a folder already handed back.
            for _, dirnames, filenames, dfd in os.fwalk(".", dir_fd=fd, topdown=False,
                                                        follow_symlinks=False):
                for name in filenames:
                    _return_file(name, dfd, uid, gid)
                os.fchown(dfd, uid, gid)
        finally:
            os.close(fd)
    for root in skipped:
        print(f"canary: skipped {root}: it is reached through a link", file=sys.stderr)
    return 0


def _return_file(name, dfd, uid, gid):
    """Hand one entry back. A regular file is opened without following links
    and checked and re-owned through the same handle, so the file checked is
    the file changed; one with more than one name (another file elsewhere on
    the Mac) is left alone."""
    try:
        ffd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except OSError:
        os.chown(name, uid, gid, dir_fd=dfd, follow_symlinks=False)  # a link or special file
        return
    try:
        st = os.fstat(ffd)
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            return
        os.fchown(ffd, uid, gid)
    finally:
        os.close(ffd)


def script(p, prefix="/", owner="root:wheel", person=None):
    """The whole privileged step as one sh script."""
    b64, sha = _payload()
    q = shlex.quote
    lib, link = _at(prefix, LIB), _at(prefix, LINK)
    lines = ["set -eu", "umask 022", 'T=$(mktemp -d)', 'trap \'rm -rf "$T"\' EXIT']
    if p["level"] != "scan":
        lines += [f"printf %s {q(b64)} | /usr/bin/base64 -D > \"$T/c.tgz\"",
                  f"printf '%s  %s\\n' {q(sha)} \"$T/c.tgz\" | /usr/bin/shasum -a 256 -c - >/dev/null",
                  f"rm -rf {q(lib + '.new')}", f"mkdir -p {q(lib + '.new')}",
                  f"tar -xzf \"$T/c.tgz\" -C {q(lib + '.new')}",
                  # Keep the recorded level if a later step fails.
                  f"[ ! -f {q(lib + '/state.json')} ] || cp {q(lib + '/state.json')} {q(lib + '.new/state.json')}",
                  f"rm -rf {q(lib)}", f"mv {q(lib + '.new')} {q(lib)}",
                  f"mkdir -p {q(os.path.dirname(link))}", f"ln -sfn {q(lib + '/bin/canary')} {q(link)}"]
    for f in p["files"]:
        data = base64.b64encode(f["content"].encode()).decode("ascii")
        lines += [f"mkdir -p {q(os.path.dirname(f['path']))}",
                  f"printf %s {q(data)} | /usr/bin/base64 -D > {q(f['path'] + '.canary-new')}",
                  f"chmod 644 {q(f['path'] + '.canary-new')}",
                  f"mv {q(f['path'] + '.canary-new')} {q(f['path'])}"]
    lines += [f"rm -f {q(path)}" for path in p["remove"]]
    # Locking and unlocking run the root-owned canary, which walks each skill
    # root from / through folder handles and never follows a link.
    helper = f"{PYTHON} -I -B {q(lib + '/bin/canary')}"
    if p["unlock"] and person:
        # No escape when the helper is missing: a failed unlock fails the whole
        # step, so the recorded level stays Lockdown and doctor keeps saying so.
        lines.append(f"{helper} _roots unlock {q(owner)} {q(person)} {q(p['home'])} "
                     + " ".join(q(r) for r in p["unlock"]))
    # Scan keeps the program (the Mac installer may have put it there) and
    # records the level; only the protection is removed.
    state = base64.b64encode(json.dumps(p["state"], indent=2).encode()).decode("ascii")
    lines += [f"[ ! -d {q(lib)} ] || printf %s {q(state)} | /usr/bin/base64 -D > {q(lib + '/state.json')}",
              f"[ ! -d {q(lib)} ] || chown -R {q(owner)} {q(lib)}",
              f"[ ! -d {q(lib)} ] || chmod -R go-w {q(lib)}"]
    return "\n".join(lines) + "\n"


ADMIN_SCRIPT = """on run argv
  do shell script (item 1 of argv) with administrator privileges
end run"""


def run_as_admin(text):
    """True when the person approved and the script succeeded."""
    try:
        proc = subprocess.run(["osascript", "-e", ADMIN_SCRIPT, "--", text],
                              capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


CHOOSE_SCRIPT = """on run argv
  set r to choose from list {item 1 of argv, item 2 of argv} with title "SkillCanary setup" with prompt "How much protection do you want? You can change this later with canary setup." default items {item 2 of argv}
  if r is false then return ""
  return item 1 of r
end run"""


def choose_level():
    try:
        proc = subprocess.run(["osascript", "-e", CHOOSE_SCRIPT, "--"]
                              + [LEVEL_TEXT[level] for level in LEVELS],
                              capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for level in LEVELS:
        if proc.stdout.strip() == LEVEL_TEXT[level]:
            return level
    return None


def _write_frontdoor(p):
    for root in p["frontdoor"]:
        try:
            frontdoor.write(p["home"], root)
        except OSError:
            pass  # the skill is a convenience; protection does not depend on it


def launchctl(args):
    """Run launchctl as the person; its exit code."""
    try:
        return subprocess.run(["launchctl", *args], capture_output=True, timeout=60).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 1


def _watcher(level, home, prefix, launcher):
    """At Guard, install and start the watcher as the person (after the
    SkillCanary skill and the first look, so it holds neither); at Scan,
    stop and remove it."""
    from canary import watcher
    path = watcher.plist_path(home)
    domain = f"gui/{os.getuid()}"
    launcher(["bootout", f"{domain}/{watcher.LABEL}"])
    if level != "guard":
        if os.path.lexists(path):
            os.unlink(path)
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    support = os.path.join(home, "Library", "Application Support", "Canary")
    # Setup is the person's own first look: the watcher starts from what is
    # here now, not from what it saw before.
    try:
        os.unlink(os.path.join(support, watcher.SEEN))
    except OSError:
        pass
    tmp = path + f".{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(watcher.launch_agent_plist(_at(prefix, LIB + "/bin/canary"), support))
    os.replace(tmp, path)
    launcher(["bootstrap", domain, path])


def setup(level=None, *, home=None, prefix="/", runner=run_as_admin, chooser=choose_level,
          owner="root:wheel", person=None, launcher=None):
    """Move this Mac to `level`. Returns (outcome dict, exit code)."""
    if level == "lockdown":
        raise ValueError("Lockdown was removed; use guard, which also returns locked folders")
    # The root step acts on this home, so it comes from the account database,
    # never from $HOME, which whoever launched setup controls.
    if home is None:
        import pwd
        home = pwd.getpwuid(os.getuid()).pw_dir
    person = person or f"{os.getuid()}:{os.getgid()}"
    level = level or chooser()
    if level not in LEVELS:
        return {"outcome": "cancelled", "level": None, "manual": []}, 10
    p = plan(level, home, prefix)
    previous = (read_state(prefix) or {}).get("level", "scan")
    needs_admin = level != "scan" or previous != "scan"
    # The SkillCanary skill is written as the person, never by the root step,
    # and after it, which may have just returned the skill folders.
    if needs_admin and not runner(script(p, prefix, owner, person)):
        return {"outcome": "not_changed", "level": previous, "manual": []}, 10
    _write_frontdoor(p)
    # The guest list's first look: the skills here now are the person's.
    try:
        from canary import guestlist
        guestlist.scan(home, first_look=True)
    except (OSError, ValueError):
        pass
    try:
        _watcher(level, home, prefix, launcher or launchctl)
    except OSError:
        pass  # doctor reports a watcher that is not running
    return {"outcome": "done", "level": level,
            "manual": [{"path": m["path"], "block": m["block"]} for m in p["manual"]]}, 0


def doctor(home=None, prefix="/", expected_uid=0, root_uid=0, launcher=None):
    """(level, gaps in plain words, claim)."""
    home = home or os.path.expanduser("~")
    state = read_state(prefix)
    raw = _raw_state(prefix)
    if state is None and raw is not None:
        return "unknown", [f"SkillCanary's recorded level ({raw!r}) is not one it knows. "
                           "Run canary setup to set it again."], \
            "SkillCanary's state is not one it understands; nothing is claimed."
    if not state or state["level"] == "scan":
        return "scan", [], CLAIMS["scan"]
    level, gaps = state["level"], []
    lib = _at(prefix, LIB)
    for dirpath, dirnames, filenames in os.walk(lib):
        for name in [dirpath] + [os.path.join(dirpath, f) for f in filenames]:
            st = os.lstat(name)
            if st.st_uid != expected_uid or st.st_mode & 0o022:
                gaps.append("Canary's installed files can be changed without a password.")
                break
        else:
            continue
        break
    parent = os.path.dirname(lib)
    while parent and parent != os.path.dirname(parent):
        st = os.stat(parent)
        if st.st_uid != expected_uid and st.st_uid != 0 or st.st_mode & 0o002:
            gaps.append(f"{parent} can be changed without a password, so Canary's install could be replaced.")
            break
        if parent == _at(prefix, "/").rstrip("/") or parent == prefix.rstrip("/"):
            break
        parent = os.path.dirname(parent)
    for host, name in (("claude", "Claude Code"), ("codex", "Codex")):
        policy = _at(prefix, claude_host.MANAGED_DIR + "/canary.json") if host == "claude" \
            else _at(prefix, "/etc/codex/requirements.toml")
        try:
            with open(policy, encoding="utf-8") as fh:
                has_hook = hook_command(prefix, host) in fh.read().replace('\\"', '"')
        except OSError:
            has_hook = False
        if not has_hook:
            gaps.append(f"{name} is not running Canary's hook ({policy} lacks it).")
    from canary import watcher
    launcher = launcher or launchctl
    if level == "guard":
        want = watcher.launch_agent_plist(
            _at(prefix, LIB + "/bin/canary"),
            os.path.join(home, "Library", "Application Support", "Canary"))
        try:
            with open(watcher.plist_path(home), encoding="utf-8") as fh:
                ours = fh.read() == want
        except OSError:
            ours = None
        if ours is False:
            gaps.append("SkillCanary's watcher file was changed, so it may not run SkillCanary. "
                        "Run canary setup --level guard.")
        elif ours is None or launcher(["print", f"gui/{os.getuid()}/{watcher.LABEL}"]) != 0:
            gaps.append("SkillCanary's watcher is not running, so a skill that arrives outside "
                        "an agent is reported at the next session start but not held. Run "
                        "canary setup --level guard.")
    if level == "lockdown":
        gaps.append("This Mac is still at Lockdown, which SkillCanary no longer has. Run "
                    "canary setup --level guard to return your skill folders to you.")
    if root_uid != os.getuid():
        for root in lock_roots(home):
            try:
                owned_by_root = os.stat(root).st_uid == root_uid
            except OSError:
                continue
            if owned_by_root:
                gaps.append(f"{root} is still owned by root, so you cannot add or change "
                            "skills there. Run canary setup --level guard; if it is reached "
                            "through a link, change the folder it leads to back yourself.")
    try:
        ok = subprocess.run([PYTHON, "-I", "-c", "pass"], capture_output=True,
                            timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ok = False
    if not ok:
        gaps.append(f"{PYTHON} does not run, so the hook would fail open. "
                    "Install the command-line tools: xcode-select --install")
    # With a gap, the level's claim does not hold yet, but saying "nothing is
    # enforced" would be wrong too: the hooks are in place.
    if level == "lockdown":
        claim = ("This Mac is still at Lockdown, left over from an earlier SkillCanary; "
                 "the hooks are in place, but run the setup step below.")
    else:
        claim = CLAIMS[level] if not gaps else (
            f"{level.capitalize()} is set up but not fully in force until the gaps "
            "below are fixed.")
    return level, gaps, claim


# ---- old install records (program 2026-10-06) --------------------------------

MAX_LISTED = 20


def old_records(home=None):
    """The lockfile's records whose folders are gone, skills first, each group
    sorted by key: [{"kind", "key", "name", "installed"}]. A record that is not
    well formed is dead and lists `installed` as []. A missing lockfile has no
    records; an unreadable one raises add.LockError."""
    from canary import add
    home = home or os.path.expanduser("~")
    lock = add._read_lock(home)
    plugins = lock.get("plugins")
    out = []
    for kind, records in (("skill", lock["skills"]),
                          ("plugin", plugins if isinstance(plugins, dict) else {})):
        for key in sorted(records):
            rec = records[key]
            if not add.is_live(rec):
                name = add.record_name(key, rec) if kind == "skill" else key
                out.append({"kind": kind, "key": key, "name": name,
                            "installed": add.record_paths(rec)})
    return out


def _plural(n, one, many):
    return one if n == 1 else many


def _first_path(rec, home):
    from canary import add
    return add._short(rec["installed"][0], home) if rec["installed"] else "(no path recorded)"


def render_old_records(records, home):
    n = len(records)
    lines = [f"Old install records: {n} "
             f"({_plural(n, 'its folder is gone', 'their folders are gone')})"]
    lines += [f"  {r['name']}  {_first_path(r, home)}" for r in records]
    lines.append("Run canary doctor --prune to remove them. It asks you first.")
    return "\n".join(lines)


def prune_dialog_text(records, home):
    n = len(records)
    lines = [f"SkillCanary has {n} install {_plural(n, 'record for a skill or plugin whose folders are gone', 'records for skills or plugins whose folders are gone')}:"]
    for r in records[:MAX_LISTED]:
        path = _first_path(r, home)
        lines.append(f"- {r['name']} " + (path if path.startswith("(") else f"({path})"))
    if n > MAX_LISTED:
        lines.append(f"- and {n - MAX_LISTED} more")
    lines += ["Removing them lets you install these names again. It does not change any",
              "skill or plugin on this Mac.", "",
              "The names come from the packages, not from SkillCanary."]
    return "\n".join(lines)


def prune_records(home=None, approve=None):
    """`canary doctor --prune`: ask the person, then remove the records that
    are still dead. Prints the outcome and returns the exit code."""
    from canary import add
    home = home or os.path.expanduser("~")
    if approve is None:
        approve = lambda text: add.ask(text, "NEEDS_REVIEW", yes="Remove records")
    try:
        records = old_records(home)
        if not records:
            print("No old install records.")
            return 0
        if approve(prune_dialog_text(records, home)) is not True:
            print("Nothing removed: the person did not agree in SkillCanary's dialog.")
            return 10
        shown = {(r["kind"], r["key"]) for r in records}
        with add._Commit(home):
            lock = add._read_lock(home)
            plugins = lock.get("plugins")
            removed = 0
            for kind, records_ in (("skill", lock["skills"]),
                                   ("plugin", plugins if isinstance(plugins, dict) else {})):
                for key in [k for k in records_ if (kind, k) in shown
                            and not add.is_live(records_[k])]:
                    del records_[key]
                    removed += 1
            add._write_lock(home, lock)
    except add.LockError as exc:
        print(f"canary: {exc}", file=sys.stderr)
        return 3
    print(f"Removed {removed} old install {_plural(removed, 'record', 'records')}.")
    return 0
