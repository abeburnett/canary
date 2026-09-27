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

LEVELS = ("scan", "guard", "lockdown")
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
    "lockdown": "Enforces vetting for user-level skill folders on this Mac, and guards "
                "repository skills.",
}
LEVEL_TEXT = {
    "scan": "Scan: check skills when you ask. No password, nothing enforced.",
    "guard": "Guard (recommended): block agents from installing skills any way but "
             "canary add. Password once.",
    "lockdown": "Lockdown: Guard, and only canary add can change your skill folders. "
                "Password now and at each install.",
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
    return state if isinstance(state, dict) and state.get("level") in LEVELS else None


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


def _read(path):
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
        sha = hashlib.sha256(now.encode()).hexdigest() if now is not None else None
        ours = now is not None and (now == content or now in earlier or (
            isinstance(recorded.get(target), str) and recorded[target] == sha))
        if level == "scan":
            if ours:
                remove.append(target)
        elif now is None or ours:
            if now != content:
                files.append({"path": target, "content": content})
            created[target] = hashlib.sha256(content.encode()).hexdigest()
        else:
            manual.append({"path": target, "block": content})
    roots = lock_roots(home)
    return {"level": level, "files": files, "remove": remove, "manual": manual,
            "frontdoor": frontdoor.targets(home, roots),
            "lock": roots if level == "lockdown" else [],
            "unlock": roots if level != "lockdown" and hint.get("level") == "lockdown" else [],
            "home": home,
            "state": {"level": level, "created": created,
                      "locked": roots if level == "lockdown" else [],
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
    """Lock (owner, no group/other write) or unlock (back to the person) each
    skill root through folder handles, never following links. A root reached
    through a link is skipped and reported; `canary doctor` shows it as a gap.
    Runs as root inside the privileged step, from the root-owned install."""
    uid, gid = _ids(owner if action == "lock" else person)
    pid = _ids(person)
    skipped = []
    for root in roots:
        try:
            fd = _open_dirs(root, create_under=home if action == "lock" else None, person=pid)
        except FileNotFoundError:
            continue
        except OSError:
            skipped.append(root)
            continue
        try:
            for _, dirnames, filenames, dfd in os.fwalk(".", dir_fd=fd, follow_symlinks=False):
                os.fchown(dfd, uid, gid)
                if action == "lock":
                    os.fchmod(dfd, os.fstat(dfd).st_mode & 0o7755 | 0o755)
                for name in filenames + dirnames:
                    st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        continue  # fwalk visits it next, through its own handle
                    os.chown(name, uid, gid, dir_fd=dfd, follow_symlinks=False)
                    if action == "lock" and stat.S_ISREG(st.st_mode):
                        os.chmod(name, st.st_mode & 0o7755, dir_fd=dfd, follow_symlinks=False)
        finally:
            os.close(fd)
    for root in skipped:
        print(f"canary: skipped {root}: it is reached through a link", file=sys.stderr)
    return 0


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
    for action, roots in (("lock", p["lock"]), ("unlock", p["unlock"] if person else [])):
        if roots:
            lines.append(f"[ ! -x {q(lib + '/bin/canary')} ] || {helper} _roots {action} "
                         f"{q(owner)} {q(person or owner)} {q(p['home'])} "
                         + " ".join(q(r) for r in roots))
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
  set r to choose from list {item 1 of argv, item 2 of argv, item 3 of argv} with title "SkillCanary setup" with prompt "How much protection do you want? You can change this later with canary setup." default items {item 2 of argv}
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


def setup(level=None, *, home=None, prefix="/", runner=run_as_admin, chooser=choose_level,
          owner="root:wheel", person=None):
    """Move this Mac to `level`. Returns (outcome dict, exit code)."""
    home = home or os.path.expanduser("~")
    person = person or f"{os.getuid()}:{os.getgid()}"
    level = level or chooser()
    if level not in LEVELS:
        return {"outcome": "cancelled", "level": None, "manual": []}, 10
    p = plan(level, home, prefix)
    previous = (read_state(prefix) or {}).get("level", "scan")
    needs_admin = level != "scan" or previous != "scan"
    # The SkillCanary skill is written as the person, never by the root step.
    # At Lockdown that happens before the roots are locked (a Mac already at
    # Lockdown keeps the copy it has); otherwise after the root step, which
    # may have just unlocked them.
    if level == "lockdown" and previous != "lockdown":
        _write_frontdoor(p)
    if needs_admin and not runner(script(p, prefix, owner, person)):
        return {"outcome": "not_changed", "level": previous, "manual": []}, 10
    if level != "lockdown":
        _write_frontdoor(p)
    return {"outcome": "done", "level": level,
            "manual": [{"path": m["path"], "block": m["block"]} for m in p["manual"]]}, 0


def _below(home, path):
    """Each folder from just under home down to path."""
    rel = os.path.relpath(path, home).split(os.sep)
    return [os.path.join(home, *rel[:i + 1]) for i in range(len(rel))]


def doctor(home=None, prefix="/", expected_uid=0):
    """(level, gaps in plain words, claim)."""
    home = home or os.path.expanduser("~")
    state = read_state(prefix)
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
    for root in lock_roots(home):
        linked = [c for c in _below(home, root) if os.path.islink(c)]
        if linked:
            gaps.append(f"{linked[0]} is a link, so SkillCanary cannot lock or safely write "
                        f"{root}; make it a real folder.")
    if level == "lockdown":
        for root in lock_roots(home):
            try:
                st = os.stat(root)
                ok = st.st_uid == expected_uid and not st.st_mode & 0o022
            except OSError:
                ok = False
            if not ok:
                gaps.append(f"{root} is not locked; anything running as you can change it.")
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
    claim = CLAIMS[level] if not gaps else (
        f"{level.capitalize()} is set up but not fully in force until the gaps "
        "below are fixed.")
    return level, gaps, claim
