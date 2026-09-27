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
LIB = "usr/local/lib/skillcanary"
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


def read_state(prefix="/"):
    try:
        with open(_at(prefix, LIB + "/state.json"), encoding="utf-8") as fh:
            state = json.load(fh)
        return state if isinstance(state, dict) and state.get("level") in LEVELS else None
    except (OSError, ValueError):
        return None


def plan(level, home, prefix="/"):
    """What the privileged script must do to move this Mac to `level`."""
    previous = read_state(prefix) or {"level": "scan", "created": {}, "locked": []}
    files, remove, manual = [], [], []
    if level != "scan":
        for host, adapter in (("claude", claude_host), ("codex", codex_host)):
            for planned in adapter.managed_install_plan(_at(prefix, LIB + "/bin/canary")):
                target, content = _at(prefix, planned.path), planned.content
                recorded = previous.get("created", {}).get(target)
                if os.path.lexists(target) and recorded != _sha_file(target):
                    manual.append({"path": target, "block": content})
                elif _sha_file(target) != hashlib.sha256(content.encode()).hexdigest():
                    files.append({"path": target, "content": content})
    keep = {f["path"] for f in files} | set(previous.get("created", {})) if level != "scan" else set()
    for path, sha in previous.get("created", {}).items():
        if level == "scan" and _sha_file(path) == sha:
            remove.append(path)
    created = {} if level == "scan" else {
        p: s for p, s in previous.get("created", {}).items() if p in keep and _sha_file(p) == s}
    created.update({f["path"]: hashlib.sha256(f["content"].encode()).hexdigest() for f in files})
    return {"level": level, "files": files, "remove": remove, "manual": manual,
            "frontdoor": frontdoor.targets(home, lock_roots(home)),
            "lock": lock_roots(home) if level == "lockdown" else [],
            "unlock": [r for r in previous.get("locked", []) if level != "lockdown"],
            "state": {"level": level, "created": created,
                      "locked": lock_roots(home) if level == "lockdown" else [],
                      "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}


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
    if p["lock"]:
        # Lockdown: write the SkillCanary skill before the roots are locked.
        skill = base64.b64encode(frontdoor.installed_text().encode()).decode("ascii")
        for folder in p.get("frontdoor", []):
            lines += [f"mkdir -p {q(folder)}",
                      f"printf %s {q(skill)} | /usr/bin/base64 -D > {q(folder + '/SKILL.md')}"]
    for root in p["lock"]:
        lines += [f"mkdir -p {q(root)}", f"chown -R {q(owner)} {q(root)}",
                  f"chmod -R go-w {q(root)}", f"chmod 755 {q(root)}"]
    for root in p["unlock"]:
        if person:
            lines.append(f"[ ! -e {q(root)} ] || chown -R {q(person)} {q(root)}")
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
    if needs_admin and not runner(script(p, prefix, owner, person)):
        return {"outcome": "not_changed", "level": previous, "manual": []}, 10
    if level != "lockdown":
        for folder in p["frontdoor"]:
            try:
                frontdoor.write(folder)
            except OSError:
                pass  # the skill is a convenience; protection does not depend on it
    return {"outcome": "done", "level": level,
            "manual": [{"path": m["path"], "block": m["block"]} for m in p["manual"]]}, 0


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
    claim = CLAIMS[level] if not gaps else CLAIMS["scan"] + " (Gaps below prevent more.)"
    return level, gaps, claim
