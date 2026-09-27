"""`canary add`: fetch into quarantine, check, ask the person, install the
checked bytes. The rules are fixed in docs/architecture.md ("canary add").

The agent that runs this passes a link and receives only the outcome. Every
string that comes from the package or the link is attacker text: it goes to
the person's dialog labelled as such, and to the agent only as a sanitized
name or a validated GitHub identifier.
"""

import http.client
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

from canary import classify, scan, setup
from canary.hosts import claude as claude_host
from canary.hosts import codex as codex_host

EXIT_FOR_OUTCOME = {"installed": 0, "declined": 10, "not_installed": 10, "refused": 20}
HOSTS = {"claude": ("Claude Code", claude_host, (".claude",)),
         "codex": ("Codex", codex_host, (".codex", ".agents"))}
SUPPORT_DIR = os.path.expanduser("~/Library/Application Support/Canary")
MAX_DOWNLOAD = 50 * 1024 * 1024
MAX_EXTRACTED = 200 * 1024 * 1024
MAX_ENTRIES = 5000
DIALOG_SECONDS = 300

OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
REPO = r"[A-Za-z0-9._-]{1,100}"
GITHUB = re.compile(rf"https://github\.com/({OWNER})/({REPO}?)(?:\.git)?"
                    r"(?:/(tree|blob)/([A-Za-z0-9._-]{1,255})(/[^?#\s]*)?)?/?")
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
SHA = re.compile(r"[0-9a-f]{40}")


class SourceError(Exception):
    """The link, download or package cannot be used. Safe to show the agent."""


class LockError(Exception):
    pass


# ---- sources ------------------------------------------------------------

def parse_source(source):
    """("github", owner, repo, ref, path) or ("local", absolute path, ...)."""
    m = GITHUB.fullmatch(source)
    if m:
        owner, repo, kind, ref, path = m.groups()
        if not repo or repo in (".", ".."):
            raise SourceError("That GitHub link has no repository name.")
        parts = [p for p in (path or "").split("/") if p]
        if any(p in (".", "..") or "\x00" in p for p in parts):
            raise SourceError("That GitHub link has an unusable path.")
        if kind == "blob":
            if not parts or parts[-1] != "SKILL.md":
                raise SourceError("Link a skill folder, or its SKILL.md file.")
            parts = parts[:-1]
        return ("github", owner, repo, ref or "HEAD", "/".join(parts))
    if source.startswith(("http://", "https://")) or "://" in source:
        raise SourceError("Only https://github.com links and local folders are supported.")
    path = os.path.abspath(os.path.expanduser(source))
    if not os.path.isdir(path) or os.path.islink(path):
        raise SourceError("No such folder.")
    return ("local", path, None, None, "")


def _https(host, path, headers, dest=None, cap=None):
    """One GET with no redirects. Returns the body, or streams it to dest."""
    conn = http.client.HTTPSConnection(host, timeout=60)
    try:
        conn.request("GET", path, headers={"User-Agent": "skillcanary", **headers})
        resp = conn.getresponse()
        if resp.status != 200:
            raise SourceError(f"GitHub answered HTTP {resp.status}.")
        if dest is None:
            return resp.read(4096)
        total = 0
        with open(dest, "wb") as fh:
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    raise SourceError("The download is larger than 50 MB.")
                fh.write(chunk)
        return None
    except OSError:
        raise SourceError("Could not reach GitHub.") from None
    finally:
        conn.close()


def github_fetch(owner, repo, ref, dest):
    """Resolve ref to a commit SHA, then download that exact commit."""
    body = _https("api.github.com", f"/repos/{owner}/{repo}/commits/{ref}",
                  {"Accept": "application/vnd.github.sha"})
    sha = body.decode("ascii", "replace").strip()
    if not SHA.fullmatch(sha):
        raise SourceError("GitHub did not return a commit for that link.")
    _https("codeload.github.com", f"/{owner}/{repo}/tar.gz/{sha}", {}, dest, MAX_DOWNLOAD)
    return sha


def _extract(archive, dest):
    """Extract by hand. Anything but plain files and folders refuses the whole
    archive; every member must sit under one top-level folder."""
    try:
        tar = tarfile.open(archive, "r:gz")
    except (tarfile.TarError, OSError):
        raise SourceError("The download is not a readable archive.") from None
    top, count, total = None, 0, 0
    with tar:
        for member in tar:
            count += 1
            if count > MAX_ENTRIES:
                raise SourceError("The package has too many files.")
            name = member.name
            if "\x00" in name or name.startswith("/") or "\\" in name:
                raise SourceError("The archive has an unsafe file name.")
            parts = [p for p in name.split("/") if p]
            if not parts or any(p in (".", "..") for p in parts):
                raise SourceError("The archive has an unsafe file name.")
            if top is None:
                top = parts[0]
            if parts[0] != top:
                raise SourceError("The archive has more than one top-level folder.")
            target = os.path.join(dest, *parts)
            if member.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            if not member.isreg():
                raise SourceError("The package contains links or special files.")
            total += member.size
            if total > MAX_EXTRACTED:
                raise SourceError("The package is too large.")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            mode = 0o755 if member.mode & 0o100 else 0o644
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(tar.extractfile(member), out)
    if top is None:
        raise SourceError("The archive is empty.")
    return os.path.join(dest, top)


def _copy_local(src, dest):
    """Copy a local folder without following links and without .git."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        rel = os.path.relpath(dirpath, src)
        os.makedirs(os.path.join(dest, rel), exist_ok=True)
        for name in dirnames + filenames:
            count += 1
            if count > MAX_ENTRIES:
                raise SourceError("The package has too many files.")
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                raise SourceError("The folder contains links or special files.")
            if stat.S_ISREG(st.st_mode):
                shutil.copyfile(path, os.path.join(dest, rel, name), follow_symlinks=False)
                os.chmod(os.path.join(dest, rel, name), 0o755 if st.st_mode & 0o100 else 0o644)
    return dest


def _select(root, path):
    """The one skill folder a link names."""
    folder = os.path.join(root, *path.split("/")) if path else root
    if not os.path.isdir(folder) or os.path.islink(folder):
        raise SourceError("The link's folder is not in the repository.")
    if os.path.isfile(os.path.join(folder, "SKILL.md")):
        return folder
    found = [d for d, _, files in os.walk(folder) if "SKILL.md" in files]
    if len(found) == 1:
        return found[0]
    if not found:
        raise SourceError("No skill (SKILL.md) found at that link.")
    raise SourceError(f"That link holds {len(found)} skills; link the folder of the one you want.")


def _name(folder, fallback):
    try:
        with open(os.path.join(folder, "SKILL.md"), encoding="utf-8") as fh:
            text = fh.read(65536)
    except (OSError, UnicodeDecodeError):
        text = ""
    m = re.match(r"---\r?\n(.*?)\r?\n---", text, re.S)
    if m:
        for line in m.group(1).splitlines():
            key, _, value = line.partition(":")
            if key == "name":
                value = value.strip().strip("\"'")
                if NAME.fullmatch(value):
                    return value
                break
    if NAME.fullmatch(fallback or ""):
        return fallback
    raise SourceError("The skill has no usable name (lowercase letters, digits and dashes).")


# ---- filesystem helpers --------------------------------------------------

def _set_modes(root, writable):
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            x = os.stat(path).st_mode & 0o100
            os.chmod(path, (0o755 if x else 0o644) if writable else (0o555 if x else 0o444))
        os.chmod(dirpath, 0o755 if writable else 0o555)


def _remove(path):
    if not os.path.lexists(path):
        return
    for dirpath, _, _ in os.walk(path):
        try:
            os.chmod(dirpath, 0o755)
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


def _lock_path(home):
    return os.path.join(home, ".agents", ".canary-lock.json")


def _read_lock(home):
    path = _lock_path(home)
    if not os.path.exists(path):
        return {"schema": "canary.lock/1", "skills": {}}
    try:
        with open(path, encoding="utf-8") as fh:
            lock = json.load(fh)
        if lock.get("schema") != "canary.lock/1" or not isinstance(lock.get("skills"), dict):
            raise ValueError
        return lock
    except (OSError, ValueError, AttributeError):
        raise LockError(f"{path} is not a Canary lockfile; not changing it.") from None


def _write_lock(home, lock):
    path = _lock_path(home)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".canary-lock-", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(lock, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


# ---- the person's approval -------------------------------------------------

PLAIN = {
    "shell_injection": "runs shell commands as soon as the skill loads",
    "allowed_tools": "pre-approves tools, so the agent may not ask you first",
    "skill_hooks": "adds hooks that run automatically",
    "plugin_hooks": "adds hooks that run automatically",
    "plugin_power": "is a plugin that does more than give instructions",
    "mcp_config": "connects the agent to a tool server (MCP)",
    "skill_dependencies": "asks for extra tools, servers or permissions",
    "unparsed_frontmatter": "has a settings header SkillCanary cannot fully read",
    "instructs_execution": "tells the agent to run a program",
    "bin_dir": "includes a folder of programs",
    "script": "includes scripts the agent can run",
    "executable_bit": "includes files marked as programs",
    "package_manifest": "installs other software packages",
    "unrecognized_file": "includes files of a type SkillCanary does not recognise",
}

def dialog_text(summary):
    """What the person reads. Canary's verdict and reasons first; strings from
    the link or package are labelled, and the package's own description is
    never shown."""
    hosts = ", ".join(HOSTS[h][0] for h in summary["hosts"])
    if summary["owner"]:
        source = f"github.com/{summary['owner']}/{summary['repo']} at {summary['commit'][:7]}"
    else:
        source = "a folder on this Mac"
    verdict = {"LIKELY_SAFE": "no problems found",
               "NEEDS_REVIEW": "needs your judgment"}.get(summary["verdict"], summary["verdict"])
    lines = [f"SkillCanary checked this skill: {verdict}.", ""]
    can = sorted({PLAIN[k] for k in summary["capabilities"] if k in PLAIN})
    if can:
        lines += ["What it can do:"] + [f"- It {c}." for c in can] + [""]
    other = [r for r in summary["reasons"] if not r.startswith("Runs code or grants tools")]
    lines += [f"- {r}" for r in other]
    lines += ["", f"From the link: {source}", f"Installs as: {summary['name']}",
              f"Into: {hosts}", "",
              "The source and name come from the link and package, not from SkillCanary."]
    return "\n".join(lines)


DIALOG_SCRIPT = """on run argv
  set theText to item 1 of argv
  if item 2 of argv is "review" then
    set r to display dialog theText with title "SkillCanary" buttons {"Install anyway", "Cancel"} default button "Cancel" cancel button "Cancel" with icon caution giving up after (item 3 of argv as integer)
  else
    set r to display dialog theText with title "SkillCanary" buttons {"Cancel", "Install"} default button "Install" cancel button "Cancel" giving up after (item 3 of argv as integer)
  end if
  if gave up of r then return "timeout"
  return button returned of r
end run"""


def macos_dialog(summary):
    """True to install, False when the person cancels, None when no dialog
    could be shown or nobody answered."""
    if sys.platform != "darwin" or not shutil.which("osascript"):
        return None
    kind = "review" if summary["verdict"] != "LIKELY_SAFE" else "safe"
    try:
        proc = subprocess.run(["osascript", "-e", DIALOG_SCRIPT, "--", dialog_text(summary),
                               kind, str(DIALOG_SECONDS)],
                              capture_output=True, text=True, timeout=DIALOG_SECONDS + 30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return False if "-128" in proc.stderr else None
    return {"Install": True, "Install anyway": True}.get(proc.stdout.strip())


# ---- the flow ------------------------------------------------------------

def _hosts(home, wanted):
    if wanted:
        return list(dict.fromkeys(wanted))
    return [h for h, (_, _, dirs) in HOSTS.items()
            if any(os.path.isdir(os.path.join(home, d)) for d in dirs)]


def _admin_install(snapshot, destinations, digest, run_id, canary_bin, owner):
    """Lockdown: stage every copy, have the root-owned canary confirm each
    staged copy is the checked package, then rename them all, in one
    administrator step. The quarantine is the person's, so only a copy
    verified after it became root-owned is trusted."""
    q = shlex.quote
    stages = [os.path.join(os.path.dirname(d), f".canary-staging-{run_id}") for d in destinations]
    lines = ["set -eu", "cleanup() { rm -rf " + " ".join(q(x) for x in stages) + "; }",
             "trap cleanup EXIT"]
    for stage, dest in zip(stages, destinations):
        lines += [f"[ ! -e {q(dest)} ]", f"mkdir -p {q(os.path.dirname(dest))}",
                  f"cp -R {q(snapshot)} {q(stage)}", f"chown -R {q(owner)} {q(stage)}",
                  f"chmod -R u+w,go-w {q(stage)}",
                  f"[ \"$(/usr/bin/python3 -I -B {q(canary_bin)} digest {q(stage)})\" = {q(digest)} ]"]
    lines += [f"mv {q(stage)} {q(dest)}" for stage, dest in zip(stages, destinations)]
    return "\n".join(lines) + "\n"


def add(source, *, home=None, support_dir=None, approve=None, fetch=None,
        backend="auto", model=None, timeout_s=classify.DEFAULT_TIMEOUT_S, hosts=None,
        prefix="/", admin=None, admin_owner="root:wheel"):
    """Run the whole add flow and return a canary.add/1 result.
    Raises SourceError (exit 2) or LockError (exit 3)."""
    home = home or os.path.expanduser("~")
    support_dir = support_dir or SUPPORT_DIR
    approve = approve or macos_dialog
    fetch = fetch or github_fetch
    kind, *rest = parse_source(source)
    hosts = _hosts(home, hosts)
    if not hosts:
        raise SourceError("Neither Claude Code nor Codex is set up for this user.")
    lock = _read_lock(home)

    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
    quarantine = os.path.join(support_dir, "quarantine", run_id)
    work = tempfile.mkdtemp(prefix="canary-add-")
    os.makedirs(quarantine, mode=0o700)
    try:
        if kind == "github":
            owner, repo, ref, path = rest
            archive = os.path.join(work, "package.tar.gz")
            commit = fetch(owner, repo, ref, archive)
            if not SHA.fullmatch(commit or ""):
                raise SourceError("GitHub did not return a commit for that link.")
            root = _extract(archive, os.path.join(work, "x"))
            fallback = path.rsplit("/", 1)[-1] if path else repo.lower()
        else:
            owner = repo = ref = commit = None
            path = ""
            root = _copy_local(rest[0], os.path.join(work, "x"))
            fallback = os.path.basename(rest[0]).lower()
        folder = _select(root, path)
        if folder != root and kind == "github":
            fallback = os.path.basename(folder).lower()
        name = _name(folder, fallback)
        snapshot = os.path.join(quarantine, "package")
        os.rename(folder, snapshot)
        _remove(work)
        _set_modes(snapshot, writable=False)

        result = classify.check(snapshot, backend=backend, model=model, timeout_s=timeout_s,
                                log_dir=os.path.join(support_dir, "logs"))
        verdict, reasons = result["verdict"], result["reasons"]
        out = {"schema": "canary.add/1", "outcome": None, "verdict": verdict, "name": name,
               "source": {"owner": owner, "repo": repo, "commit": commit},
               "installed": [], "reasons": list(reasons)}
        if verdict == "UNSAFE":
            out["outcome"] = "refused"
            out["reasons"].append("Not installed: SkillCanary judged it unsafe.")
            return out

        destinations = [os.path.join(HOSTS[h][1].install_root(home), name) for h in hosts]
        if name in lock["skills"] or any(os.path.lexists(d) for d in destinations):
            out["outcome"] = "not_installed"
            out["reasons"].append(f"A skill named {name} is already installed; "
                                  "use canary update to replace it.")
            return out

        summary = {"verdict": verdict, "reasons": reasons, "name": name, "owner": owner,
                   "capabilities": sorted({c["kind"] for c in result["scan"]["capabilities"]}),
                   "repo": repo, "commit": commit, "hosts": hosts, "_snapshot": snapshot}
        answer = approve(summary)
        if answer is not True:
            out["outcome"] = "declined" if answer is False else "not_installed"
            out["reasons"].append("The person declined the install." if answer is False else
                                  "Nobody approved it on the Mac's screen; ask the person to "
                                  "run canary add again and answer the SkillCanary dialog.")
            return out

        if (setup.read_state(prefix) or {}).get("level") == "lockdown":
            canary_bin = os.path.join(prefix, setup.LIB, "bin", "canary")
            text = _admin_install(snapshot, destinations, result["package_digest"], run_id,
                                  canary_bin, admin_owner)
            if not (admin or setup.run_as_admin)(text):
                out["outcome"] = "not_installed"
                out["reasons"].append("The password step was declined, or the copy did not "
                                      "match what was checked; nothing was installed.")
                return out
            return _finish(out, lock, home, name, verdict, result, list(destinations),
                           {"source": source if kind == "github" else "local", "owner": owner,
                            "repo": repo, "ref": ref, "commit": commit, "path": path})
        staged = []
        try:
            for dest in destinations:
                parent = os.path.dirname(dest)
                os.makedirs(parent, exist_ok=True)
                stage = os.path.join(parent, f".canary-staging-{run_id}-{name}")
                staged.append((stage, dest))
                shutil.copytree(snapshot, stage, symlinks=True)
                _set_modes(stage, writable=True)
                if scan.scan_package(stage)["package_digest"] != result["package_digest"]:
                    raise SourceError("changed")
        except (SourceError, scan.PathError, OSError):
            for stage, _ in staged:
                _remove(stage)
            out["outcome"] = "not_installed"
            out["reasons"].append("The package changed after it was checked; nothing was installed.")
            return out
        done = []
        try:
            for stage, dest in staged:
                os.rename(stage, dest)
                done.append(dest)
        except OSError:
            for dest in done:
                _remove(dest)
            for stage, _ in staged:
                _remove(stage)
            out["outcome"] = "not_installed"
            out["reasons"].append("Another install got there first; nothing was installed.")
            return out

        return _finish(out, lock, home, name, verdict, result, done,
                       {"source": source if kind == "github" else "local", "owner": owner,
                        "repo": repo, "ref": ref, "commit": commit, "path": path})
    finally:
        _remove(work)
        _remove(quarantine)


def _finish(out, lock, home, name, verdict, result, done, source_fields):
    lock["skills"][name] = dict(source_fields, package_digest=result["package_digest"],
                                verdict=verdict, installed=done,
                                installed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    _write_lock(home, lock)
    out["outcome"] = "installed"
    out["installed"] = ["~" + d[len(home):] if d.startswith(home + os.sep) else d for d in done]
    return out


def render_text(out):
    lines = [f"SkillCanary add: {out['outcome']} ({out['verdict']})"]
    if out["name"]:
        lines.append(f"Name: {out['name']}")
    lines += [f"  - {r}" for r in out["reasons"]]
    lines += [f"  Installed: {p}" for p in out["installed"]]
    return "\n".join(lines)
