"""`canary install -- <installer command>`: run the person's own installer
against a staging home, check what lands, ask once, and put only the checked
files in place (docs/architecture.md, "canary install"; program 2026-09-30,
slice B1).

Skills (`npx skills add …` and its launchers) are copied from staging into
place, with the links the installer made. Plugins (`claude plugin install
<name>@<marketplace>`) are staged and checked, then the person's real
install runs and SkillCanary confirms the installed folder is the one it
checked, uninstalling it otherwise (owner decision 7). A marketplace add
installs nothing an agent loads, so it runs as given.

The installer is the person's chosen program and runs as them; staging
redirects where it writes by default, not where it could write. Its output
can quote package text, so it goes to a log, never to the agent.
"""

import concurrent.futures
import json
import os
import secrets
import shutil
import stat
import subprocess
import time

from canary import add, classify, explain, guestlist, installers

INSTALLER_SECONDS = 600
CHECK_WORKERS = 4
SKIP_DIRS = {".git", "node_modules", ".npm", ".cache"}
EXIT_FOR_OUTCOME = dict(add.EXIT_FOR_OUTCOME, done=0)


class InstallError(Exception):
    """The command is not one `canary install` runs (exit 2)."""


def _result(kind_, argv):
    return {"schema": "canary.install/1", "outcome": None, "verdict": None, "kind": kind_,
            "skills": [], "installed": [], "reasons": [], "next_steps": []}


def _env(stage_home, real_home, extra=None):
    """The person's environment, with every home-relative default pointed at
    the staging home. Git and npm keep the person's settings and cache, so
    private sources and offline caches still work."""
    env = dict(os.environ)
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "CODEX_HOME",
                "CLAUDE_CONFIG_DIR", "npm_config_prefix", "NPM_CONFIG_PREFIX"):
        env.pop(key, None)
    env["HOME"] = stage_home
    gitconfig = os.path.join(real_home, ".gitconfig")
    if "GIT_CONFIG_GLOBAL" not in os.environ and os.path.isfile(gitconfig):
        env["GIT_CONFIG_GLOBAL"] = gitconfig
    if not any(k.lower() == "npm_config_cache" for k in os.environ):
        env["npm_config_cache"] = os.path.join(real_home, ".npm")
    npmrc = os.path.join(real_home, ".npmrc")
    if not any(k.lower() == "npm_config_userconfig" for k in os.environ) and os.path.isfile(npmrc):
        env["npm_config_userconfig"] = npmrc
    env.update(extra or {})
    return env


def _real_env(home):
    """The person's environment for a real run, bound to the home this
    install is for."""
    return dict(os.environ, HOME=home)


def _mirror_home(real_home, stage_home):
    """Empty copies of the person's top-level hidden folders, so an installer
    that looks for `~/.claude` or `~/.codex` to pick its agents finds them."""
    try:
        names = os.listdir(real_home)
    except OSError:
        return
    for name in names:
        if name.startswith(".") and name not in (".", "..", ".Trash"):
            try:
                if stat.S_ISDIR(os.lstat(os.path.join(real_home, name)).st_mode):
                    os.makedirs(os.path.join(stage_home, name), mode=0o700, exist_ok=True)
            except OSError:
                pass


def _run(argv, cwd, env, log_path, timeout=INSTALLER_SECONDS):
    """Run the installer; its output goes to the log. The exit code, or None
    when it could not start or ran out of time."""
    os.makedirs(os.path.dirname(log_path), mode=0o700, exist_ok=True)
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as log:
        log.write(f"$ {' '.join(argv)}  (in {cwd})\n")
        log.flush()
        try:
            return subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                  stdout=log, stderr=log, timeout=timeout).returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.write(f"canary: {type(exc).__name__}\n")
            return None


def _landed(stage_root):
    """(skill folders, links) the installer left under `stage_root`. A skill
    folder is a real folder holding a SKILL.md; a link counts when it sits in
    a folder named `skills`."""
    folders, links = [], []
    for dirpath, dirnames, filenames in os.walk(stage_root, followlinks=False):
        if "SKILL.md" in filenames:
            # Even a SKILL.md that is a link: the snapshot then refuses it.
            folders.append(dirpath)
            dirnames[:] = []
            continue
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        if os.path.basename(dirpath) == "skills":
            for name in sorted(os.listdir(dirpath)):
                if os.path.islink(os.path.join(dirpath, name)):
                    links.append(os.path.join(dirpath, name))
    return folders, links


def _check_all(snapshots, backend, model, timeout_s, log_dir):
    """classify._check each snapshot, a few at a time (one model call each):
    a (result, confident) pair for each."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        futures = [pool.submit(classify._check, s, backend=backend, model=model,
                               timeout_s=timeout_s, log_dir=log_dir) for s in snapshots]
        return [f.result() for f in futures]


WORST = {"LIKELY_SAFE": 0, "NEEDS_REVIEW": 1, "UNSAFE": 2}


def dialog_text(command, items, verdict):
    """One dialog for everything the command installs. Names come from the
    packages; the command comes from the agent."""
    if not items:
        return ("Add this plugin marketplace? It is a catalogue of plugins. Nothing from "
                "it is installed until a plugin is, and SkillCanary checks each plugin "
                f"then.\n\nCommand: {' '.join(command)[:300]}\n\nThe command comes from "
                "the agent, not from SkillCanary.")
    word = {"LIKELY_SAFE": "no problems found",
            "NEEDS_REVIEW": "needs your judgment"}.get(verdict, verdict)
    lines = [f"SkillCanary checked what this install would add: {word}.", ""]
    for it in items:
        mark = "" if it["verdict"] == "LIKELY_SAFE" else "  (needs your judgment)"
        lines.append(f"- {it['name']}{mark}")
        can = sorted({add.PLAIN[k] for k in it["capabilities"] if k in add.PLAIN})
        lines += [f"    It {c}." for c in can]
        if it["verdict"] != "LIKELY_SAFE" and it.get("headline"):
            lines.append(f"    {it['headline']}")
    steps = list(dict.fromkeys(s for it in items for s in it.get("steps", [])))
    if steps:
        lines += ["", "What you can do:"] + [f"- {s}" for s in steps]
    places = sorted({_short(os.path.dirname(it["destination"]), os.path.expanduser("~"))
                     for it in items if it.get("destination")})
    if places:
        lines += ["", "Into: " + ", ".join(places)]
    lines += ["", f"Command: {' '.join(command)[:300]}", "",
              "Names come from the packages, and the command from the agent, "
              "not from SkillCanary."]
    return "\n".join(lines)


def _ask(approve, command, items, verdict):
    if approve is not None:
        return approve({"command": command, "items": items, "verdict": verdict})
    return add.ask(dialog_text(command, items, verdict), verdict)


def install(argv, *, home=None, cwd=None, support_dir=None, approve=None, backend="auto",
            model=None, timeout_s=classify.DEFAULT_TIMEOUT_S):
    """Run the whole install flow and return a canary.install/1 result.
    Raises InstallError (exit 2) or add.LockError (exit 3)."""
    parsed = installers.kind(list(argv))
    if parsed is None:
        raise InstallError("canary install runs skill and plugin installers only: "
                           "npx skills add …, or claude plugin install <name>@<marketplace>.")
    home = home or os.path.expanduser("~")
    cwd = os.path.realpath(cwd or os.getcwd())
    support_dir = support_dir or add.SUPPORT_DIR
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
    # In the quarantine, which the hook keeps agents from reading: installer
    # output can quote package text.
    log_path = os.path.join(support_dir, "quarantine", "logs", f"install-{run_id}.log")
    out = _result(parsed[0], argv)
    if parsed[0] == "marketplace":
        # Adds a catalogue of plugins; each plugin is checked when installed.
        # The person agrees to the catalogue first.
        answer = _ask(approve, list(argv), [], "LIKELY_SAFE")
        if answer is not True:
            out["outcome"] = "declined" if answer is False else "not_installed"
            out["reasons"].append("The person did not add the marketplace.")
            return out
        code = _run(list(argv), cwd, _real_env(home), log_path)
        out["outcome"] = "done" if code == 0 else "not_installed"
        out["reasons"].append("Added the marketplace; nothing from it is installed yet."
                              if code == 0 else f"The installer failed; its output is in {log_path}.")
        return out
    run_dir = os.path.join(support_dir, "quarantine", run_id)
    os.makedirs(run_dir, mode=0o700)
    try:
        if parsed[0] == "skills":
            return _skills(argv, home, cwd, support_dir, run_dir, run_id, log_path, out,
                           approve, backend, model, timeout_s)
        return _plugin(parsed, home, cwd, support_dir, run_dir, run_id, log_path, out,
                       approve, backend, model, timeout_s)
    finally:
        add._remove(run_dir)


def _stage(run_dir, home):
    stage_home = os.path.join(run_dir, "home")
    stage_project = os.path.join(run_dir, "project")
    os.makedirs(stage_home, mode=0o700)
    os.makedirs(stage_project, mode=0o700)
    _mirror_home(home, stage_home)
    return stage_home, stage_project


def _not(out, reason):
    out["outcome"] = "not_installed"
    out["reasons"].append(reason)
    return out


def _snapshot_and_check(folders, run_dir, out, backend, model, timeout_s, support_dir, name=None):
    """Snapshot each folder (refusing links and special files), check each,
    and return the items, or None after filling `out` when it cannot go on."""
    items = []
    for n, folder in enumerate(folders):
        snap = os.path.join(run_dir, "checked", str(n))
        try:
            add._copy_local(folder, snap)
            add._set_modes(snap, writable=False)
            label = name or add._name(snap, os.path.basename(folder).lower())
            items.append({"name": label, "snapshot": snap, "digest": add.tree_digest(snap)})
        except (add.SourceError, OSError) as exc:
            _not(out, "A skill could not be copied safely: "
                      f"{exc if isinstance(exc, add.SourceError) else 'it could not be read.'} "
                      "Nothing was installed.")
            return None
    results = _check_all([it["snapshot"] for it in items], backend, model, timeout_s,
                         os.path.join(support_dir, "logs"))
    for it, (result, confident) in zip(items, results):
        it["verdict"] = result["verdict"]
        it["headline"] = result["headline"]
        it["steps"] = explain.next_steps(result, confident, "install")
        it["reasons"] = result["reasons"]
        it["capabilities"] = sorted({c["kind"] for c in result["scan"]["capabilities"]})
        it["package_digest"] = result["package_digest"]
    out["verdict"] = max((it["verdict"] for it in items), key=WORST.get)
    out["skills"] = [{"name": it["name"], "verdict": it["verdict"], "headline": it["headline"]}
                     for it in items]
    out["next_steps"] = list(dict.fromkeys(s for it in items for s in it["steps"]))
    for it in items:
        out["reasons"] += [f"{it['name']}: {r}" for r in it["reasons"]]
    return items


def _skills(argv, home, cwd, support_dir, run_dir, run_id, log_path, out, approve, backend,
            model, timeout_s):
    stage_home, stage_project = _stage(run_dir, home)
    before = _real_listing(home, cwd)
    code = _run(list(argv), stage_project, _env(stage_home, home), log_path)
    appeared = _appeared(before, _real_listing(home, cwd))
    if appeared:
        return _not(out, f"While the installer ran, something new appeared in "
                         f"{_short(appeared[0], home)}, outside SkillCanary's staging folder. "
                         "SkillCanary installed nothing. Run canary list to see it.")
    if code != 0:
        return _not(out, f"The installer failed ({'exit ' + str(code) if code is not None else 'did not finish'}); "
                         f"nothing was installed. Its output is in {log_path}.")
    roots = ((stage_home, home), (stage_project, cwd))
    plan, links = [], []  # (staged folder, destination); (link destination, target destination)
    for stage_root, real_root in roots:
        folders, found_links = _landed(stage_root)
        plan += [(f, os.path.join(real_root, os.path.relpath(f, stage_root))) for f in folders]
        links += [(l, real_root, stage_root) for l in found_links]
    if any(not add.NAME.fullmatch(os.path.basename(f)) for f, _ in plan):
        return _not(out, "A skill folder's name is not one SkillCanary can use (lowercase "
                         "letters, digits and dashes); nothing was installed.")
    if not plan:
        return _not(out, "The installer added no skills to its staging home, so there was "
                         f"nothing to check or install. Its output is in {log_path}.")
    by_stage = {os.path.realpath(f): dest for f, dest in plan}
    link_plan = []
    for link, real_root, stage_root in links:
        target = by_stage.get(os.path.realpath(link))
        if target is None:
            continue  # a link to something outside what landed is not copied
        dest = os.path.join(real_root, os.path.relpath(link, stage_root))
        link_plan.append((dest, os.path.relpath(target, os.path.dirname(dest))))
    taken = [d for _, d in plan] + [d for d, _ in link_plan]
    places = add.places_of(taken)
    reason = add.conflict_reason(add._read_lock(home),
                                 list(dict.fromkeys(os.path.basename(f) for f, _ in plan)),
                                 places, taken, home)
    if reason:
        return _not(out, reason)
    items = _snapshot_and_check([f for f, _ in plan], run_dir, out, backend, model, timeout_s,
                                support_dir)
    if items is None:
        return out
    for it, (_, dest) in zip(items, plan):
        it["destination"] = dest
    names = {}
    for it in items:
        if names.setdefault(it["name"], it["digest"]) != it["digest"]:
            return _not(out, f"Two different skills are both named {it['name']}; nothing was installed.")
    if out["verdict"] == "UNSAFE":
        out["outcome"] = "refused"
        out["reasons"].append("Not installed: SkillCanary judged part of it unsafe.")
        _record_all(items, home, support_dir, "refused")
        return out
    reason = add.conflict_reason(add._read_lock(home), list(names), places, taken, home)
    if reason:
        return _not(out, reason)
    answer = _ask(approve, list(argv), items, out["verdict"])
    if answer is not True:
        out["outcome"] = "declined" if answer is False else "not_installed"
        out["reasons"].append("The person declined the install." if answer is False else
                              "Nobody approved it on the Mac's screen; ask the person to "
                              "run it again and answer the SkillCanary dialog.")
        _record_all(items, home, support_dir, out["outcome"])
        return out
    with add._Commit(home):
        lock = add._read_lock(home)
        reason = add.conflict_reason(lock, list(names), places, taken, home)
        if reason:
            return _not(out, reason)
        # Chosen now: once the files exist, a dead record of the same name
        # would look live.
        keys = {name: add.plan_key(lock, name, places)[0] for name in names}
        # Recorded before the files appear, so the watcher leaves them alone;
        # the links resolve to these folders.
        for name in names:
            mine = [it for it in items if it["name"] == name]
            add._record(guestlist.record_install, home, [it["destination"] for it in mine], name,
                        max((it["verdict"] for it in mine), key=WORST.get),
                        support=support_dir, source=mine[0]["snapshot"], how="canary install")
        done = []
        try:
            for it in items:
                got = add._install(it["snapshot"], [it["destination"]], it["digest"], run_id,
                                   it["name"], out)
                if got is None:
                    raise OSError("not installed")
                done += got
            for dest, target in link_plan:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                os.symlink(target, dest)
                done.append(dest)
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            for name in names:
                mine = [it for it in items if it["name"] == name]
                installed = ([it["destination"] for it in mine]
                             + [d for d, _ in link_plan if os.path.realpath(d) in
                                {os.path.realpath(it["destination"]) for it in mine}])
                lock["skills"][keys[name]] = {
                    "source": "installer", "command": list(argv), "name": name,
                    "places": add.places_of(installed),
                    "package_digest": mine[0]["package_digest"], "verdict": mine[0]["verdict"],
                    "installed": installed, "installed_at": stamp}
            add._write_lock(home, lock)
        except (OSError, add.SourceError):
            for path in reversed(done):
                if os.path.islink(path):
                    os.unlink(path)
                else:
                    add._remove(path)
            out["reasons"] = [r for r in out["reasons"] if not r.startswith("The package changed")]
            return _not(out, "SkillCanary could not put the checked files in place, so it "
                             "removed what it had copied.")
    out["outcome"] = "installed"
    out["installed"] = [_short(d, home) for d in done]
    return out


def _real_listing(home, cwd):
    """{skills folder: its entries} for the person's real skills folders and
    the current project's, so an installer that writes past staging shows."""
    from canary import gate
    folders = guestlist.user_roots(home) + [os.path.join(cwd, r) for r in gate.SKILL_ROOTS]
    listing = {}
    for folder in dict.fromkeys(folders):
        try:
            listing[folder] = set(os.listdir(folder))
        except OSError:
            listing[folder] = set()
    return listing


def _appeared(before, after):
    return sorted(f for f in after if after[f] - before.get(f, set()))


def _record_all(items, home, support_dir, outcome):
    for name in dict.fromkeys(it["name"] for it in items):
        verdict = max((it["verdict"] for it in items if it["name"] == name), key=WORST.get)
        add._record(guestlist.record_decision, home, name, verdict, outcome, support=support_dir)


def _short(path, home):
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


# ---- plugins (owner decision 7) ---------------------------------------------

def _config_dir(home):
    return os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")


def _marketplace_source(config_dir, marketplace):
    """What `claude plugin marketplace add` takes for a marketplace the person
    already has, read from Claude Code's record of them; None if unknown."""
    try:
        with open(os.path.join(config_dir, "plugins", "known_marketplaces.json"),
                  encoding="utf-8") as fh:
            entry = json.load(fh).get(marketplace)
        source = entry["source"]
        return {"github": source.get("repo"), "git": source.get("url"),
                "url": source.get("url"), "directory": source.get("path")}.get(source.get("source"))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def _install_path(config_dir, plugin_id, scope):
    """Where Claude Code says it installed `plugin_id` at `scope`; None if it
    does not say."""
    try:
        with open(os.path.join(config_dir, "plugins", "installed_plugins.json"),
                  encoding="utf-8") as fh:
            entries = json.load(fh)["plugins"][plugin_id]
        paths = [e["installPath"] for e in entries
                 if isinstance(e.get("installPath"), str) and e.get("scope", "user") == scope]
        return paths[-1] if paths else None
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return None


def _digest_of(folder, scratch):
    """The checked-bytes digest of a folder, read through a link-refusing copy."""
    try:
        add._copy_local(folder, scratch)
        return add.tree_digest(scratch)
    except (add.SourceError, OSError):
        return None
    finally:
        add._remove(scratch)


def _plugin(parsed, home, cwd, support_dir, run_dir, run_id, log_path, out, approve, backend,
            model, timeout_s):
    _, argv, plugin_id, scope = parsed
    marketplace = plugin_id.split("@", 1)[1]
    real_config = _config_dir(home)
    stage_home, stage_project = _stage(run_dir, home)
    stage_config = os.path.join(stage_home, ".claude")
    env = _env(stage_home, home, {"CLAUDE_CONFIG_DIR": stage_config})
    if argv[2] in ("install", "i") and _install_path(real_config, plugin_id, scope):
        return _not(out, f"{plugin_id} is already installed. To update it: canary install "
                         f"-- claude plugin update {plugin_id}")
    source = _marketplace_source(real_config, marketplace)
    if source is None:
        return _not(out, f"SkillCanary could not find the marketplace {marketplace}. Add it "
                         "first: claude plugin marketplace add <source>.")
    if _run([argv[0], "plugin", "marketplace", "add", source], stage_project, env, log_path) != 0:
        return _not(out, f"SkillCanary could not stage the marketplace; see {log_path}.")
    if _run(list(argv), stage_project, env, log_path) != 0:
        return _not(out, f"The installer failed in staging; nothing was installed. See {log_path}.")
    staged = _install_path(stage_config, plugin_id, scope)
    if not staged or not os.path.isdir(staged):
        return _not(out, f"The installer did not report where it put {plugin_id}; nothing was installed.")
    items = _snapshot_and_check([staged], run_dir, out, backend, model, timeout_s, support_dir,
                                name=plugin_id)
    if items is None:
        return out
    out["skills"] = [{"name": plugin_id, "verdict": items[0]["verdict"],
                      "headline": items[0]["headline"]}]
    if out["verdict"] == "UNSAFE":
        out["outcome"] = "refused"
        out["reasons"].append("Not installed: SkillCanary judged it unsafe.")
        _record_all(items, home, support_dir, "refused")
        return out
    answer = _ask(approve, list(argv), items, out["verdict"])
    if answer is not True:
        out["outcome"] = "declined" if answer is False else "not_installed"
        out["reasons"].append("The person declined the install." if answer is False else
                              "Nobody approved it on the Mac's screen; ask the person to "
                              "run it again and answer the SkillCanary dialog.")
        _record_all(items, home, support_dir, out["outcome"])
        return out
    # The real install, then proof it is what was checked. A plugin loads when
    # a session starts, so nothing uses it before this comparison.
    with add._Commit(home):
        code = _run(list(argv), cwd, _real_env(home), log_path)
        real = _install_path(real_config, plugin_id, scope)
        got = _digest_of(real, os.path.join(run_dir, "installed")) if real else None
        if code != 0:
            # Nothing of ours to undo: a failed update keeps what was there.
            return _not(out, f"The installer failed; its output is in {log_path}.")
        if got != items[0]["digest"]:
            removed = _run([argv[0], "plugin", "uninstall", plugin_id, "--scope", scope], cwd,
                           _real_env(home), log_path)
            return _not(out, "The plugin changed between the check and the install, so "
                             + ("SkillCanary uninstalled it." if removed == 0 else
                                "SkillCanary tried to uninstall it and could not. Remove it "
                                f"yourself: claude plugin uninstall {plugin_id}"))
        lock = add._read_lock(home)
        lock.setdefault("plugins", {})[plugin_id] = {
            "command": list(argv), "scope": scope, "package_digest": items[0]["package_digest"],
            "verdict": items[0]["verdict"], "installed": [real],
            "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        add._write_lock(home, lock)
    add._record(guestlist.record_install, home, [real], plugin_id, items[0]["verdict"],
                support=support_dir)
    out["outcome"] = "installed"
    out["installed"] = [_short(real, home)]
    return out


def render_text(out):
    lines = [f"SkillCanary install: {out['outcome']}" + (f" ({out['verdict']})" if out["verdict"] else "")]
    lines += [f"  {s['name']}: {s['verdict']}" for s in out["skills"]]
    lines += [f"  - {r}" for r in out["reasons"]]
    lines += [f"  Installed: {p}" for p in out["installed"]]
    return "\n".join(lines)
