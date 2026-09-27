"""SkillCanary lifecycle test, run inside a disposable macOS VM as a normal
user who is an administrator (sudo password "admin", the image default).

Stand-ins, because nobody is at the VM's screen:
- the macOS administrator dialog -> `sudo sh -c <script>` (same script text);
- the SkillCanary approval dialog -> an approver that answers yes or no.
Everything else is the real product on a real Mac: root ownership, /Library
and /etc policy files, the real hook command, a real GitHub download.
"""
import json
import os
import shlex
import subprocess
import sys

KIT = os.path.expanduser("~/canary-kit")
sys.path.insert(0, KIT)
from canary import add, setup  # noqa: E402

HOME = os.path.expanduser("~")
results = []


def step(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def sudo(script):
    return subprocess.run(["sudo", "-S", "sh", "-c", script], input="admin\n",
                          capture_output=True, text=True).returncode == 0


def hook(host, tool, tool_input, cwd=HOME):
    cmd = shlex.split(setup.hook_command("/", host))
    payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                          "tool_input": tool_input, "cwd": cwd})
    p = subprocess.run(cmd, input=payload, capture_output=True, text=True)
    if host == "claude":
        return "deny" if p.returncode == 2 else ("allow" if p.returncode == 0 and not p.stdout else "odd")
    if p.returncode == 0 and p.stdout:
        return "deny" if json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny" else "odd"
    return "allow" if p.returncode == 0 else "odd"


def owner(path):
    try:
        return os.stat(path).st_uid
    except OSError:
        return None


def writable_by_me(path):
    probe = os.path.join(path, ".canary-write-probe")
    try:
        with open(probe, "w"):
            pass
        os.remove(probe)
        return True
    except OSError:
        return False


LINK = "https://github.com/anthropics/skills/tree/main/skills/brand-guidelines"
for d in (".claude", ".agents/skills", ".codex"):
    os.makedirs(os.path.join(HOME, d), exist_ok=True)

# 1. Scan level: nothing machine-wide, no password
out, code = setup.setup("scan", runner=lambda t: False)
step("scan: completes without a password", out["outcome"] == "done" and code == 0)
step("scan: nothing installed machine-wide", not os.path.exists("/Library/Application Support/SkillCanary"))

# 2. Guard
out, code = setup.setup("guard", runner=sudo)
step("guard: setup completes", out["outcome"] == "done", json.dumps(out)[:200])
step("guard: Canary installed root-owned", owner("/Library/Application Support/SkillCanary/bin/canary") == 0)
step("guard: Claude Code drop-in present",
     os.path.exists("/Library/Application Support/ClaudeCode/managed-settings.d/canary.json"))
step("guard: Codex requirements.toml present", os.path.exists("/etc/codex/requirements.toml"))
level, gaps, claim = setup.doctor()
step("guard: doctor finds no gaps", level == "guard" and not gaps, "; ".join(gaps))
skill = os.path.join(HOME, ".claude/skills/x/SKILL.md")
step("guard: hook denies a Write into ~/.claude/skills (Claude)",
     hook("claude", "Write", {"file_path": skill, "content": "x"}) == "deny")
step("guard: hook denies npx skills add (Codex)",
     hook("codex", "Bash", {"command": "npx skills add someone/repo"}) == "deny")
step("guard: hook allows ordinary work (Codex)",
     hook("codex", "Bash", {"command": "cd /tmp && ls"}) == "allow")
step("guard: an agent cannot edit the installed hook",
     not writable_by_me("/Library/Application Support/SkillCanary/canary"))

# 3. canary add from a real GitHub link
r = add.add(LINK, approve=lambda s: True, backend="none")
step("guard: add a real GitHub skill (approved)", r["outcome"] == "installed", json.dumps(r)[:300])
r2 = add.add(LINK, approve=lambda s: True, backend="none")
step("guard: a second add of the same skill does not overwrite", r2["outcome"] == "not_installed")

# 4. Lockdown
out, code = setup.setup("lockdown", runner=sudo)
step("lockdown: setup completes", out["outcome"] == "done", json.dumps(out)[:200])
for root in (".claude/skills", ".agents/skills"):
    p = os.path.join(HOME, root)
    step(f"lockdown: {root} is root-owned and not writable by the user",
         owner(p) == 0 and not writable_by_me(p))
step("lockdown: the user cannot delete an installed skill",
     subprocess.run(["rm", "-rf", os.path.join(HOME, ".claude/skills/brand-guidelines")],
                    capture_output=True).returncode != 0)
level, gaps, claim = setup.doctor()
step("lockdown: doctor finds no gaps", level == "lockdown" and not gaps, "; ".join(gaps))
local = os.path.join(HOME, "local-skill")
os.makedirs(local, exist_ok=True)
with open(os.path.join(local, "SKILL.md"), "w") as fh:
    fh.write("---\nname: local-notes\ndescription: Formats notes.\n---\n\nUse bullets.\n")
r = add.add(local, approve=lambda s: True, backend="none", admin=sudo)
step("lockdown: add installs through the administrator step", r["outcome"] == "installed",
     json.dumps(r)[:300])
step("lockdown: installed copy is root-owned",
     owner(os.path.join(HOME, ".claude/skills/local-notes/SKILL.md")) == 0)
r = add.add(local.replace("local-skill", "local-skill"), approve=lambda s: False, backend="none")
step("lockdown: a decline installs nothing", r["outcome"] in ("declined", "not_installed"))

# 5. Back to Scan
out, code = setup.setup("scan", runner=sudo)
step("scan again: setup completes", out["outcome"] == "done", json.dumps(out)[:200])
step("scan again: policy files removed",
     not os.path.exists("/Library/Application Support/ClaudeCode/managed-settings.d/canary.json")
     and not os.path.exists("/etc/codex/requirements.toml"))
step("scan again: skill folders returned to the user",
     writable_by_me(os.path.join(HOME, ".claude/skills")))
step("scan again: installed skills kept",
     os.path.exists(os.path.join(HOME, ".claude/skills/brand-guidelines/SKILL.md")))

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)
