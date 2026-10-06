"""The SkillCanary skill that `canary setup` installs for Claude Code and Codex.

It teaches agents to route every skill install through `canary add` and never
to read a skill themselves, so "use Canary to install <link>" works in any new
session. `skills/canary/SKILL.md` is the same text (a test checks it).
"""

import os
import secrets
import stat

MARKER = ("\n<!-- Installed by canary setup, which keeps it up to date. "
          "Delete this folder to remove it. -->\n")

SKILL_TEXT = """---
name: "canary"
description: "Install and change AI skills safely with SkillCanary. Use when the person asks to install, add, update, edit or vet a skill or plugin, shares a link to one, says 'use Canary', or when a write to a skills folder is blocked."
---

# SkillCanary

SkillCanary checks a skill before any agent reads it and installs it only
after the person approves in a Mac dialog. You pass it links; you never read
the skill yourself.

## When the person wants a skill installed

Run `canary add "<link>"` with the link exactly as they gave it. Then report
the outcome in one or two sentences:

- `installed` (exit 0): say where it was installed.
- `declined` or `not_installed` (exit 10): relay the headline first, then
  the reasons and the steps SkillCanary gave (`headline`, `reasons` and
  `next_steps` in the result). Do not install the skill another way; that
  decision belongs to the person.
- `refused` (exit 20): say SkillCanary judged it unsafe and it was not
  installed.
- Exit 2: the link or download did not work; repeat the message.

When they give an installer command instead of a link, such as
`npx skills add <owner/repo>` or `claude plugin install <name>@<marketplace>`,
run it as a command of its own through SkillCanary:
`canary install -- <the same command>`. It runs the same installer into a
private staging folder, checks what it adds, asks the person once, and puts
only the checked files in place. In Claude Code the hook does this for you;
Codex tells you the exact command. The outcomes and exit codes are the same
as `canary add`.

Do not open, read, summarize or paste the skill's files, before or after.
Do not use `git clone` or file writes to put a new skill in a skills folder,
and do not run an installer inside a longer command; at Guard those are
blocked and sent to `canary add` or `canary install`.

## When the person wants to change an installed skill

Edit its files directly with your normal tools. SkillCanary checks skills
when they arrive, not every change afterwards.

## When SkillCanary blocks something

The block message says what to do instead; follow it. SkillCanary has only
the commands `canary --help` lists: add, install, check, list, trust, setup,
doctor, and this one:

- explain (for the person only: never run canary explain or --excerpts yourself; give the person the command to run in their own terminal)

Never tell the person to "allow" a file in SkillCanary, or suggest a setting
or command it does not have. When there is no route, give the person the exact
command to paste into their own terminal, in its own code block, and say in
one sentence what it does. Do not retry the blocked action another way.

## When they want a skill checked, not installed

Run `canary check "<path>" --text` and relay the headline, then the reasons
and the steps. To see the flagged lines themselves, the person runs
`canary explain "<path or link>"` in their own terminal; you do not.

## When `canary` is not installed

Tell the person to set it up from https://skillcanary.com, where the page
gives a sentence to paste into this app. Do not fetch or read that page
yourself.

## When they ask what they are protected against

Run `canary doctor` and relay its output. To change the level, run
`canary setup`; it asks the person in a Mac dialog and, for Guard, asks
for their password in the standard macOS window. When `canary doctor` lists
old install records (skills or plugins whose folders are gone), they can
block a reinstall; `canary doctor --prune` removes them after the person
agrees in a Mac dialog.
"""


def installed_text():
    return SKILL_TEXT + MARKER


def _ours(folder_fd):
    """True when the open folder holds only SKILL.md ending in the marker.
    A marker can be copied, so this means "looks like SkillCanary's", not
    proof of who wrote it; it only stops setup replacing other skills."""
    if set(os.listdir(folder_fd)) != {"SKILL.md"}:
        return False
    fd = os.open("SKILL.md", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder_fd)
    with os.fdopen(fd, encoding="utf-8") as fh:
        return stat.S_ISREG(os.fstat(fh.fileno()).st_mode) and fh.read().endswith(MARKER)


def _open_root(home, root, create=False):
    """An fd for root, opened from home one folder at a time without
    following links (the home folder itself is taken as given)."""
    rel = [c for c in os.path.relpath(root, home).split(os.sep) if c]
    if not rel or rel[0] == "..":
        raise OSError("skill root is not under the home folder")
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in rel:
            try:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o755, dir_fd=fd)
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def targets(home, roots):
    """Skills roots where setup may write the skill: its canary folder is
    missing, or looks like SkillCanary's. Links are never followed."""
    out = []
    for root in roots:
        try:
            root_fd = _open_root(home, root)
        except FileNotFoundError:
            out.append(root)
            continue
        except OSError:
            continue
        try:
            try:
                folder_fd = os.open("canary", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=root_fd)
            except FileNotFoundError:
                out.append(root)
                continue
            try:
                if _ours(folder_fd):
                    out.append(root)
            finally:
                os.close(folder_fd)
        except (OSError, UnicodeDecodeError):
            pass
        finally:
            os.close(root_fd)
    return out


def write(home, root):
    """Write the skill into root/canary as the current user, through folder
    handles opened from home without following links, re-checking at write
    time. Returns False when the folder is no longer safe to write. A file
    dropped into the folder between that check and the final rename can
    still be replaced; only something already running as the person can do
    that, and it controls the folder anyway."""
    root_fd = _open_root(home, root, create=True)
    try:
        try:
            os.mkdir("canary", 0o755, dir_fd=root_fd)
        except FileExistsError:
            pass
        folder_fd = os.open("canary", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            if os.listdir(folder_fd) and not _ours(folder_fd):
                return False
            tmp = f".SKILL.md.{secrets.token_hex(8)}"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644,
                         dir_fd=folder_fd)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(installed_text())
            os.replace(tmp, "SKILL.md", src_dir_fd=folder_fd, dst_dir_fd=folder_fd)
            return True
        finally:
            os.close(folder_fd)
    finally:
        os.close(root_fd)
