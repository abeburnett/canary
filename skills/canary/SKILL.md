---
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
