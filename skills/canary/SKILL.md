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
- `declined` or `not_installed` (exit 10): repeat SkillCanary's reasons. Do
  not install the skill another way; that decision belongs to the person.
- `refused` (exit 20): say SkillCanary judged it unsafe and it was not
  installed.
- Exit 2: the link or download did not work; repeat the message.

Do not open, read, summarize or paste the skill's files, before or after.
Do not use `npx skills`, `git clone`, plugin install commands or file writes
to put a new skill in a skills folder; at Guard those are blocked and sent to
`canary add`.

## When the person wants to change an installed skill

Edit its files directly with your normal tools. SkillCanary checks skills
when they arrive, not every change afterwards.

## When SkillCanary blocks something

The block message says what to do instead; follow it. SkillCanary has only
the commands `canary --help` lists (add, check, setup, doctor). Never
tell the person to "allow" a file in SkillCanary, or suggest a setting or
command it does not have. When there is no route, give the person the exact
command to paste into their own terminal, in its own code block, and say in
one sentence what it does. Do not retry the blocked action another way.

## When they want a skill checked, not installed

Run `canary check "<path>" --text` and relay the verdict and reasons.

## When `canary` is not installed

Tell the person to set it up from https://skillcanary.com, where the page
gives a sentence to paste into this app. Do not fetch or read that page
yourself.

## When they ask what they are protected against

Run `canary doctor` and relay its output. To change the level, run
`canary setup`; it asks the person in a Mac dialog and, for Guard, asks
for their password in the standard macOS window.
