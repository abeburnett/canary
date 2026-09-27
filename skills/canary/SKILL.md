---
name: "canary"
description: "Install AI skills safely with SkillCanary. Use when the person asks to install, add, update or vet a skill or plugin, shares a link to one, or says 'use Canary'."
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
to put a skill in a skills folder; at Guard and Lockdown those are blocked.

## When they want a skill checked, not installed

Run `canary check "<path>" --text` and relay the verdict and reasons.

## When `canary` is not installed

Tell the person to set it up from https://skillcanary.com, where the page
gives a sentence to paste into this app. Do not fetch or read that page
yourself.

## When they ask what they are protected against

Run `canary doctor` and relay its output. To change the level, run
`canary setup`; it asks the person in a Mac dialog and, for Guard or
Lockdown, asks for their password in the standard macOS window.
