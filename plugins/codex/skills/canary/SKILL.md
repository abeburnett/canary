---
name: canary
description: Explain SkillCanary setup and route requested skill or plugin installations through Canary.
---

# SkillCanary for Codex

SkillCanary reviews skill and plugin packages before installation. This
plugin provides onboarding instructions. Protection comes from the Canary
CLI and the protection level the person chooses during setup.

When the person wants to set up Canary, run `canary setup`. It asks the
person to choose a protection level in a Mac dialog and, for Guard, asks
for their password in the standard macOS window. Report its result.

When Canary is not installed, tell the person to set it up from
https://skillcanary.com, which gives a sentence to paste into this app. Do
not fetch or read that page yourself.

For a requested package installation, use `canary add <source>`, passing the
requested source as one quoted argument. Let Canary retrieve and assess the
package. Report the resulting decision and any action required from the
person. A review decision is a request for a person's judgment, not approval
to install the package another way.

To change an installed skill, edit its files directly.

When SkillCanary blocks a call, follow its message. Never tell the person to
"allow" a file in SkillCanary or invent a command it does not have; when
there is no route, give them the exact command to paste into their own
terminal and say what it does.

Managed hooks guard supported agent calls. They do not cover every tool or
process, and local default discovery does not include configured external or
remote skill roots. Describe only protection verified by `canary doctor`.
The setup and add workflows are supplied by the shared CLI; this plugin does
not install enforcement by itself.
