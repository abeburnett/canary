---
name: canary
description: Explain SkillCanary setup and route requested skill or plugin installations through Canary.
---

# SkillCanary for Codex

SkillCanary reviews skill and plugin packages before installation. This
plugin provides onboarding instructions. Protection comes from the Canary
CLI and the protection level the person chooses during setup.

When the person wants to set up Canary, ask them to run
`canary setup --host codex` in their own terminal. Setup explains the
available protection levels and any password requirement. Let the person
complete that step and report its result.

When Canary is not installed, direct the person to its official signed
release instructions. The planned Homebrew command is
`brew install skillcanary/tap/canary`; availability must be confirmed before
presenting it as a working installation channel.

For a requested package installation, use `canary add <source>`, passing the
requested source as one quoted argument. Let Canary retrieve and assess the
package. Report the resulting decision and any action required from the
person. A review decision is a request for a person's judgment, not approval
to install the package another way.

Managed hooks guard supported agent calls. They do not cover every tool or
process, and local default discovery does not include configured external or
remote skill roots. Describe only protection verified by `canary doctor`.
The setup and add workflows are supplied by the shared CLI; this plugin does
not install enforcement by itself.
