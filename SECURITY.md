# Security policy

SkillCanary is a security tool, so we treat reports about it as a priority.

## Report a vulnerability

Email **abe@abeburnett.com** with "SkillCanary security" in the subject. Please
include the version (`canary --version`), your macOS version, the protection
level (`canary doctor`), and steps to reproduce. Don't open a public issue for
anything that could help someone get around SkillCanary.

We aim to reply within three working days, and to tell you what we'll fix and
when. We credit reporters in the release notes unless you'd rather we didn't.

## What SkillCanary claims

SkillCanary makes only the claims `canary doctor` prints for your Mac:

| Level | Claim |
|---|---|
| Scan | Scans skills when asked. Nothing is enforced. |
| Guard | Guards installs by agents in Claude Code and Codex. |
| Lockdown | Enforces vetting for user-level skill folders on this Mac, and guards repository skills. |

A report that SkillCanary fails to meet its claim at a level is in scope. So is
anything that makes a skill look safer than it is, lets package text reach an
agent, runs code as root that a normal user could have changed, or makes
`canary doctor` report a protection that isn't in force.

## Known limits

These are documented, not bugs; the site and `docs/architecture.md` state them.

- **Guard is a guard, not a wall.** Hooks see each tool call, and a command
  written to hide its target can get past them. Lockdown closes this for
  user-level skill folders; skills inside a repository are guarded only.
- **The approval dialog can be clicked by an agent that controls the screen**
  at Scan and Guard. Lockdown also asks for your password at each install.
- **A missing Python fails open.** Claude Code and Codex let a call through
  when a hook cannot run. The hook runs on macOS's `/usr/bin/python3`, which
  needs Apple's command-line tools; `canary doctor` reports when it can't run.
- **For Lockdown, install with the Mac installer.** Homebrew keeps programs in
  a folder your account can write to, so software already running as you
  could change SkillCanary before you run `canary setup`. The Mac installer
  puts it in `/Library/Application Support/SkillCanary`, which macOS keeps
  root-owned.
- **The `canary` command link can be replaced on some Macs.** It lives in
  `/usr/local/bin`, which an older Homebrew may have given to your account.
  Something running as you could then point `canary` at another program. The
  hooks are unaffected: they run SkillCanary by its full, root-owned path,
  `/Library/Application Support/SkillCanary/bin/canary`, which you can also
  use yourself for setup.
- **Skill roots reached through a link are not locked.** If `~/.claude`,
  `~/.agents` or a `skills` folder in them is a symbolic link, Lockdown skips
  it rather than follow the link, and `canary doctor` reports it.
- **A recently used `sudo` can be reused** from the same terminal window, for
  a few minutes, by anything running there, including an agent. Close the
  window after using `sudo`.
- **The classifier is a model.** It can only make a verdict stricter, and it
  runs isolated with no tools, but it can miss things. The pattern scan and
  your approval remain the backstop.
- **No human security audit yet.** SkillCanary has been reviewed by
  independent AI models (the fixes and their tests are in the commit history),
  not by a human auditor.
