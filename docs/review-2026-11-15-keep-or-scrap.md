# Keep, redesign or uninstall SkillCanary

Review date: 2026-11-15. Installed version: 0.1.5, protection level guard. Reviewer: Claude Fable 5.2, read-only. I approved, restored, held, trusted and deleted nothing, and I changed no settings or hooks.

## Key points

**Verdict: redesign.** Keep the check on the install path and the hook. Change how the watcher treats a held skill. If you will not make changes 1 and 2 below this month, set the protection level to scan instead of living with the current behavior.

- **Protection is narrow.** SkillCanary stops two things before an agent reads them: an installer command that an agent runs in its shell, and a new skill that an agent creates with a file tool. It does not stop plugins, plugin updates, MCP servers, skills created with ordinary shell commands, or changes to skills you already approved.
- **Most of what reaches your agents arrives by a path SkillCanary does not check.** You have 30 Claude Code plugins holding 154 skills, 10 hook files and 11 MCP configuration files. SkillCanary has checked one of those plugins, once, on 2026-10-02.
- **All three interruptions you describe have one cause.** The watcher holds eight old copies of skills that you have since installed. Every time the watcher starts, it asks about all eight again. Seven of the eight need the typed name. Each approval then fails because the installed copy is in the way, and nothing is recorded. No command removes a hold, so this repeats at every restart.
- **I found no evidence that SkillCanary has kept a harmful skill off this Mac.** Every skill it refused, declined or judged UNSAFE in six weeks is installed today. The four skills it judged UNSAFE are installed because you chose "install anyway". I did not judge whether those four are safe.

Each claim below is marked *shown* (I ran a command and saw the result) or *read* (I read it in the code or the docs and did not run it).

## How SkillCanary works, in its own terms

SkillCanary has three parts. The *check* runs when you or an agent use `canary add` or `canary install`: it copies the package into the quarantine, runs a pattern scan and an AI review, shows a dialog, and installs the copy it checked. The *hook* runs before every tool call in Claude Code and Codex: it sends installer commands to the check and refuses file-tool writes that create a new skill folder. The *watcher* is a background program that moves any new entry in `~/.claude/skills`, `~/.agents/skills` or `~/.codex/skills` into the quarantine (a *hold*) and asks you about it. The *guest list* is the record behind `canary list` and the notice an agent sees when a session starts.

`canary list` on 2026-11-15 shows 263 skills (shown): 148 *yours* (present when setup first looked on 2026-10-02, or trusted later), 104 *checked* (eight of them "installed anyway"), 11 *unchecked*, and eight *held*. Seven checked skills are "changed since approval".

## 1. Protection

The table answers, for each arrival path, whether SkillCanary stops a malicious skill before an agent reads it.

| Path | Stopped before an agent reads it? | Evidence |
|---|---|---|
| Skills folders: an agent runs a known installer, or creates a skill with a file tool | Yes. The hook sends the installer to the check, or refuses the write. | Shown |
| Skills folders: anything else creates the skill (shell commands, a script, you in Finder) | Partly. The hook allows it. The watcher holds it about two seconds after it stops changing. An agent can read it in that window. | Hook: shown. Hold and window: read, plus 41 hold records in the ledger |
| Plugins | Only when an agent types the plugin install command in its shell. Not from the plugin menu, not for updates. | Shown |
| MCP servers | No. | Shown |
| Installers | Yes for the command forms it recognises. No for a command built from a variable or placed in a script file. | Shown |
| Sync tools | Held if the tool writes into one of the three user skills folders. Not seen if it writes anywhere else. | Read, plus ledger and folder counts shown |
| Updates to approved skills | No. A change is reported at the next session start, and only for checked skills. | Shown |

### Skills folders

I fed 27 made-up tool calls to the installed hook and recorded its decision. Nothing ran; the hook only answers allow, refuse or rewrite.

The hook rewrote these to `canary install -- …` (shown): the skills installer, the plugin installer, and the plugin marketplace command. It refused these (shown): a `git clone` into a user skills folder, and a file-tool write of a new skill in a user folder or a repository folder. For Codex it refused the skills installer and an `apply_patch` that adds a new skill, and told the agent to use `canary install` (shown).

The hook allowed all of these (shown):

- `mkdir` and `cp` of a new skill into a skills folder, in Claude Code and in Codex.
- `curl … | tar` extracting into a skills folder.
- `mv` of a folder into a skills folder.
- A Python script that copies a skill in.
- An installer command with one word supplied by a variable.
- An installer command inside a script file.

The code says the same: "A command assembled from pieces … is out of reach, as is any program that starts an installer itself; the watcher reports what lands" (`canary/installers.py:20`, read).

For those cases the watcher is the only protection. It waits until the new entry has been still for two seconds (`SETTLE_SECONDS = 2.0`, `canary/watcher.py:36`, read), then holds it. SECURITY.md states that an agent can read the skill during that window, and that an agent can stop the watcher (read). The hook allowed `kill` of the watcher's process id (shown).

The watcher does hold arrivals in practice. The ledger has 41 hold records, the latest on 2026-11-05, when it held `rocketsim`, judged it LIKELY_SAFE and put it back 12 seconds later (shown from the ledger). I did not create a test skill to watch a hold happen.

Three gaps in this path:

- **Eleven skills in `~/.codex/skills` are unchecked and were never held** (shown). They arrived on 2026-10-02 and Codex has been able to load them for six weeks: accelerate-mobile-delivery, app-store-readiness, goldie, ios-preview-director, luna-review, playwright, release-judgment, swiftui-specialist, swiftui-whats-new-27, terra-review and xcodebuildmcp-cli. I did not establish why the watcher did not hold them.
- **Skills inside a repository are never held** (read, SECURITY.md). The hook refuses a file-tool write that creates one (shown) and allows a shell command that creates one.
- **Other agents' skills folders are not watched** (shown). `~/.cursor/skills` has 49 entries, `~/.gemini/skills` 44 and `~/.config/opencode/skills` 43. Most are links into `~/.agents/skills`; 15 are real folders that SkillCanary never sees.

### Plugins

SkillCanary checks a plugin only when an agent types the install command in its shell (shown: the hook rewrote it). SECURITY.md says plugins installed any other way are not checked (read).

Your Mac shows the result (shown). Claude Code has 30 plugins installed. Together they hold 154 skills, 10 `hooks.json` files, 11 MCP configuration files and six `bin` folders. SkillCanary's records name one plugin, `code-review@claude-plugins-official`, checked on 2026-10-02. That plugin updated on 2026-10-27, and `canary doctor` now reports the record as old. The other 29 plugins were never checked.

Plugins also update without an agent's shell. Eight plugins updated between 2026-11-05 and 2026-11-14, including context7, playwright, skill-creator and superpowers. The ledger has no event for any of them. A file-tool write of a new skill inside a plugin's folder also passed the hook (shown).

The desktop app's synced plugins add 286 more skill files under `~/.claude/plugins/synced`, also unchecked (shown, count only).

### MCP servers

SkillCanary does not check MCP servers (shown). The hook allowed `claude mcp add`, `codex mcp add`, a file-tool write of a project `.mcp.json`, and an MCP tool call. You have eight user-level MCP servers in Claude Code, two project-scoped ones and about 17 in Codex. None appears in `canary list`.

The pattern scan does flag an MCP configuration file as a capability when it finds one inside a package it is checking (read, `scanner/references/checks.md`). It also states its own limit: for "an MCP server run from `@latest`", the scanner "cannot see the future bytes".

### Installers

Covered above. The recognised command forms go to the check (shown). A command built from a variable, a command in a script file, and a program that starts an installer itself all pass the hook (first two shown, third read). The watcher then holds what lands in the three user folders, after the two-second window.

### Sync tools

A sync tool that writes into the three user skills folders gets the watcher's treatment: each new entry is held, in each folder (read). The ledger shows the effect: 22 holds in one second on 2026-10-07, when one set of skills landed in more than one folder (shown).

A sync tool that writes anywhere else is not seen. The session-start sync hook on this Mac writes under `~/.claude/plugins`, outside the three folders (shown).

### Updates to approved skills

SkillCanary does not stop a change to an installed skill. The hook allowed a file-tool edit of an approved skill's `SKILL.md`, a file-tool write of a new script inside an approved skill, a shell append to an approved skill, and `git pull` inside an approved skill (shown). The hook's own header says: "Everything else passes, including edits to installed skills" (`canary/gate.py:7`, read).

The guest list reports the change later, and only for checked skills. Seven checked skills are listed as changed since approval today (shown). For the 148 skills marked yours, the ledger records the change and nothing shows it to you (`canary/guestlist.py:309`, read). Example: `impeccable`, a third-party skill whose script runs as a hook at session start, after edits and at stop, changed on 2026-11-01 with no notice (shown).

### What the check itself is worth

The README reports that the pattern scan plus the AI review declined 60 of 60 attack samples, and the pattern scan alone declined 20 of 60. The README says the project wrote those samples itself. The claim that guard "stops agents installing skills other ways" is marked "Documented, not rerun here" in `docs/proof/2026-10-12-plain-verdicts/README.md`. All of this is read; I did not rerun the benchmark.

## 2. Friction

I reproduced complaints 1 to 3 from records on this Mac, not from a live restart. Restarting the watcher would have raised the dialogs again and changed state. Complaint 4 I answered from the ledger.

### The state behind complaints 1 to 3

The watcher holds eight entries (shown, `canary list`):

| Held skill | Held on | Its place in |
|---|---|---|
| hyperframes-cli | 2026-10-07 | `~/.agents/skills` |
| hyperframes-cli | 2026-10-10 | `~/.claude/skills` |
| media-use | 2026-10-10 | `~/.claude/skills` |
| media-use | 2026-10-10 | `~/.agents/skills` |
| make-ugc | 2026-10-13 | `~/.claude/skills` |
| treg | 2026-10-13 | `~/.agents/skills` |
| treg | 2026-10-13 | `~/.claude/skills` |
| treg | 2026-10-13 | `~/.codex/skills` |

Every one of those places is now occupied by a copy that `canary list` shows as checked. You approved make-ugc on 2026-10-13, and hyperframes-cli, media-use and treg on 2026-10-15 with "install anyway" (shown).

I could not compare the held copies with the installed copies. The hook refuses any agent that reads the quarantine, and I did not work around it.

### Complaint 1: pop-ups after a restart for skills you believe are installed

**Reproduced from records.** Your belief is correct: the skills are installed. The pop-ups are about the eight older copies.

*Cause in code.* When the watcher starts, it queues every held entry for review again (`canary/watcher.py:357`, read). The comment in the code says so: "a held skill stays held; the next restart asks again". Holds have no expiry and no cleanup. `canary --help` lists no command that removes a hold; `canary restore` runs the same review (shown for the help text, read for the code).

*Evidence on disk.* The Mac booted on 2026-11-13 at 16:07 local time. The watcher started at 16:29:46. The macOS log shows eight dialog-sized `osascript` runs between 16:29:51 and 16:30:44, each followed by a short one (shown). That matches eight dialogs, each followed by one notification. This reading is an inference: the log does not record the dialog text, and other programs can run `osascript`.

### Complaint 2: retyping skill names

**Reproduced from records.**

*Cause in code.* When a skill's verdict is UNSAFE, the dialog requires you to type the skill's name (`canary/watcher.py:308`, `canary/add.py:578`, read). The watcher asks once per held entry, so one skill in three folders is three dialogs and three typed names.

*Evidence on disk.* Seven of the eight held entries are skills that SkillCanary judged UNSAFE before: hyperframes-cli twice, media-use twice, treg three times. Each restart therefore asks for seven typed names. The ledger shows the wider pattern: 32 UNSAFE verdicts in six weeks, all on four skills (treg 15, hyperframes-cli 8, media-use 6, hallmark 3), and 24 refusals on the same four (shown).

The code reviews each held entry again before it asks, which means one AI review per held entry per restart (read; the review logs are in the quarantine, so I could not confirm it).

### Complaint 3: "it can't move the skill"

**Reproduced from records.**

*Cause in code.* After you approve, the watcher tries to put the held copy back. If something is already at that place, it stops and sends this notification: "SkillCanary could not put NAME back: something else is there now. It stays held; canary list shows where." (`canary/watcher.py:331`, read). It writes nothing to the ledger, and the hold stays.

*Evidence on disk.* All eight places are occupied (shown). After the 2026-11-13 restart the ledger has no event at all for those two minutes (shown). A refusal would have written two records per skill, so the fit is: you approved, the move failed, nothing was recorded. The same thing will happen at the next restart.

### Complaint 4: has it ever stopped anything real?

**The records show no case.** I checked every outcome in the ledger against what is installed today (shown):

- UNSAFE verdicts: 32, on four skills. All four are installed, "anyway".
- Refused: 24, on the same four skills. All installed.
- Declined: three (a test skill, make-ugc, design-taste-frontend). All installed.
- Not installed: one (handoff). Installed now.

*Cause in code and state.* Two things keep you from seeing this yourself. The hook writes no record when it refuses or redirects a command, so its work leaves no trace. And 93% of the ledger's 9,381 events are "arrived" and "removed" records for skills inside repositories, written each time a session starts in a different folder (shown). The few events that matter are hard to find.

What I cannot tell you: whether the four UNSAFE verdicts were right. If they were right, SkillCanary warned you and you overrode it. If they were wrong, they were false alarms, and the typed names were their price. In both cases nothing was kept out.

### Cost

The hook adds about 0.26 seconds to each tool call in Claude Code and Codex, and the session-start notice takes 0.35 seconds (shown, measured on this Mac).

## 3. Verdict: redesign

**Do not keep it as it is.** The eight holds will raise eight dialogs, seven typed names and eight failure notices at every restart, and no command ends that.

**Do not uninstall yet.** The check on the install path is the one part I saw work, and none of your complaints comes from it. It is the only thing on this Mac that puts your decision between an agent-run installer and your skills folders.

**Redesign, in this order.** I read "protection gained per interruption removed" as: first the changes that remove the most interruptions and lose no protection, then the changes that add protection without adding interruptions.

1. **Stop asking again at restart, and add a way to end a hold.** Ask once, when the watcher holds a skill. After that, a hold appears in `canary list` and the session-start notice only. Add a command that drops a hold. When the place is taken by a copy you approved and the held copy has the same content, drop the hold without asking. *Removes:* every restart dialog, typed name and failure notice. *Protection lost:* none; the held copy stays out of reach until you decide.
2. **One decision per skill content.** When the same content arrives in two or three folders, ask once and apply the answer to each copy. Remember the answer by content: content you approved, including "install anyway", goes back without a dialog, and content you refused stays held without a dialog. *Removes:* the repeated dialogs behind 22 holds in one second. *Protection lost:* none for identical content.
3. **Record what the hook stops, and show a total.** Write a ledger record for each refusal and redirect. Add one line to `canary list`: how many installs went through the check, how many you declined, how many you installed anyway. Stop recording arrivals and removals of repository skills. *Interruptions:* none. *Gain:* you can answer complaint 4 yourself.
4. **Check changed skills without asking.** When a checked or yours skill changes, run the check in the background. Interrupt only for an UNSAFE verdict. List every other change in the notice, including changes to yours skills, which the notice hides today. *Protection gained:* updates stop being invisible. *Interruptions added:* one dialog per UNSAFE change.
5. **Put plugins and MCP servers on the guest list.** Record each installed plugin version and each configured MCP server. When one appears or changes, check it in the background and report it in the notice. *Protection gained:* the largest path onto this Mac becomes visible. *Limit:* this reports; it does not hold. I did not check whether Claude Code or Codex offer a setting that blocks plugin updates.

Changes 1 and 2 are the smallest set that makes SkillCanary quiet. Changes 4 and 5 are what would make it protective beyond the install path.

### What a quiet version gives up

- **The reminder.** A hold you ignore no longer comes back as a dialog. You see it only in the notice and in `canary list`.
- **Repeated friction on a risky skill.** You type the name once per content, not once per copy per restart. If you approve by mistake, the approval covers every copy.
- **Blocking, for everything except new skills.** Changes, plugins and MCP servers are reported after they arrive. An agent can read them before you see the notice. That is already true today; the quiet version makes it visible and does not close it.

### If you will not make the changes

Set the protection level to scan with `canary setup --level scan`. The code describes scan as "Scans skills when asked. Nothing is enforced" (`canary/setup.py:39`). At scan, setup removes the hook's settings files and installs the watcher only at guard (`canary/setup.py:167` and `:368`). All of this is read; I did not run it. You keep `canary scan` and `canary check` for vetting a skill on demand. The restart dialogs stop, and you get back 0.26 seconds per tool call. You lose the redirect of agent-run installers, which is the protection shown above, and the watcher's holds. The eight held copies stay in the quarantine until you delete them.

## Decisions that are yours

I did none of these. Each one approves, deletes or changes something.

- **Clear the eight holds.** No command does it. The route is to delete the eight folders under `~/Library/Application Support/Canary/quarantine/held/` in your own terminal. Before you do, compare each held copy with the installed copy using `canary digest <folder>`; if they differ, the held copy is a version you have not approved.
- **Decide on the 11 unchecked Codex skills.** `canary check <folder>` gives a verdict for one. `canary trust <folder>` marks one as yours. Or remove them.
- **Refresh or drop the old plugin record** that `canary doctor` reports.

## What I checked and what I did not

Checked by running commands: `canary list`, `canary doctor`, `canary --help`, the session-start notice, the ledger, the installed managed settings for both hosts, the hook's decision on 33 made-up tool calls (27 for Claude Code, six for Codex), counts of plugins, MCP servers and other agents' skills folders, the process list and the macOS log for 2026-11-13.

Not checked:

- I did not restart the watcher or create a test skill, so I did not watch a hold or a dialog happen.
- I did not read the held copies, their records or the AI review logs. The hook refuses agents, and I did not work around it.
- I did not rerun the benchmark or the end-to-end suite. The README numbers are read.
- I did not judge whether treg, hyperframes-cli, media-use or hallmark are safe.
- The hook results show the hook's decision on a made-up event. They do not show a real agent run.
- I did not establish what re-created treg, media-use and hyperframes-cli after their first holds, or why the 11 Codex skills were never held.

One side effect: `canary list` and the session-start notice write to the ledger. This review added three "changed" records (clear-writing, done-when-audit, orchestrate) and some repository arrival and removal records on 2026-11-15.
