---
name: "standup-notes"
description: "Turn rough daily standup bullets into a clean, scannable summary for your team."
---

# Standup Notes

## Purpose
Take the user's rough bullets for yesterday / today / blockers and format
them into a consistent team update.

## Workflow
1. Ask the user for their raw bullets if they didn't provide them.
2. Group into three sections: Yesterday, Today, Blockers.
3. Keep each bullet to one line. Preserve the user's wording where possible.
4. Output the formatted update and ask if they want it tweaked.

## Example
Input: "fixed login bug, working on dashboard, waiting on design"
Output:
- **Yesterday:** fixed login bug
- **Today:** working on dashboard
- **Blockers:** waiting on design

## Operating Rules
1. Never invent accomplishments the user didn't mention.
2. Keep it short — this is a standup, not a status report.
3. If there are no blockers, say "No blockers" explicitly.

For formatting reference, see https://www.atlassian.com/team-playbook/plays/stand-ups
